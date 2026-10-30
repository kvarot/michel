// Server-sent events read with fetch: EventSource cannot send the
// "Authorization: Bearer" header the API requires, so the page reads the
// text/event-stream body itself (fetch + ReadableStream). Pure parsing and
// an injectable fetch keep it testable without a browser (stream.test.js).

/**
 * @typedef {{event: string, id: string, data: string}} SSEvent
 * @typedef {{buffer: string, retry: number}} SSEState
 */

/**
 * parseSSE reads one chunk of a text/event-stream. state carries what an
 * earlier chunk left unfinished (pass undefined for the first one): an event
 * cut between two chunks comes out whole once its blank line arrives.
 * Comment lines (": ping") are ignored; "retry:" is kept in state.retry.
 * An event without a name is a "message"; several data lines are joined
 * with "\n"; an event without data is dropped.
 * @param {string} chunk
 * @param {SSEState|undefined} state
 * @returns {{events: SSEvent[], state: SSEState}}
 */
export function parseSSE(chunk, state) {
  let retry = state?.retry || 0
  let buf = (state?.buffer || '') + String(chunk ?? '')
  // A CR at the very end may be the first half of a CRLF: keep it for later,
  // so it does not count as a line end of its own.
  let hold = ''
  if (buf.endsWith('\r')) {
    hold = '\r'
    buf = buf.slice(0, -1)
  }
  buf = buf.replace(/\r\n?/g, '\n')
  const events = []
  let end
  while ((end = buf.indexOf('\n\n')) >= 0) {
    const block = buf.slice(0, end)
    buf = buf.slice(end + 2)
    let event = ''
    let id = ''
    const data = []
    for (const line of block.split('\n')) {
      if (line === '' || line.startsWith(':')) continue
      const colon = line.indexOf(':')
      const field = colon < 0 ? line : line.slice(0, colon)
      let value = colon < 0 ? '' : line.slice(colon + 1)
      if (value.startsWith(' ')) value = value.slice(1)
      if (field === 'event') event = value
      else if (field === 'data') data.push(value)
      else if (field === 'id') id = value
      else if (field === 'retry' && /^\d+$/.test(value)) retry = Number(value)
    }
    if (data.length) events.push({ event: event || 'message', id, data: data.join('\n') })
  }
  return { events, state: { buffer: buf + hold, retry } }
}

/** sleep waits ms milliseconds. */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * connect reads the event stream at url and calls onEvent for each event,
 * until close() is called. When the stream ends or the connection fails,
 * it connects again: after the server's "retry" (else minDelay) when the
 * stream had sent something, else after a delay that doubles at each
 * failure up to maxDelay. A reconnect replays what the server sends first,
 * so the caller de-duplicates. A 401 or another 4xx (but 408 and 429) stops
 * for good and calls onStop({status}).
 * @param {{
 *   url: string,
 *   headers: Record<string, string>,
 *   onEvent: (ev: SSEvent) => void,
 *   onStop?: (why: {status: number}) => void,
 *   onOpen?: () => void,
 *   onDrop?: () => void,
 *   fetchImpl?: typeof fetch,
 *   wait?: (ms: number) => Promise<void>,
 *   minDelay?: number,
 *   maxDelay?: number,
 * }} options
 * @returns {{close: () => void}}
 */
export function connect(options) {
  const {
    url, headers, onEvent, onStop = () => {}, onOpen = () => {}, onDrop = () => {},
    fetchImpl = (...args) => fetch(...args), wait = sleep, minDelay = 1000, maxDelay = 30000,
  } = options
  let closed = false
  let controller = null
  let failures = 0
  let retry = 0

  async function once() {
    controller = new AbortController()
    const resp = await fetchImpl(url, {
      method: 'GET',
      headers: { ...headers, Accept: 'text/event-stream' },
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal,
    })
    if (!resp.ok) {
      const s = resp.status
      if (s >= 400 && s < 500 && s !== 408 && s !== 429) return { stop: s }
      return { got: false }
    }
    onOpen()
    let got = false
    let state
    const reader = resp.body.getReader()
    const decoder = new TextDecoder()
    for (;;) {
      const { value, done } = await reader.read()
      if (done || closed) break
      const r = parseSSE(decoder.decode(value, { stream: true }), state)
      state = r.state
      retry = state.retry || retry
      for (const ev of r.events) {
        if (closed) break
        got = true
        onEvent(ev)
      }
    }
    return { got }
  }

  async function loop() {
    while (!closed) {
      let delay
      try {
        const r = await once()
        if (r.stop) {
          closed = true
          onStop({ status: r.stop })
          return
        }
        if (r.got) failures = 0
        delay = r.got ? retry || minDelay : Math.min(minDelay * 2 ** failures++, maxDelay)
      } catch {
        delay = Math.min(minDelay * 2 ** failures++, maxDelay)
      }
      if (closed) return
      onDrop()
      await wait(delay)
    }
  }

  loop()
  return {
    close() {
      closed = true
      if (controller) controller.abort()
    },
  }
}
