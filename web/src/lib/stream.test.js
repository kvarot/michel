import { describe, expect, test } from 'vitest'
import { connect, parseSSE } from './stream.js'

describe('parseSSE', () => {
  test('reads named events with their id and JSON data', () => {
    const { events, state } = parseSSE('retry: 3000\n\nid: m1\nevent: message\ndata: {"id":"m1"}\n\nevent: state\ndata: {"state":"preparing"}\n\n', undefined)
    expect(events).toEqual([
      { event: 'message', id: 'm1', data: '{"id":"m1"}' },
      { event: 'state', id: '', data: '{"state":"preparing"}' },
    ])
    expect(state.retry).toBe(3000)
    expect(state.buffer).toBe('')
  })

  test('joins an event cut between two chunks', () => {
    let r = parseSSE('id: m1\nevent: mess', undefined)
    expect(r.events).toEqual([])
    r = parseSSE('age\ndata: {"text":"[secr', r.state)
    expect(r.events).toEqual([])
    r = parseSSE('et-ab12-1]"}\n', r.state)
    expect(r.events).toEqual([])
    r = parseSSE('\n', r.state)
    expect(r.events).toEqual([{ event: 'message', id: 'm1', data: '{"text":"[secret-ab12-1]"}' }])
  })

  test('ignores ": ping" comments and handles CRLF split across chunks', () => {
    let r = parseSSE(': ping\r\n\r\nevent: state\r\ndata: {}\r', undefined)
    expect(r.events).toEqual([])
    r = parseSSE('\n\r\n', r.state)
    expect(r.events).toEqual([{ event: 'state', id: '', data: '{}' }])
  })

  test('an event without a name is a message; several data lines are joined', () => {
    const { events } = parseSSE('data: a\ndata: b\n\n', undefined)
    expect(events).toEqual([{ event: 'message', id: '', data: 'a\nb' }])
  })
})

/** body makes a fetch Response body that sends chunks, then ends. */
function body(chunks) {
  const enc = new TextEncoder()
  return new ReadableStream({
    start(c) {
      for (const ch of chunks) c.enqueue(enc.encode(ch))
      c.close()
    },
  })
}

describe('connect', () => {
  test('reads the stream with fetch and the Authorization header, then reconnects', async () => {
    const calls = []
    const answers = [
      { ok: true, status: 200, body: body(['id: m1\nevent: message\ndata: {"id":"m1"}\n', '\n']) },
      { ok: true, status: 200, body: body(['id: m1\nevent: message\ndata: {"id":"m1"}\n\nevent: state\ndata: {"state":"failed"}\n\n']) },
    ]
    const got = []
    let resolveDone
    const done = new Promise((r) => { resolveDone = r })
    const conn = connect({
      url: '/api/v1/fix/a1/events',
      headers: { Authorization: 'Bearer tok' },
      fetchImpl: async (url, init) => {
        calls.push({ url, init })
        const a = answers.shift()
        if (!a) return new Promise(() => {})
        return a
      },
      wait: async () => {},
      onEvent: (ev) => {
        got.push([ev.event, ev.data])
        if (ev.event === 'state') {
          conn.close()
          resolveDone()
        }
      },
    })
    await done
    expect(calls.length).toBe(2)
    expect(calls[0].url).toBe('/api/v1/fix/a1/events')
    expect(calls[0].init.headers.Authorization).toBe('Bearer tok')
    expect(calls[0].init.headers.Accept).toBe('text/event-stream')
    expect(calls[0].init.signal).toBeDefined()
    expect(got).toEqual([['message', '{"id":"m1"}'], ['message', '{"id":"m1"}'], ['state', '{"state":"failed"}']])
  })

  test('stops on 401 and 404 and says why', async () => {
    for (const status of [401, 404]) {
      let n = 0
      const stopped = await new Promise((resolve) => {
        connect({
          url: '/x',
          headers: {},
          fetchImpl: async () => {
            n += 1
            return { ok: false, status, body: null }
          },
          wait: async () => {},
          onEvent: () => {},
          onStop: resolve,
        })
      })
      expect(stopped).toEqual({ status })
      expect(n).toBe(1)
    }
  })

  test('backs off after failures, longer each time, up to a ceiling', async () => {
    const waits = []
    let n = 0
    await new Promise((resolve) => {
      const conn = connect({
        url: '/x',
        headers: {},
        fetchImpl: async () => {
          n += 1
          if (n > 6) {
            conn.close()
            resolve()
            return new Promise(() => {})
          }
          throw new Error('offline')
        },
        wait: async (ms) => { waits.push(ms) },
        onEvent: () => {},
        minDelay: 1000,
        maxDelay: 8000,
      })
    })
    expect(waits).toEqual([1000, 2000, 4000, 8000, 8000, 8000])
  })
})

describe('connect drops', () => {
  test('onDrop is called after a failure only, not after a stream that ended cleanly', async () => {
    let drops = 0
    let n = 0
    await new Promise((resolve) => {
      const conn = connect({
        url: '/x',
        headers: {},
        fetchImpl: async () => {
          n += 1
          if (n === 1) return { ok: true, status: 200, body: body(['event: state\ndata: {}\n\n']) }
          if (n === 2) throw new Error('offline')
          conn.close()
          resolve()
          return new Promise(() => {})
        },
        wait: async () => {},
        onEvent: () => {},
        onDrop: () => { drops += 1 },
      })
    })
    expect(drops).toBe(1)
  })
})
