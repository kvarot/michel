<template>
  <section class="m-chat" :aria-label="$t('fix.chat.label')" :aria-busy="String(starting)">
    <div class="m-chat__head">
      <template v-if="showStart">
        <v-btn
          color="primary"
          variant="flat"
          size="x-large"
          class="m-chat__go"
          :loading="starting"
          :disabled="starting || !canStart"
          @click="$emit('start')"
        >
          {{ $t(attempt ? 'fix.chat.retry' : 'fix.chat.start') }}
        </v-btn>
        <p v-if="starting" class="m-chat__line m-voice" role="status">{{ $t('fix.chat.starting') }}</p>
        <p v-else class="m-muted m-small m-chat__hint">{{ $t('fix.chat.start_hint') }}</p>
      </template>
      <p v-else-if="state === 'preparing'" class="m-chat__line m-voice" role="status">
        <v-progress-circular indeterminate size="16" width="2" color="primary" />
        <span>{{ activity || $t('fix.chat.thinking') }}</span>
      </p>
      <p v-else-if="state === 'proposed'" class="m-chat__line m-voice">{{ $t('fix.chat.proposed') }}</p>
      <p v-else-if="attempt && attempt.branch" class="m-chat__line m-voice">{{ $t('fix.chat.applied', { branch: attempt.branch }) }}</p>
      <div v-if="attempt && attempt.cause && ['failed', 'refused', 'superseded', 'inconclusive'].includes(state)" class="m-chat__cause m-small">
        <p><MaskedText :text="$t('fix.chat.cause', { cause: attempt.cause })" /></p>
        <details v-if="attempt.cause_detail" class="m-chat__detail">
          <summary>{{ $t('fix.proposal.detail') }}</summary>
          <p class="m-code"><MaskedText :text="attempt.cause_detail" /></p>
        </details>
      </div>
      <p v-if="reconnecting" class="m-muted m-small" role="status">{{ $t('fix.chat.reconnecting') }}</p>
    </div>

    <ol ref="list" class="m-chat__messages">
      <li v-if="!messages.length && attempt" class="m-muted m-small">{{ $t('fix.chat.empty') }}</li>
      <li v-for="m in messages" :key="m.id" class="m-msg" :class="`m-msg--${role(m)}`">
        <span class="m-msg__who m-small">{{ $t(`fix.chat.role.${role(m)}`) }}</span>
        <p class="m-msg__text" :class="{ 'm-voice': role(m) === 'michel' }"><MaskedText :text="m.text" /></p>
      </li>
    </ol>

    <form v-if="attempt" class="m-chat__form" @submit.prevent="send">
      <template v-if="open">
        <v-textarea
          v-model="draft"
          :label="$t('fix.chat.placeholder')"
          rows="1"
          auto-grow
          max-rows="6"
          hide-details
          :disabled="sending"
          @keydown.enter.exact.prevent="send"
        />
        <v-btn type="submit" color="primary" variant="tonal" :loading="sending" :disabled="sending || !draft.trim()">{{ $t('fix.chat.send') }}</v-btn>
      </template>
      <p v-else class="m-muted m-small">{{ $t('fix.chat.closed') }}</p>
    </form>
  </section>
</template>

<script>
import MaskedText from './MaskedText.vue'

// FixChat is the middle of the Fix page, as in Claude Desktop: the big
// "OK, répare" button for who does not want to talk, then the conversation
// as it streams, what the agent does in one line, and a field to write to
// it. The parent owns the stream and the requests.
export default {
  name: 'FixChat',
  components: { MaskedText },
  props: {
    // attempt is the AttemptView shown, null for a finding not started.
    attempt: { type: Object, default: null },
    messages: { type: Array, default: () => [] },
    activity: { type: String, default: '' },
    canStart: { type: Boolean, default: true },
    starting: { type: Boolean, default: false },
    sending: { type: Boolean, default: false },
    reconnecting: { type: Boolean, default: false },
    // noStart: the page's guide holds the button (a project's flaw).
    noStart: { type: Boolean, default: false },
  },
  emits: ['start', 'send'],
  data() {
    return { draft: '' }
  },
  computed: {
    state() {
      return this.attempt?.state || ''
    },
    // showStart: nothing started, or the last attempt ended without a fix.
    showStart() {
      return !this.noStart && (!this.attempt || ['failed', 'refused', 'superseded'].includes(this.state))
    },
    // open: the agent may still read a message.
    open() {
      return ['preparing', 'proposed'].includes(this.state)
    },
  },
  watch: {
    'messages.length'() {
      this.$nextTick(() => {
        const el = this.$refs.list
        if (el) el.scrollTop = el.scrollHeight
      })
    },
  },
  methods: {
    role(m) {
      return ['user', 'agent', 'michel'].includes(m.role) ? m.role : 'michel'
    },
    send() {
      const text = this.draft.trim()
      if (!text || this.sending) return
      this.$emit('send', text, () => {
        this.draft = ''
      })
    },
  },
}
</script>

<style scoped>
.m-chat { display: grid; grid-template-rows: auto minmax(0, 1fr) auto; gap: 1rem; min-height: 0; }
.m-chat__head { display: grid; gap: 0.6rem; justify-items: start; }
.m-chat__go { font-weight: 650; letter-spacing: 0; }
.m-chat__line { display: flex; align-items: center; gap: 0.6rem; margin: 0; font-size: 1.1rem; line-height: 1.5; }
.m-chat__hint { margin: 0; max-width: 56ch; }
.m-chat__cause { margin: 0; padding: 0.5rem 0.75rem; border-radius: 8px; background: rgba(var(--v-theme-warning), 0.1); }
.m-chat__cause p { margin: 0; }
.m-chat__detail summary { cursor: pointer; margin-top: 0.35rem; }
.m-chat__detail p { margin-top: 0.25rem; overflow-wrap: anywhere; }
.m-chat__messages {
  list-style: none;
  margin: 0;
  padding: 0 0.25rem 0 0;
  display: grid;
  align-content: start;
  gap: 0.75rem;
  overflow-y: auto;
  max-height: 60vh;
  min-height: 8rem;
}
.m-msg { display: grid; gap: 0.15rem; max-width: 92%; }
.m-msg__who { font-weight: 650; color: rgba(var(--v-theme-on-surface), 0.66); }
.m-msg__text {
  margin: 0;
  padding: 0.6rem 0.85rem;
  border-radius: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: rgba(var(--v-theme-on-surface), 0.045);
}
.m-msg--user { justify-self: end; }
.m-msg--user .m-msg__who { justify-self: end; }
.m-msg--user .m-msg__text { background: rgba(var(--v-theme-primary), 0.12); }
.m-msg--michel .m-msg__text { background: transparent; padding-left: 0; font-size: 1.05rem; }
.m-chat__form { display: flex; gap: 0.5rem; align-items: flex-end; }
.m-chat__form p { margin: 0; }
</style>
