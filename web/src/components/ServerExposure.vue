<template>
  <section class="m-expo" :aria-labelledby="`srv-${target.id}-expo`">
    <p class="m-expo__heading m-small">{{ $t('expo.heading') }}</p>
    <h3 :id="`srv-${target.id}-expo`" class="m-voice m-expo__title">{{ cols.title }}</h3>
    <p class="m-muted m-small">{{ cols.sub }}</p>
    <p v-if="cols.checked" class="m-muted m-small">{{ cols.checked }}</p>
    <p v-if="cols.shared" class="m-expo__shared">{{ cols.shared }}</p>

    <v-alert v-if="failure" type="warning" variant="tonal" density="comfortable" role="alert">
      <p>{{ failure.offline ? $t('offline.hint') : $t('expo.load_failed') }}</p>
      <v-btn size="small" variant="text" color="primary" class="m-expo__retry" @click="$emit('retry')">{{ $t('app.retry') }}</v-btn>
    </v-alert>

    <div v-if="!cols.read && !cols.failed" class="m-expo__check">
      <p class="m-small">{{ $t(emptyKey) }}</p>
      <v-btn
        color="primary"
        variant="tonal"
        size="small"
        :loading="checking"
        :disabled="checking || !target.active || !target.host_key_pinned"
        @click="$emit('check')"
      >
        {{ $t('servers.sheet.check') }}
      </v-btn>
    </div>

    <div class="m-expo__wall">
      <section v-for="c in columns" :key="c.key" class="m-expo__col" :class="`m-expo__col--${c.key}`" :aria-labelledby="`srv-${target.id}-col-${c.key}`">
        <h4 :id="`srv-${target.id}-col-${c.key}`" class="m-expo__col-title">{{ c.title }}</h4>
        <p v-if="!c.rows.length" class="m-muted m-small">{{ c.empty }}</p>
        <ul v-else class="m-expo__rows">
          <li
            v-for="(r, i) in c.rows"
            :id="r.findingId ? `srv-flaw-${r.findingId}` : undefined"
            :key="`${c.key}-${i}`"
            class="m-expo__row"
            :tabindex="r.findingId ? -1 : undefined"
          >
            <span v-if="r.tag === 'close'" class="m-small m-tag--look m-expo__tag">{{ $t('expo.tag.close') }}</span>
            <span v-else-if="r.tag === 'check'" class="m-small m-tag--info m-expo__tag">{{ $t('expo.tag.check') }}</span>
            <p class="m-expo__name">{{ r.name }}</p>
            <p class="m-small m-expo__note"><MaskedText :text="r.note" /></p>
            <p v-if="r.detail" class="m-small m-muted m-code m-expo__detail">{{ r.detail }}</p>

            <div v-if="r.findingId || r.advice.length" class="m-expo__flaw">
              <FailurePath v-if="r.findingId" :steps="pathOf(r)" />
              <details v-if="r.advice.length" class="m-expo__how" :open="!!r.findingId && finding === r.findingId">
                <summary class="m-small">{{ $t('expo.what_to_do') }}</summary>
                <ul class="m-expo__lines m-small">
                  <li v-for="(line, n) in r.advice" :key="n">{{ line }}</li>
                </ul>
              </details>
              <v-btn v-if="r.findingId && !r.decided" size="small" variant="outlined" color="primary" class="m-expo__decide" @click="openDecision(r)">{{ $t('expo.decision.open') }}</v-btn>
              <p v-if="r.undo" class="m-small m-muted m-expo__note">{{ r.undo }}</p>
            </div>
          </li>
        </ul>
      </section>
    </div>

    <v-alert v-if="done" type="success" variant="tonal" density="comfortable" class="m-expo__done" role="status">
      <p>{{ $t('expo.decision.done') }}</p>
      <p class="m-small">
        {{ $t('decision.proof') }} <span class="m-code">{{ done.eventId }}</span>
        <v-btn size="x-small" variant="text" @click="copy">{{ copied ? $t('decision.copied') : $t('decision.copy') }}</v-btn>
      </p>
      <p class="m-small m-muted">{{ $t('decision.proof_hint') }}</p>
    </v-alert>

    <section v-if="cols.closed.length" class="m-expo__closed" :aria-labelledby="`srv-${target.id}-closed`">
      <h4 :id="`srv-${target.id}-closed`" class="m-expo__col-title">{{ $t('expo.closed_title') }}</h4>
      <p v-if="cols.read" class="m-muted m-small">{{ $t('expo.closed_hint') }}</p>
      <ul class="m-expo__rows">
        <li v-for="(c, i) in cols.closed" :key="i" class="m-expo__row">
          <p>{{ c.text }}</p>
          <p v-if="c.when" class="m-small m-muted">{{ c.when }}</p>
          <p v-if="c.detail" class="m-small m-muted m-code">{{ c.detail }}</p>
          <FailurePath v-if="cols.read" class="m-expo__closed-path" :steps="closedSteps" />
        </li>
      </ul>
    </section>

    <v-dialog v-model="decisionOpen" max-width="520" scrollable>
      <v-card :aria-labelledby="`srv-${target.id}-decision`">
        <v-card-title :id="`srv-${target.id}-decision`" class="m-expo__dialog-title">{{ deciding ? $t('expo.decision.title', { service: deciding.name }) : '' }}</v-card-title>
        <v-card-text>
          <form class="m-expo__form" @submit.prevent="submit">
            <p>{{ $t('expo.decision.body') }}</p>
            <p v-if="deciding && deciding.port">{{ $t('expo.decision.which', { number: deciding.port }) }}</p>
            <v-textarea
              v-model="why"
              :label="$t('decision.why')"
              :hint="$t('expo.decision.why_hint')"
              persistent-hint
              rows="2"
              auto-grow
              counter="1000"
              :error-messages="whyError"
            />
            <FieldHelp id="exposure.decision" :field="$t('expo.decision.open')" />
            <div v-if="serverError" class="m-expo__error" role="alert">
              <p>{{ serverError.offline ? $t('offline.hint') : serverError.error || $t('decision.failed') }}</p>
              <p v-if="serverError.hint" class="m-small">{{ serverError.hint }}</p>
            </div>
            <div class="m-expo__dialog-actions">
              <v-btn variant="text" :disabled="saving" @click="decisionOpen = false">{{ $t('expo.decision.cancel') }}</v-btn>
              <v-btn type="submit" color="primary" variant="flat" :loading="saving" :disabled="!check.ok || saving">{{ $t('decision.submit') }}</v-btn>
            </div>
            <span v-if="saving" class="m-muted m-small" role="status">{{ $t('decision.saving') }}</span>
          </form>
        </v-card-text>
      </v-card>
    </v-dialog>
  </section>
</template>

<script>
import FailurePath from './FailurePath.vue'
import { markGuideRead } from '../lib/guideView.js'
import { save } from '../lib/storage.js'
import FieldHelp from './FieldHelp.vue'
import MaskedText from './MaskedText.vue'
import { api } from '../api.js'
import { exposureColumns, exposureDecisionCheck } from '../lib/exposureView.js'
import { exposurePath } from '../lib/pathView.js'

// ServerExposure is what the last check saw listen on a server, from inside it:
// three columns, the third always there, since Michel never reads the firewall
// of the host. ServerSheet owns the reading; a decision answers with the view
// again, handed back to it.
export default {
  name: 'ServerExposure',
  components: { FailurePath, FieldHelp, MaskedText },
  props: {
    // exposure is GET /targets/{id}/exposure, null when it could not be read.
    exposure: { type: Object, default: null },
    // failure is why the page could not read it.
    failure: { type: Object, default: null },
    // target is the TargetView.
    target: { type: Object, required: true },
    // finding is the flaw the address names: its advice is open.
    finding: { type: String, default: '' },
    checking: { type: Boolean, default: false },
  },
  emits: ['check', 'decided', 'retry'],
  data() {
    return {
      decisionOpen: false,
      deciding: null,
      why: '',
      touchedWhy: false,
      saving: false,
      serverError: null,
      done: null,
      copied: false,
    }
  },
  computed: {
    cols() {
      return exposureColumns(this.exposure, this.target, this.$ui.lang, this.$ui.advanced, !!this.failure)
    },
    columns() {
      const third = { key: 'unverified', title: this.$t('expo.col.unverified'), rows: this.cols.unverified, empty: '' }
      // The page did not get the view: the first two would say « not read », which it does not know.
      if (this.cols.failed) return [third]
      return [
        { key: 'open', title: this.$t('expo.col.open'), rows: this.cols.open, empty: this.cols.empty.open },
        { key: 'reserved', title: this.$t('expo.col.reserved'), rows: this.cols.reserved, empty: this.cols.empty.reserved },
        third,
      ]
    },
    closedSteps() {
      return exposurePath({ gone: true }).steps
    },
    // Why there is nothing to show yet, and what to do: the button may be greyed.
    emptyKey() {
      if (!this.target.active) return 'servers.state.inactive'
      return this.target.host_key_pinned ? 'empty.exposure' : 'servers.state.key_unconfirmed'
    },
    // A row with its path is a flaw shown: it counts for the guide, like a card.
    showsFlaw() {
      return this.cols.open.some((r) => r.findingId)
    },
    check() {
      return exposureDecisionCheck(this.why, new Date())
    },
    whyError() {
      const k = this.check.errorKey
      if (k === 'decision.why_too_long') return [this.$t(k)]
      if (k === 'decision.why_required' && this.touchedWhy) return [this.$t(k)]
      return []
    },
  },
  watch: {
    showsFlaw: {
      immediate: true,
      handler(shows) {
        if (shows) markGuideRead(this.$ui.guide, save)
      },
    },
    why() {
      this.touchedWhy = true
    },
    // Opened by code, the dialog has no activator to give the keyboard back to:
    // it goes to the row, or to the card of a list not read, on any way out.
    decisionOpen(open) {
      if (open || !this.deciding) return
      const id = this.deciding.findingId
      this.$nextTick(() => document.getElementById(`srv-flaw-${id}`)?.focus({ preventScroll: true }))
    },
  },
  methods: {
    pathOf(r) {
      return exposurePath({ decided: r.decided }).steps
    },
    /** openDecision opens the dialog for a row, or for a card of the sheet ({findingId, name, port}). */
    openDecision(r) {
      this.deciding = r
      this.why = ''
      this.$nextTick(() => {
        this.touchedWhy = false
      })
      this.serverError = null
      this.decisionOpen = true
    },
    async submit() {
      if (!this.check.ok || this.saving || !this.deciding) return
      const id = this.deciding.findingId
      this.saving = true
      this.serverError = null
      this.done = null
      this.copied = false
      try {
        const q = `?lang=${encodeURIComponent(this.$ui.lang)}`
        const view = await api.post(`/targets/${encodeURIComponent(this.target.id)}/exposure/${encodeURIComponent(id)}/decision${q}`, { why: this.why })
        this.done = { eventId: view?.audit_event_id || '' }
        this.decisionOpen = false
        this.$emit('decided', view)
      } catch (err) {
        if (err?.status === 401) return
        this.serverError = err
        // Gone since: the view may have changed under the dialog.
        if (err?.status === 409) this.$emit('retry')
      } finally {
        this.saving = false
      }
    },
    async copy() {
      try {
        await navigator.clipboard.writeText(this.done.eventId)
        this.copied = true
      } catch {
        this.copied = false
      }
    },
  },
}
</script>

<style scoped>
.m-expo p { margin: 0; line-height: 1.5; }
.m-expo { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0.6rem; }
.m-expo__heading { color: rgb(var(--v-theme-secondary)); font-weight: 650; text-transform: uppercase; letter-spacing: 0.04em; }
.m-expo__title { font-size: 1.25rem; font-weight: 600; line-height: 1.3; margin: 0; overflow-wrap: anywhere; }
.m-expo__shared { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-info)); }
.m-expo__retry { margin: 0.25rem 0 0 -0.6rem; }
.m-expo__check { display: grid; gap: 0.5rem; justify-items: start; }
.m-expo__check p { margin: 0; }
.m-expo__wall { display: flex; flex-wrap: wrap; gap: 0.85rem; align-items: stretch; margin-top: 0.25rem; }
.m-expo__col {
  flex: 1 1 13rem;
  min-width: 0;
  padding: 0.75rem 0.9rem;
  border-radius: 8px;
  border: 1px solid var(--m-line);
  background: rgb(var(--v-theme-surface));
}
.m-expo__col--open { border-top: 4px solid rgb(var(--v-theme-error)); }
.m-expo__col--reserved { border-top: 4px solid rgb(var(--v-theme-success)); }
.m-expo__col--unverified { border-top: 4px solid rgb(var(--v-theme-secondary)); }
.m-expo__col-title { font-size: 0.95rem; font-weight: 650; margin: 0 0 0.4rem; }
.m-expo__rows { list-style: none; margin: 0; padding: 0; }
.m-expo__row { padding: 0.5rem 0; border-top: 1px solid var(--m-line); display: grid; grid-template-columns: minmax(0, 1fr); gap: 0.15rem; justify-items: start; scroll-margin-top: 1rem; }
.m-expo__row:first-child { border-top: 0; padding-top: 0; }
.m-expo__row:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 4px; border-radius: 4px; }
.m-expo__tag { margin-bottom: 0.15rem; }
.m-expo__name { font-weight: 600; overflow-wrap: anywhere; }
.m-expo__note, .m-expo__detail { overflow-wrap: anywhere; }
.m-expo__flaw { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0.5rem; margin-top: 0.4rem; width: 100%; }
.m-expo__how summary { cursor: pointer; color: rgb(var(--v-theme-primary)); font-weight: 600; }
.m-expo__lines { margin: 0.4rem 0 0; padding-left: 1.1rem; display: grid; gap: 0.4rem; line-height: 1.45; }
.m-expo__decide { justify-self: start; max-width: 100%; height: auto !important; min-height: 2rem; white-space: normal; }
.m-expo__decide :deep(.v-btn__content) { white-space: normal; padding: 0.3rem 0; line-height: 1.25; }
.m-expo__done p + p { margin-top: 0.3rem; }
.m-expo__closed { padding: 0.75rem 0.9rem; border-radius: 8px; border: 1px solid var(--m-line); display: grid; gap: 0.4rem; grid-template-columns: minmax(0, 1fr); }
.m-expo__closed-path { margin-top: 0.4rem; width: 100%; }
.m-expo__dialog-title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-expo__form { display: grid; gap: 0.75rem; }
.m-expo__error { color: rgb(var(--v-theme-error)); }
.m-expo__dialog-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.5rem; }
</style>
