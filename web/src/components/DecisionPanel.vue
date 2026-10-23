<template>
  <section class="m-decision" :aria-labelledby="titleId">
    <h4 :id="titleId" class="m-decision__title">{{ $t('decision.title') }}</h4>
    <p class="m-small" :class="{ 'm-muted': !current }">
      {{ current ? $t('decision.current', { label: current }) : $t('decision.none') }}
    </p>

    <p v-if="finding.status === 'gone'" class="m-small">{{ $t('decision.gone') }}</p>

    <form v-else class="m-decision__form" @submit.prevent="submit">
      <div class="m-decision__actions" role="group" :aria-label="$t('decision.title')">
        <v-btn
          v-for="a in actions"
          :key="a"
          :variant="action === a ? 'flat' : 'outlined'"
          color="primary"
          :aria-pressed="String(action === a)"
          @click="action = action === a ? '' : a"
        >
          {{ $t(`decision.action.${a}`) }}
        </v-btn>
      </div>

      <v-text-field
        v-if="action === 'defer'"
        v-model="until"
        type="date"
        :label="$t('decision.until')"
        :min="tomorrow"
        :hint="$t('decision.until_hint', { date: defaultDate })"
        persistent-hint
        :error-messages="untilError"
        class="m-decision__until"
      />

      <v-textarea
        v-model="why"
        :label="$t('decision.why')"
        :hint="$t(action === 'ignore' ? 'decision.why_needed' : 'decision.why_optional')"
        persistent-hint
        rows="2"
        auto-grow
        counter="1000"
        :error-messages="whyError"
      />

      <p v-if="action && check.ok" class="m-decision__will" aria-live="polite">{{ will }}</p>

      <div class="m-decision__submit">
        <v-btn type="submit" color="primary" variant="flat" :loading="saving" :disabled="!check.ok || saving">
          {{ $t('decision.submit') }}
        </v-btn>
        <span v-if="saving" class="m-muted m-small" role="status">{{ $t('decision.saving') }}</span>
      </div>
    </form>

    <v-alert v-if="done" type="success" variant="tonal" density="comfortable" class="m-decision__done" role="status">
      <p class="m-decision__line">{{ done.text }}</p>
      <p class="m-decision__line m-small">
        {{ $t('decision.proof') }} <span class="m-code">{{ done.eventId }}</span>
        <v-btn size="x-small" variant="text" class="m-decision__copy" @click="copy">{{ copied ? $t('decision.copied') : $t('decision.copy') }}</v-btn>
      </p>
      <p class="m-decision__line m-small m-muted">{{ $t('decision.proof_hint') }}</p>
    </v-alert>

    <v-alert v-if="serverError" type="error" variant="tonal" density="comfortable" class="m-decision__done" role="alert">
      <p class="m-decision__line">{{ serverError.offline ? $t('offline.hint') : serverError.error || $t('decision.failed') }}</p>
      <p v-if="serverError.hint" class="m-decision__line m-small">{{ serverError.hint }}</p>
    </v-alert>
  </section>
</template>

<script>
import { api } from '../api.js'
import { decisionLabel, formatDate, isoDay, validateDecision } from '../lib/digestView.js'

let seq = 0

export default {
  name: 'DecisionPanel',
  props: {
    finding: { type: Object, required: true },
  },
  emits: ['decided'],
  data() {
    seq += 1
    const now = new Date()
    return {
      titleId: `decision-${seq}`,
      actions: ['fix', 'defer', 'ignore'],
      action: '',
      why: '',
      until: isoDay(now, 30),
      touchedWhy: false,
      saving: false,
      done: null,
      serverError: null,
      copied: false,
    }
  },
  computed: {
    current() {
      return decisionLabel(this.finding.decision, this.$ui.lang)
    },
    tomorrow() {
      return isoDay(new Date(), 1)
    },
    defaultDate() {
      return formatDate(isoDay(new Date(), 30), this.$ui.lang)
    },
    request() {
      return { action: this.action, why: this.why, until: this.action === 'defer' ? this.until : '' }
    },
    check() {
      return validateDecision(this.request, new Date())
    },
    untilError() {
      return ['decision.until_past', 'decision.until_invalid'].includes(this.check.errorKey) ? [this.$t(this.check.errorKey)] : []
    },
    whyError() {
      const k = this.check.errorKey
      if (k === 'decision.why_too_long') return [this.$t(k)]
      if (k === 'decision.why_required' && this.touchedWhy) return [this.$t(k)]
      return []
    },
    will() {
      if (this.action === 'defer') {
        // An empty date means the server default: in 30 days.
        const date = this.until.trim() ? formatDate(this.until, this.$ui.lang) : this.defaultDate
        return this.$t('decision.will.defer', { date })
      }
      return this.$t(`decision.will.${this.action}`)
    },
  },
  watch: {
    why() {
      this.touchedWhy = true
    },
    action() {
      this.serverError = null
    },
  },
  methods: {
    async submit() {
      if (!this.check.ok || this.saving) return
      this.saving = true
      this.serverError = null
      this.done = null
      this.copied = false
      const sent = { ...this.request }
      try {
        const view = await api.post(`/findings/${encodeURIComponent(this.finding.id)}/decision?lang=${encodeURIComponent(this.$ui.lang)}`, sent)
        const dueDate = formatDate(view.decision?.due_at, this.$ui.lang)
        this.done = { text: this.$t(`decision.done.${sent.action}`, { date: dueDate }), eventId: view.audit_event_id || '' }
        this.action = ''
        this.why = ''
        this.touchedWhy = false
        this.$emit('decided', view)
      } catch (err) {
        if (err?.status !== 401) this.serverError = err
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
.m-decision {
  border-top: 1px solid rgba(var(--v-theme-on-surface), 0.1);
  padding-top: 1rem;
}
.m-decision__title { font-size: 1rem; font-weight: 650; margin: 0 0 0.25rem; }
.m-decision p { margin: 0 0 0.75rem; }
.m-decision__form { display: grid; gap: 0.9rem; }
.m-decision__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.m-decision__until { max-width: 22rem; }
.m-decision__will {
  border-left: 3px solid rgb(var(--v-theme-primary));
  padding: 0.2rem 0 0.2rem 0.75rem;
  margin: 0 !important;
  line-height: 1.5;
}
.m-decision__submit { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; }
.m-decision__done { margin-top: 1rem; }
.m-decision__line { margin: 0 !important; }
.m-decision__line + .m-decision__line { margin-top: 0.3rem !important; }
.m-decision__copy { margin-left: 0.25rem; }
</style>
