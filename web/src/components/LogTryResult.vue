<template>
  <div class="m-try" role="region" :aria-labelledby="`${uid}-title`">
    <p :id="`${uid}-title`" class="m-try__title">{{ $t('logs.try.title') }}</p>
    <p v-if="result.message" class="m-small" role="status">{{ result.message }}</p>
    <p v-if="result.note" class="m-muted m-small">{{ result.note }}</p>
    <template v-if="records.length">
      <p class="m-small">{{ $t('logs.try.found', { n: records.length }) }}</p>
      <ul class="m-try__list">
        <li v-for="(r, i) in records" :key="i" class="m-try__item">
          <p>
            <span class="m-sev" :class="`m-sev--${severity(r.level)}`">{{ levelText(r.level) }}</span>
            <span class="m-voice"> {{ r.type || r.location || $t('logs.errors.unknown') }}</span>
          </p>
          <p v-if="r.type && r.location" class="m-muted m-small">{{ $t('logs.errors.where', { where: r.location }) }}</p>
          <p class="m-muted m-small">{{ $t('logs.try.times', { n: r.count }) }}</p>
          <p v-if="r.text" class="m-small">{{ r.text }}</p>
        </li>
      </ul>
    </template>
    <ul v-if="unseen.length" class="m-try__plain m-small">
      <li v-for="u in unseen" :key="u.what">{{ u.text }}</li>
    </ul>
    <p v-if="result.skipped_bytes > 0" class="m-muted m-small">{{ $t('logs.try.partial') }}</p>
    <p v-if="result.too_many_files" class="m-muted m-small">{{ $t('logs.try.too_many') }}</p>
    <p v-if="result.rejected > 0 && records.length" class="m-muted m-small">{{ $t('logs.try.rejected', { n: result.rejected }) }}</p>
    <div>
      <v-btn size="small" variant="text" @click="$emit('close')">{{ $t('logs.close') }}</v-btn>
    </div>
  </div>
</template>

<script>
import { levelLabel, levelSeverity } from '../lib/serverLogsView.js'

let counter = 0

// LogTryResult shows what "Essayer" brought back: exactly what a real read
// would keep (level, type, place, how many times, the cleaned text only if
// the API returned one), with nothing stored. A line of the log is never in it.
export default {
  name: 'LogTryResult',
  props: {
    result: { type: Object, required: true },
    lang: { type: String, default: 'fr' },
  },
  emits: ['close'],
  data() {
    return { uid: `m-try-${++counter}` }
  },
  computed: {
    records() {
      return this.result.records || []
    },
    unseen() {
      return (this.result.unseen || []).map((u) => ({ what: u.what, text: this.$t('logs.read.unseen', { what: u.what, reason: u.reason }) }))
    },
  },
  methods: {
    levelText(l) {
      return levelLabel(l, this.lang)
    },
    severity: levelSeverity,
  },
}
</script>

<style scoped>
.m-try { display: grid; gap: 0.5rem; padding: 0.75rem 1rem; border-radius: 8px; border: 1px solid rgba(var(--v-theme-on-surface), 0.15); background: rgba(var(--v-theme-on-surface), 0.04); }
.m-try p { margin: 0; line-height: 1.55; }
.m-try__title { font-weight: 650; }
.m-try__list, .m-try__plain { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.6rem; }
.m-try__item { display: grid; gap: 0.15rem; }
</style>
