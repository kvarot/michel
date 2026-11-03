<template>
  <section aria-labelledby="resolved-title" class="m-resolved">
    <header class="m-resolved__head">
      <h1 id="resolved-title" class="m-verdict">{{ $t('resolved.title') }}</h1>
      <p class="m-muted m-resolved__sub">{{ $t('resolved.sub') }}</p>
    </header>

    <div v-if="!loaded" class="m-resolved__loading" role="status">
      <v-progress-circular indeterminate color="primary" size="28" width="3" />
      <p class="m-muted">{{ $t('app.loading') }}</p>
    </div>

    <div v-else-if="failed" class="m-panel m-resolved__error" role="alert">
      <p>{{ $t('resolved.error') }}</p>
      <v-btn variant="outlined" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
    </div>

    <div v-else-if="!lines.length" class="m-panel m-resolved__empty">
      <p>{{ $t('empty.resolved') }}</p>
      <v-btn variant="flat" color="primary" href="#/">{{ $t('empty.resolved_action') }}</v-btn>
    </div>

    <template v-else>
      <section v-for="g in groups" :key="g.key" class="m-resolved__group" :aria-labelledby="`resolved-${g.key}`">
        <h2 :id="`resolved-${g.key}`" class="m-resolved__group-title">{{ $t(`resolved.${g.key}.title`) }}</h2>
        <p class="m-muted m-small m-resolved__group-hint">{{ $t(`resolved.${g.key}.hint`) }}</p>
        <ul class="m-panel m-resolved__list">
          <li v-for="(line, i) in g.lines" :key="`${line.href}-${i}`" class="m-resolved__row">
            <span class="m-small m-resolved__word" :class="line.verified ? 'm-tag--done' : 'm-tag--look'">
              {{ $t(line.verified ? 'resolved.word.verified' : 'resolved.word.unconfirmed') }}
            </span>
            <div class="m-resolved__text">
              <p class="m-resolved__title">{{ line.title }}</p>
              <p class="m-muted m-small m-resolved__where">
                {{ line.where }}
                <span v-if="line.at">{{ $t('resolved.date', { date: line.at }) }}</span>
              </p>
              <p v-if="line.deploy" class="m-small m-resolved__deploy">{{ $t('resolved.deploy') }}</p>
            </div>
            <v-btn class="m-resolved__action" variant="outlined" color="primary" :href="line.href">{{ $t('resolved.open') }}</v-btn>
          </li>
        </ul>
      </section>
    </template>
  </section>
</template>

<script>
import { api } from '../api.js'
import { resolvedLines } from '../lib/todoView.js'

export default {
  name: 'ResolvedPage',
  data() {
    return {
      loaded: false,
      // failed: the fixes could not be read. The page then says so: an empty
      // list would claim that nothing is resolved.
      failed: false,
      attempts: [],
      // No route sends the exposures a reading no longer sees yet: none are
      // listed, and none are claimed.
      exposures: [],
      seq: 0,
    }
  },
  computed: {
    lines() {
      return resolvedLines(this.attempts, this.exposures, this.$ui.lang)
    },
    groups() {
      return [
        { key: 'verified', lines: this.lines.filter((l) => l.verified) },
        { key: 'unconfirmed', lines: this.lines.filter((l) => !l.verified) },
      ].filter((g) => g.lines.length)
    },
  },
  created() {
    this.load()
  },
  methods: {
    async load() {
      const seq = ++this.seq
      this.loaded = false
      try {
        const attempts = await api.get(`/fixes?state=proven_fixed&lang=${encodeURIComponent(this.$ui.lang)}`)
        if (seq !== this.seq) return
        this.attempts = Array.isArray(attempts) ? attempts : []
        this.failed = false
      } catch {
        if (seq !== this.seq) return
        this.attempts = []
        this.failed = true
      }
      this.loaded = true
    },
  },
}
</script>

<style scoped>
.m-resolved { display: grid; gap: 1.25rem; }
.m-resolved p { margin: 0; }
.m-resolved__sub { margin-top: 0.5rem; }
.m-resolved__loading { display: grid; gap: 0.9rem; justify-items: start; }
.m-resolved__error, .m-resolved__empty { display: grid; gap: 0.9rem; justify-items: start; padding: 1rem 0.9rem; }
.m-resolved__group-title { font-size: 1.05rem; font-weight: 600; margin: 0; }
.m-resolved__group-hint { margin: 0.2rem 0 0.6rem; }
.m-resolved__list { list-style: none; margin: 0; padding: 0; }
.m-resolved__row { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 0.9rem; }
.m-resolved__row + .m-resolved__row { border-top: 1px solid var(--m-line); }
.m-resolved__word { flex: none; width: 8rem; justify-content: center; }
.m-resolved__text { flex: 1 1 auto; min-width: 0; }
.m-resolved__title { font-weight: 600; line-height: 1.35; overflow-wrap: anywhere; }
.m-resolved__where { margin-top: 0.15rem; overflow-wrap: anywhere; }
.m-resolved__where span::before { content: ' · '; }
.m-resolved__deploy { margin-top: 0.25rem; }
.m-resolved__action { flex: none; }
@media (max-width: 599px) {
  .m-resolved__row { flex-wrap: wrap; }
  .m-resolved__word { width: auto; }
  .m-resolved__text { flex-basis: 100%; }
  .m-resolved__action { width: 100%; }
}
</style>
