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

    <p v-if="loaded && !failed && exposuresPartial" class="m-small m-resolved__partial" role="status">{{ $t('resolved.exposure_unread') }}</p>

    <div v-if="loaded && !failed && !lines.length" class="m-panel m-resolved__empty">
      <p>{{ $t('empty.resolved') }}</p>
      <v-btn variant="flat" color="primary" href="#/">{{ $t('empty.resolved_action') }}</v-btn>
    </div>

    <template v-else-if="loaded && !failed">
      <section v-for="g in groups" :key="g.key" class="m-resolved__group" :aria-labelledby="`resolved-${g.key}`">
        <h2 :id="`resolved-${g.key}`" class="m-resolved__group-title">{{ $t(`resolved.${g.key}.title`) }}</h2>
        <p class="m-muted m-small m-resolved__group-hint">{{ $t(`resolved.${g.key}.hint`) }}</p>
        <p v-if="g.deploy" class="m-small m-resolved__deploy">{{ $t('resolved.deploy') }}</p>
        <ul class="m-panel m-resolved__list">
          <li v-for="(line, i) in g.lines" :key="`${line.href}-${i}`" class="m-resolved__row">
            <span class="m-small m-resolved__word" :class="`m-tag--${line.tone}`">
              {{ $t(`resolved.word.${line.word}`) }}
            </span>
            <div class="m-resolved__text">
              <p class="m-resolved__title">{{ line.title }}</p>
              <p class="m-muted m-small m-resolved__where">
                {{ line.where }}
                <span v-if="line.at">{{ $t(line.dateKey, { date: line.at }) }}</span>
              </p>
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
import { closedExposures } from '../lib/exposureView.js'
import { maxServerDetails, resolvedLines } from '../lib/todoView.js'

export default {
  name: 'ResolvedPage',
  data() {
    return {
      loaded: false,
      // failed: the fixes could not be read. The page then says so: an empty
      // list would claim that nothing is resolved.
      failed: false,
      attempts: [],
      // exposures: the services a server read now no longer shows open to all.
      exposures: [],
      // exposuresPartial: a server could not be read, or is past the limit (R15).
      exposuresPartial: false,
      seq: 0,
    }
  },
  computed: {
    lines() {
      return resolvedLines(this.attempts, this.exposures, this.$ui.lang)
    },
    groups() {
      // The deploy sentence is said once, under the verified group only: it
      // speaks of a fix Michel confirmed, so it never sits under the others.
      const verified = this.lines.filter((l) => l.verified)
      const seen = (l) => l.kind === 'exposure'
      return [
        { key: 'verified', lines: verified, deploy: verified.some((l) => l.deploy) },
        { key: 'unconfirmed', lines: this.lines.filter((l) => !l.verified && !l.back && !seen(l)), deploy: false },
        { key: 'no_longer_open', lines: this.lines.filter(seen), deploy: false },
        { key: 'back', lines: this.lines.filter((l) => l.back), deploy: false },
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
      const lang = `lang=${encodeURIComponent(this.$ui.lang)}`
      const [fixes, exposures] = await Promise.all([
        api.get(`/fixes?state=proven_fixed&${lang}`).then((a) => ({ attempts: a }), () => null),
        this.readExposures(lang),
      ])
      if (seq !== this.seq) return
      this.attempts = Array.isArray(fixes?.attempts) ? fixes.attempts : []
      this.failed = !fixes
      this.exposures = exposures.list
      this.exposuresPartial = exposures.partial
      this.loaded = true
    },
    /** readExposures asks each server what it no longer sees open to all. A read that fails is said, not taken for « nothing ». */
    async readExposures(lang) {
      let servers
      try {
        servers = await api.get(`/targets?${lang}`)
      } catch {
        return { list: [], partial: true }
      }
      const all = (Array.isArray(servers) ? servers : []).filter((s) => s && s.active !== false)
      const read = all.slice(0, maxServerDetails)
      const views = {}
      let partial = read.length < all.length
      await Promise.all(read.map(async (s) => {
        try {
          views[s.id] = await api.get(`/targets/${encodeURIComponent(s.id)}/exposure?${lang}`)
        } catch {
          partial = true
        }
      }))
      return { list: closedExposures(read, views), partial }
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
.m-resolved__partial { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-look)); }
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
.m-resolved__deploy { margin: -0.3rem 0 0.6rem; }
.m-resolved__action { flex: none; }
@media (max-width: 599px) {
  .m-resolved__row { flex-wrap: wrap; }
  .m-resolved__word { width: auto; }
  .m-resolved__text { flex-basis: 100%; }
  .m-resolved__action { width: 100%; }
}
</style>
