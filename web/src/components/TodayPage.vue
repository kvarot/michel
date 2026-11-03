<template>
  <div class="m-today">
    <section class="m-hero" aria-labelledby="today-title">
      <p class="m-hero__day m-muted">{{ $t('today.heading') }}</p>
      <h1 id="today-title" class="m-headline">{{ headline.title }}</h1>
      <p v-if="headline.word" class="m-word">{{ headline.word }}</p>
      <p v-if="digest.since_label" class="m-muted m-small m-hero__since">{{ digest.since_label }}</p>
    </section>

    <section v-if="touched.length" class="m-review m-review--servers" aria-labelledby="servers-title">
      <h2 id="servers-title" class="m-review__title">{{ $t('today.servers.title') }}</h2>
      <p class="m-muted m-small m-review__hint">{{ $t('today.servers.hint') }}</p>
      <ul class="m-review__list">
        <li v-for="t in touched" :key="t.id" class="m-review__item">
          <span class="m-review__what">
            <span class="m-review__pkg">{{ t.name }}</span>
            <span class="m-small m-voice">{{ serverSentence(t) }}</span>
          </span>
          <v-btn color="primary" variant="flat" size="small" :href="serverHref(t)">{{ $t('today.servers.open') }}</v-btn>
        </li>
      </ul>
    </section>

    <section v-if="toReview.length" class="m-review" aria-labelledby="review-title">
      <h2 id="review-title" class="m-review__title">{{ $t('today.fixes.title') }}</h2>
      <p class="m-muted m-small m-review__hint">{{ $t('today.fixes.hint') }}</p>
      <ul class="m-review__list">
        <li v-for="a in toReview" :key="a.id" class="m-review__item">
          <span class="m-review__what">
            <span class="m-code m-review__pkg">{{ a.finding.package }}</span>
            <span class="m-muted m-small">{{ a.server ? $t('srvfix.flaw_on', { name: a.server.target.name }) : $t('fix.in_project', { project: a.project }) }}</span>
          </span>
          <v-btn color="primary" variant="flat" size="small" :href="reviewHref(a)">{{ $t('today.fixes.open') }}</v-btn>
        </li>
      </ul>
    </section>

    <ExploitedBanner :exploited="digest.exploited || []" :decided="digest.exploited_decided || 0" @decided="$emit('decided')" />

    <OsvBanner :fetched-at="osvFetchedAt" :stale="digest.osv_stale" />

    <v-alert v-if="digest.failed_scans > 0" type="warning" variant="tonal" class="m-block" density="comfortable">
      {{ $t('today.failed_scans', { n: digest.failed_scans }) }}
    </v-alert>

    <ReadingList :items="digest.reading || []" />

    <details v-if="catalog.line" class="m-catalog">
      <summary class="m-small">{{ catalog.line }}</summary>
      <ul class="m-catalog__list m-small">
        <li v-if="(catalog.failed || []).length">{{ $t('catalog.failed', { keys: catalog.failed.join(', ') }) }}</li>
        <li v-if="(catalog.waiting_consent || []).length">{{ $t('catalog.waiting', { keys: catalog.waiting_consent.join(', ') }) }}</li>
        <li v-if="(catalog.unreachable || []).length">{{ $t('catalog.unreachable', { keys: catalog.unreachable.join(', ') }) }}</li>
        <li v-if="(catalog.new_versions || []).length">{{ $t('catalog.new_versions', { names: catalog.new_versions.map((v) => v.name).join(', ') }) }}</li>
        <li v-if="digest.discover_new > 0">{{ $t('catalog.discover', { n: digest.discover_new }) }}</li>
      </ul>
      <v-btn variant="text" size="small" color="primary" href="#/sources" class="m-catalog__open">{{ $t('catalog.open') }}</v-btn>
    </details>
  </div>
</template>

<script>
import ExploitedBanner from './ExploitedBanner.vue'
import OsvBanner from './OsvBanner.vue'
import ReadingList from './ReadingList.vue'
import { api } from '../api.js'
import { fixHash } from '../lib/fixView.js'
import { serverHeadline, serversHash, stateSentence, touchedServers } from '../lib/serversView.js'

export default {
  name: 'TodayPage',
  components: { ExploitedBanner, OsvBanner, ReadingList },
  props: {
    digest: { type: Object, required: true },
    meta: { type: Object, default: null },
  },
  emits: ['decided'],
  data() {
    return { toReview: [], touched: [], servers: [] }
  },
  computed: {
    // headline: an urgent (else critical) server flaw comes before the
    // projects' digest, which never says "all calm" over it.
    headline() {
      return serverHeadline(this.servers, this.$ui.lang) || { title: this.digest.title, word: this.digest.word }
    },
    catalog() {
      return this.digest.catalog || {}
    },
    osvFetchedAt() {
      const t = this.digest.osv_fetched_at || ''
      return t.startsWith('0001-') ? '' : t
    },
  },
  watch: {
    // A new digest (refresh, decision, language) reads the fixes again.
    digest() {
      this.loadReview()
      this.loadServers()
    },
  },
  created() {
    this.loadReview()
    this.loadServers()
  },
  methods: {
    /** loadReview reads the fixes waiting for approval; without the fix service the section stays hidden. */
    async loadReview() {
      try {
        this.toReview = (await api.get(`/fixes?state=proposed&lang=${encodeURIComponent(this.$ui.lang)}`)) || []
      } catch {
        this.toReview = []
      }
    },
    /** loadServers reads the servers: those touched by a flaw come first on the page. */
    async loadServers() {
      try {
        this.servers = (await api.get(`/targets?lang=${encodeURIComponent(this.$ui.lang)}`)) || []
        this.touched = touchedServers(this.servers)
      } catch {
        this.servers = []
        this.touched = []
      }
    },
    serverSentence(t) {
      return stateSentence(t, this.$ui.lang)
    },
    serverHref(t) {
      return serversHash(t.id)
    },
    reviewHref(a) {
      return fixHash({ attempt: a.id })
    },
  },
}
</script>

<style scoped>
.m-hero { padding-bottom: 2rem; }
.m-hero__day { margin: 0 0 0.5rem; font-size: 0.95rem; }
.m-hero__since { margin: 0.75rem 0 0; }
.m-block { margin-bottom: 1.25rem; }
.m-review {
  margin-bottom: 1.5rem;
  padding: 1rem 1.25rem;
  border-radius: 12px;
  border: 1px solid rgba(var(--v-theme-primary), 0.35);
  background: rgba(var(--v-theme-primary), 0.07);
}
.m-review--servers { border-color: rgba(var(--v-theme-error), 0.35); background: rgba(var(--v-theme-error), 0.06); }
.m-review__title { font-family: var(--m-voice); font-size: 1.3rem; font-weight: 600; margin: 0 0 0.25rem; }
.m-review__hint { margin: 0 0 0.6rem; }
.m-review__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.5rem; }
.m-review__item { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.5rem 1rem; }
.m-review__what { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem 0.6rem; }
.m-review__pkg { font-weight: 600; }
.m-catalog { margin-top: 2rem; color: rgba(var(--v-theme-on-background), 0.72); }
.m-catalog summary { cursor: pointer; }
.m-catalog__list { margin: 0.5rem 0 0; padding-left: 1.25rem; }
.m-catalog__open { margin: 0.25rem 0 0 -0.75rem; }
</style>
