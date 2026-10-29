<template>
  <div class="m-today">
    <section class="m-hero" aria-labelledby="today-title">
      <p class="m-hero__day m-muted">{{ $t('today.heading') }}</p>
      <h1 id="today-title" class="m-headline">{{ digest.title }}</h1>
      <p v-if="digest.word" class="m-word">{{ digest.word }}</p>
      <p v-if="digest.since_label" class="m-muted m-small m-hero__since">{{ digest.since_label }}</p>
    </section>

    <ExploitedBanner :exploited="digest.exploited || []" :decided="digest.exploited_decided || 0" @decided="$emit('decided')" />

    <OsvBanner :fetched-at="osvFetchedAt" :stale="digest.osv_stale" />

    <v-alert v-if="digest.failed_scans > 0" type="warning" variant="tonal" class="m-block" density="comfortable">
      {{ $t('today.failed_scans', { n: digest.failed_scans }) }}
    </v-alert>

    <section v-if="!projects.length" class="m-empty">
      <p>{{ $t('today.no_projects') }}</p>
      <p class="m-muted">{{ $t('today.no_projects_hint') }}</p>
    </section>

    <div class="m-projects">
      <ProjectCard
        v-for="(p, i) in projects"
        :key="p.name"
        :project="p"
        :items="groups[i] ? groups[i].items : []"
        @decided="$emit('decided')"
      />
    </div>

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
import ProjectCard from './ProjectCard.vue'
import ReadingList from './ReadingList.vue'
import { groupAttention } from '../lib/digestView.js'

export default {
  name: 'TodayPage',
  components: { ExploitedBanner, OsvBanner, ProjectCard, ReadingList },
  props: {
    digest: { type: Object, required: true },
    meta: { type: Object, default: null },
  },
  emits: ['decided'],
  computed: {
    projects() {
      return this.digest.projects || []
    },
    groups() {
      return groupAttention(this.digest)
    },
    catalog() {
      return this.digest.catalog || {}
    },
    osvFetchedAt() {
      const t = this.digest.osv_fetched_at || ''
      return t.startsWith('0001-') ? '' : t
    },
  },
}
</script>

<style scoped>
.m-hero { padding-bottom: 2rem; }
.m-hero__day { margin: 0 0 0.5rem; font-size: 0.95rem; }
.m-hero__since { margin: 0.75rem 0 0; }
.m-block { margin-bottom: 1.25rem; }
.m-empty { display: grid; gap: 0.4rem; padding: 1.5rem 0; }
.m-empty p { margin: 0; }
.m-projects { display: grid; gap: 1.25rem; }
.m-catalog { margin-top: 2rem; color: rgba(var(--v-theme-on-background), 0.72); }
.m-catalog summary { cursor: pointer; }
.m-catalog__list { margin: 0.5rem 0 0; padding-left: 1.25rem; }
.m-catalog__open { margin: 0.25rem 0 0 -0.75rem; }
</style>
