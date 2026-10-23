<template>
  <div class="m-today">
    <section class="m-hero" aria-labelledby="today-title">
      <p class="m-hero__day m-muted">{{ $t('today.heading') }}</p>
      <h1 id="today-title" class="m-headline">{{ digest.title }}</h1>
      <p v-if="digest.word" class="m-word">{{ digest.word }}</p>
      <p v-if="digest.since_label" class="m-muted m-small m-hero__since">{{ digest.since_label }}</p>
    </section>

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
  </div>
</template>

<script>
import OsvBanner from './OsvBanner.vue'
import ProjectCard from './ProjectCard.vue'
import { groupAttention } from '../lib/digestView.js'

export default {
  name: 'TodayPage',
  components: { OsvBanner, ProjectCard },
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
</style>
