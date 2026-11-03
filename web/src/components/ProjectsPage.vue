<template>
  <div class="m-projects-page">
    <section aria-labelledby="projects-title" class="m-projects-page__head">
      <h1 id="projects-title" class="m-verdict">{{ $t('projects.title') }}</h1>
      <p class="m-muted m-small">{{ $t('projects.hint') }}</p>
    </section>

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
import ProjectCard from './ProjectCard.vue'
import { groupAttention } from '../lib/digestView.js'

export default {
  name: 'ProjectsPage',
  components: { ProjectCard },
  props: {
    digest: { type: Object, required: true },
  },
  emits: ['decided'],
  computed: {
    projects() {
      return this.digest.projects || []
    },
    groups() {
      return groupAttention(this.digest)
    },
  },
}
</script>

<style scoped>
.m-projects-page__head { padding-bottom: 1.5rem; }
.m-projects-page__head p { margin: 0.5rem 0 0; }
.m-empty { display: grid; gap: 0.4rem; padding: 1.5rem 0; }
.m-empty p { margin: 0; }
.m-projects { display: grid; gap: 1.25rem; }
</style>
