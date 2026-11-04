<template>
  <div class="m-projects-page">
    <section aria-labelledby="projects-title" class="m-projects-page__head">
      <h1 id="projects-title" class="m-verdict">{{ $t('projects.title') }}</h1>
      <p class="m-muted m-small">{{ $t('projects.hint') }}</p>
      <div v-if="projects.length" class="m-projects-page__actions">
        <v-btn color="primary" variant="flat" @click="dialog = true">{{ $t('projects.add') }}</v-btn>
      </div>
    </section>

    <p v-if="notice" ref="notice" class="m-projects-page__notice" role="status" tabindex="-1">{{ notice }}</p>
    <p v-if="lost" class="m-projects-page__notice" role="alert">{{ $t('projects.scan_lost') }}</p>

    <section v-if="!projects.length" class="m-empty">
      <template v-if="$ui.advanced">
        <p>{{ $t('today.no_projects') }}</p>
        <p class="m-muted">{{ $t('today.no_projects_hint') }}</p>
      </template>
      <p v-else>{{ $t('empty.projects') }}</p>
      <v-btn class="m-empty__action" color="primary" variant="flat" @click="dialog = true">{{ $t('projects.add') }}</v-btn>
    </section>

    <div class="m-projects">
      <ProjectCard
        v-for="(p, i) in projects"
        :key="p.name"
        :project="p"
        :items="groups[i] ? groups[i].items : []"
        :digest-fresh="digestFresh"
        @decided="$emit('decided')"
        @scan-changed="onScanChanged"
      />
    </div>

    <v-dialog v-model="dialog" max-width="560" scrollable>
      <AddProjectDialog v-if="dialog" @close="dialog = false" @added="onAdded" />
    </v-dialog>
  </div>
</template>

<script>
import AddProjectDialog from './AddProjectDialog.vue'
import ProjectCard from './ProjectCard.vue'
import { api } from '../api.js'
import { groupAttention } from '../lib/digestView.js'
import { anyScanning, needsDigest, withScanState } from '../lib/projectsView.js'

// Between two looks at a running check; and how many failed looks in a row
// are told to the person.
const pollEvery = 2000
const maxLost = 3

// ProjectsPage is "Mes projets": the cards of the digest, the button to add a
// project, and how the checks stand (GET /projects). It looks again while a
// check runs, and reads the digest again when one ends.
export default {
  name: 'ProjectsPage',
  components: { AddProjectDialog, ProjectCard },
  props: {
    digest: { type: Object, required: true },
  },
  emits: ['decided', 'changed'],
  data() {
    return { views: [], dialog: false, notice: '', lost: false, misses: 0, timer: null, digestFresh: false, awaiting: false, firstLoad: true }
  },
  computed: {
    lang() {
      return this.$ui.lang
    },
    projects() {
      const byName = Object.fromEntries(this.views.map((v) => [v.name, v]))
      return (this.digest.projects || []).map((p) => withScanState(p, byName[p.name]))
    },
    groups() {
      return groupAttention(this.digest)
    },
  },
  watch: {
    lang() {
      this.loadViews()
    },
    // App answered: the cards may now trust the counts.
    digest() {
      this.digestFresh = true
    },
  },
  created() {
    this.loadViews()
  },
  beforeUnmount() {
    clearTimeout(this.timer)
    this.timer = null
    this.gone = true
  },
  methods: {
    async loadViews() {
      clearTimeout(this.timer)
      this.timer = null
      const previous = this.views
      let list
      try {
        list = (await api.get(`/projects?lang=${encodeURIComponent(this.lang)}`)) || []
      } catch (err) {
        if (this.gone || err?.status === 401) return
        // Michel does not answer: the last state stays, and the page says it may be old.
        this.misses += 1
        this.lost = this.misses >= maxLost
        if (anyScanning(this.views)) this.timer = setTimeout(this.loadViews, pollEvery)
        return
      }
      if (this.gone) return
      this.misses = 0
      this.lost = false
      this.views = list
      const wanted = needsDigest(previous, list, this.awaiting, this.firstLoad)
      this.firstLoad = false
      if (anyScanning(list)) {
        this.timer = setTimeout(this.loadViews, pollEvery)
        return
      }
      this.awaiting = false
      if (wanted) {
        // A check may have ended: the counts of the cards changed, and until
        // they arrive no card says "0 critical".
        this.digestFresh = false
        this.$emit('decided')
      }
    },
    onScanChanged() {
      // The digest predates this check: if the person leaves before it ends, the To-do page reads it again.
      this.$emit('changed')
      this.notice = ''
      this.awaiting = true
      this.loadViews()
    },
    onAdded(added) {
      this.dialog = false
      this.notice = this.$t('projects.added', { name: added?.name || '' })
      // The button that opened the dialog may leave with the empty screen.
      this.$nextTick(() => this.$refs.notice?.focus())
      this.$emit('decided')
      this.loadViews()
    },
  },
}
</script>

<style scoped>
.m-projects-page__head { padding-bottom: 1.5rem; }
.m-projects-page__head p { margin: 0.5rem 0 0; }
.m-projects-page__actions { margin-top: 1rem; }
.m-projects-page__notice { margin: 0 0 1rem; outline: none; }
.m-empty { display: grid; gap: 0.4rem; padding: 0 0 1.5rem; justify-items: start; }
.m-empty__action { margin-top: 0.6rem; }
.m-empty p { margin: 0; }
.m-projects { display: grid; gap: 1.25rem; }
</style>
