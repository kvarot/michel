<template>
  <div class="m-gitup">
    <p class="m-small">{{ $t('git.update.lead') }}</p>
    <v-btn
      class="m-gitup__btn"
      color="primary"
      :variant="running ? 'tonal' : 'flat'"
      :aria-disabled="running ? 'true' : undefined"
      @click="run"
    >
      <v-progress-circular v-if="running" class="m-gitup__spin" indeterminate size="14" width="2" />
      {{ $t(running ? 'git.update.running' : 'git.update.button') }}
    </v-btn>
    <p v-if="running" class="m-gitup__hidden" role="status">{{ $t('git.update.running') }}</p>
    <!-- Read before the click, and it can be old: the button stays, a click tells the truth of now. -->
    <p v-if="why" class="m-gitup__why m-small">{{ why }}</p>
    <p v-if="result" class="m-gitup__result" role="status">{{ $t(`git.update.${result}`) }}</p>
    <div v-if="failure" class="m-gitup__refusal" role="alert">
      <template v-if="failure.key"><p>{{ $t(failure.key) }}</p></template>
      <template v-else>
        <p>{{ failure.error }}</p>
        <p v-if="failure.hint" class="m-small">{{ failure.hint }}</p>
      </template>
    </div>
  </div>
</template>

<script>
import { api } from '../api.js'
import { refusalLines, updateFollowUp } from '../lib/gitView.js'
import { scanPath } from '../lib/projectsView.js'

// GitUpdateButton is « Mettre à jour mon dossier »: one click, one update (R29), and
// the check that follows new files. It stays clickable when the view says it would be
// refused: that reading can be old, and the refusal holds the advice.
export default {
  name: 'GitUpdateButton',
  props: {
    name: { type: String, required: true },
    // update is GitView.update, null when it is not known.
    update: { type: Object, default: null },
  },
  emits: ['scan-started', 'finished'],
  data() {
    return { running: false, result: '', failure: null }
  },
  computed: {
    why() {
      return !this.running && !this.result && !this.failure && this.update && !this.update.ready ? this.update.why : ''
    },
  },
  methods: {
    async run() {
      if (this.running) return
      this.running = true
      this.result = ''
      this.failure = null
      try {
        const res = await api.post(`/projects/${encodeURIComponent(this.name)}/git/update?lang=${encodeURIComponent(this.$ui.lang)}`)
        if (updateFollowUp(res?.outcome) === 'scan') await this.check()
        else this.result = 'none'
      } catch (err) {
        if (err?.status !== 401) this.failure = refusalLines(err)
      } finally {
        this.running = false
        this.$emit('finished')
      }
    },
    /** check starts the check of the new files: the folder is up to date whatever it answers. */
    async check() {
      try {
        await api.post(scanPath(this.name, this.$ui.lang))
        this.result = 'done'
        this.$emit('scan-started')
      } catch (err) {
        this.result = 'done_no_check'
        if (err?.status !== 401) this.failure = refusalLines(err)
      }
    },
  },
}
</script>

<style scoped>
.m-gitup { display: grid; gap: 0.5rem; line-height: 1.5; min-width: 0; }
.m-gitup p { margin: 0; overflow-wrap: anywhere; }
.m-gitup__btn { justify-self: start; max-width: 100%; height: auto; min-height: 36px; white-space: normal; padding-block: 0.35rem; }
.m-gitup__btn[aria-disabled='true'] { cursor: progress; }
.m-gitup__spin { margin-right: 0.5rem; }
.m-gitup__why, .m-gitup__refusal { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-look)); }
.m-gitup__refusal { display: grid; gap: 0.25rem; }
.m-gitup__hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
</style>
