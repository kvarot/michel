<template>
  <section class="m-merge m-panel" aria-labelledby="fix-merge-lead">
    <!-- Above both modes: a refused send can end the attached mode, and it must still be read. -->
    <div v-if="pushFailure" class="m-merge__refusal" role="alert">
      <template v-if="pushFailure.key"><p>{{ $t(pushFailure.key) }}</p></template>
      <template v-else>
        <p>{{ pushFailure.error }}</p>
        <p v-if="pushFailure.hint" class="m-small">{{ pushFailure.hint }}</p>
      </template>
    </div>

    <template v-if="step.mode === 'manual'">
      <p id="fix-merge-lead" ref="lead" tabindex="-1" class="m-merge__lead">{{ $t('git.manual.lead') }}</p>
      <div class="m-merge__cmd">
        <code class="m-code m-merge__code">{{ step.command }}</code>
        <v-btn size="small" variant="tonal" color="primary" @click="copy">{{ copied ? $t('git.manual.copied') : $t('git.manual.copy') }}</v-btn>
      </div>
      <p v-if="copyFailed" class="m-small" role="alert">{{ $t('git.manual.copy_failed') }}</p>
      <p v-if="copied" class="m-merge__hidden" role="status">{{ $t('git.manual.copied') }}</p>
      <p>{{ $t('git.manual.next') }}</p>
      <a href="#/projects" class="m-merge__projects">{{ $t('git.manual.projects') }}</a>

      <GitQuestion v-if="asks" class="m-merge__git" :name="project" :view="git" :heading="heading" :start-open="attaching" @answered="onAnswered" @reload="$emit('reload-git')" />
      <div v-else-if="step.attach" class="m-merge__git">
        <p>{{ $t('git.manual.attach') }}</p>
        <v-btn size="small" variant="tonal" color="primary" class="m-merge__attach" @click="onAttach">{{ $t('git.attach') }}</v-btn>
      </div>
    </template>

    <template v-else>
      <p id="fix-merge-lead" ref="lead" tabindex="-1" class="m-merge__lead">{{ $t(state.key, state.params) }}</p>
      <p>{{ $t('git.push.lead', { branch: step.branch }) }}</p>
      <v-btn
        class="m-merge__push"
        color="primary"
        variant="flat"
        :aria-disabled="pushing ? 'true' : undefined"
        @click="push"
      >
        <v-progress-circular v-if="pushing" class="m-merge__spin" indeterminate size="14" width="2" />
        {{ pushing ? $t('git.push.running') : $t(step.push.label, step.push.params) }}
      </v-btn>
      <p v-if="pushing" class="m-merge__hidden" role="status">{{ $t('git.push.running') }}</p>
      <template v-if="pushFailure && git">
        <p>{{ $t('git.push.way_out') }}</p>
        <GitQuestion class="m-merge__git" :name="project" :view="git" :heading="heading" @answered="onAnswered" @reload="$emit('reload-git')" />
      </template>

      <template v-if="step.push.pushed">
        <p role="status">{{ $t(sentence.key, sentence.params) }}</p>
        <template v-if="step.link">
          <!-- A real link, not window.open: a browser blocks that after a request (R31). -->
          <a class="m-merge__link" :href="step.link.href" target="_blank" rel="noopener noreferrer">{{ $t('git.merge.open', step.link.params) }}</a>
          <p class="m-small">{{ $t('git.merge.lead') }}</p>
        </template>
        <p v-else-if="step.push.params.provider">{{ $t('git.merge.no_link', { branch: step.branch }) }}</p>
        <p>{{ $t('git.after') }}</p>
        <GitUpdateButton :name="project" :update="step.update" @scan-started="watchCheck" @finished="$emit('reload-git')" />
        <p class="m-small">{{ $t('git.update.check_self') }}</p>
        <a href="#/projects" class="m-merge__projects">{{ $t('git.manual.projects') }}</a>
        <p v-if="watching" class="m-merge__watch m-small" role="status">
          <v-progress-circular indeterminate size="14" width="2" color="primary" />
          {{ $t('git.update.checking') }}
        </p>
        <p v-else-if="checked && !checkFailure" class="m-small" role="status">{{ $t('git.update.checked') }}</p>
        <div v-if="checkFailure" class="m-merge__refusal" role="alert">
          <p>{{ checkFailure.error }}</p>
          <p v-if="checkFailure.hint" class="m-small">{{ checkFailure.hint }}</p>
        </div>
        <p v-if="lost" class="m-small" role="alert">{{ $t('projects.scan_lost') }}</p>
      </template>
    </template>
  </section>
</template>

<script>
import GitQuestion from './GitQuestion.vue'
import GitUpdateButton from './GitUpdateButton.vue'
import { api } from '../api.js'
import { afterPush, gitState, mergeAsks, pushSentence, refusalLines } from '../lib/gitView.js'
import { mergeStep } from '../lib/pathView.js'

// Between two looks at a running check; how many failed looks in a row are told.
const pollEvery = 3000
const maxLost = 3

// MergeStep is what is left to the person once the fix is on its branch. Not
// attached: the command to copy (R6). Attached: one click sends, a real link leads to
// the site, one click updates the folder and starts the check (R19, R29, R31). Michel
// never merges. FailureGuide reads the git view, FixPage the attempt: refresh asks it
// to read the attempt again, with final once the check is over.
export default {
  name: 'MergeStep',
  components: { GitQuestion, GitUpdateButton },
  props: {
    attempt: { type: Object, required: true },
    project: { type: String, required: true },
    // projectView is the element of GET /projects; git the GitView, null if it could not be read.
    projectView: { type: Object, default: null },
    git: { type: Object, default: null },
    heading: { type: String, default: 'h3' },
  },
  emits: ['git', 'reload-git', 'refresh'],
  data() {
    return { copied: false, copyFailed: false, asking: false, attaching: false, pushing: false, pushFailure: null, sent: null, outcome: '', watching: false, checked: false, checkFailure: null, lost: false, misses: 0, timer: null, gone: false }
  },
  computed: {
    step() {
      return mergeStep({ attempt: this.sent ? afterPush(this.attempt, this.sent) : this.attempt, project: this.projectView, git: this.git })
    },
    // The person believes it attached and it no longer is: they read why, and can change it.
    asks() {
      return mergeAsks(this.git, this.asking)
    },
    state() {
      const p = this.attempt.push || {}
      return gitState(this.git || { repo: 'ok', attached: true, provider: p.provider, display: p.display })
    },
    sentence() {
      return pushSentence(this.step, this.outcome)
    },
    scanning() {
      return !!this.projectView?.scanning
    },
  },
  watch: {
    // A check running when the page opens is followed too.
    scanning: {
      immediate: true,
      handler(now) {
        if (now) this.watchCheck()
      },
    },
    // The mode changes under the keyboard: what held the focus may be gone with it.
    'step.mode'() {
      this.$nextTick(() => {
        const el = document.activeElement
        if (!el || el === document.body) this.$refs.lead?.focus()
      })
    },
  },
  beforeUnmount() {
    this.gone = true
    clearTimeout(this.timer)
    this.timer = null
  },
  methods: {
    async copy() {
      this.copyFailed = false
      try {
        await navigator.clipboard.writeText(this.step.command)
        this.copied = true
      } catch {
        this.copied = false
        this.copyFailed = true
      }
    },
    onAttach() {
      this.asking = true
      this.attaching = true
      // The button goes with this click: the question takes the keyboard.
      this.$nextTick(() => document.querySelector('.m-merge__git .m-gitq__title')?.focus())
    },
    onAnswered(view) {
      // The sentence of the answer stays where the keyboard is, whatever it answered.
      this.asking = true
      this.attaching = false
      this.pushFailure = null
      this.$emit('git', view)
      this.$emit('refresh', { final: false })
    },
    async push() {
      if (this.pushing) return
      this.pushing = true
      this.pushFailure = null
      try {
        const res = await api.post(`/fix/${encodeURIComponent(this.attempt.id)}/push?lang=${encodeURIComponent(this.$ui.lang)}`)
        this.sent = res
        this.outcome = res?.outcome || ''
        this.$emit('refresh', { final: false })
      } catch (err) {
        if (err?.status === 401) return
        this.pushFailure = refusalLines(err)
        this.outcome = ''
        // Refused: what the page holds may be old (an address changed, a rule removed).
        this.$emit('reload-git')
      } finally {
        this.pushing = false
      }
    },
    /** watchCheck looks at the check until it ends: the path follows the attempt, read again at each look. */
    watchCheck() {
      this.checked = false
      this.checkFailure = null
      this.lost = false
      this.misses = 0
      this.watching = true
      this.next()
    },
    next() {
      clearTimeout(this.timer)
      this.timer = setTimeout(() => this.look(), pollEvery)
    },
    async look() {
      let view
      try {
        const list = (await api.get(`/projects?lang=${encodeURIComponent(this.$ui.lang)}`)) || []
        view = list.find((p) => p.name === this.project)
      } catch (err) {
        if (this.gone || err?.status === 401) return
        this.misses += 1
        this.lost = this.misses >= maxLost
        this.next()
        return
      }
      if (this.gone) return
      this.misses = 0
      this.lost = false
      if (view?.scanning) {
        this.$emit('refresh', { final: false })
        this.next()
        return
      }
      this.watching = false
      this.checkFailure = view?.last_failure ? { error: view.last_failure.error, hint: view.last_failure.hint } : null
      // The sentence about the folder waits until the attempt is read again: it speaks of that reading.
      const done = (ok) => {
        if (this.gone) return
        this.checked = ok
        this.lost = !ok
        // The Git view was read while the check ran and said "busy": read it again.
        this.$emit('reload-git')
      }
      this.$emit('refresh', { final: true, done })
    },
  },
}
</script>

<style scoped>
.m-merge { padding: 0.75rem 0.9rem; display: grid; gap: 0.6rem; line-height: 1.5; min-width: 0; }
.m-merge p { margin: 0; overflow-wrap: anywhere; }
.m-merge__lead { outline: none; }
.m-merge__cmd { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.m-merge__code {
  flex: 1 1 12rem;
  min-width: 0;
  padding: 0.4rem 0.6rem;
  border-radius: 6px;
  background: rgb(var(--v-theme-surface-variant));
  overflow-wrap: anywhere;
  user-select: all;
}
.m-merge__projects { justify-self: start; color: rgb(var(--v-theme-primary)); font-weight: 600; }
.m-merge__git { display: grid; gap: 0.5rem; padding-top: 0.6rem; border-top: 1px solid rgba(var(--v-theme-on-surface), 0.1); }
.m-merge__attach { justify-self: start; }
.m-merge__push { justify-self: start; max-width: 100%; height: auto; min-height: 36px; white-space: normal; padding-block: 0.35rem; }
.m-merge__push[aria-disabled='true'] { cursor: progress; }
.m-merge__spin { margin-right: 0.5rem; }
.m-merge__link {
  justify-self: start;
  max-width: 100%;
  padding: 0.45rem 0.9rem;
  border: 1px solid rgb(var(--v-theme-primary));
  border-radius: 6px;
  color: rgb(var(--v-theme-primary));
  font-weight: 600;
  overflow-wrap: anywhere;
}
.m-merge__link:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 2px; }
.m-merge__watch { display: flex; align-items: center; gap: 0.5rem; }
.m-merge__refusal { display: grid; gap: 0.25rem; padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-look)); overflow-wrap: anywhere; }
.m-merge__hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
</style>
