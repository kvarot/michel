<template>
  <section class="m-panel m-steps" aria-labelledby="guide-title">
    <h2 id="guide-title" ref="title" class="m-steps__title" tabindex="-1">{{ $t('guide.title') }}</h2>
    <p class="m-small m-muted m-steps__intro">{{ $t('guide.intro') }}</p>

    <ol class="m-steps__list">
      <li v-for="(s, i) in steps" :key="s.key" class="m-steps__row" :class="{ 'm-steps__row--now': s.current }" :aria-current="s.current ? 'step' : undefined">
        <span class="m-steps__num" :class="{ 'm-steps__num--done': s.done, 'm-steps__num--now': s.current }" aria-hidden="true">
          <svg v-if="s.done" viewBox="0 0 24 24" width="16" height="16"><path d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z" fill="currentColor" /></svg>
          <template v-else>{{ i + 1 }}</template>
        </span>
        <div class="m-steps__body">
          <p class="m-steps__line">
            <span class="m-steps__name">{{ $t(`guide.${s.key}.title`) }}</span>
            <span class="m-small m-steps__word" :class="s.done ? 'm-tag--done' : s.current ? 'm-tag--info' : 'm-muted'">{{ $t(`guide.state.${stateOf(s)}`) }}</span>
          </p>
          <p v-if="!s.done" class="m-small m-steps__text">{{ $t(s.text) }}</p>
          <v-btn v-if="s.action" class="m-steps__action" color="primary" variant="flat" :href="s.action.href">{{ $t(s.action.label) }}</v-btn>

          <!-- The Git question belongs to step one, and holds up no step. -->
          <div v-if="s.key === 'add' && git" class="m-steps__git">
            <p class="m-small m-steps__git-for">{{ $t('guide.git.for', { name: git.name }) }}</p>
            <template v-if="git.mode === 'no_repo'">
              <p class="m-small">{{ $t('git.none') }}</p>
              <p class="m-small">{{ $t('git.none_how') }}</p>
            </template>
            <p v-else-if="gitFailure" class="m-small" role="alert">{{ gitFailure.key ? $t(gitFailure.key) : gitFailure.error }}</p>
            <p v-else-if="!gitView" class="m-small m-muted" role="status">{{ $t('app.loading') }}</p>
            <GitQuestion v-else :key="git.name" :name="git.name" :view="gitView" @answered="gitView = $event" @reload="loadGit" />
          </div>
        </div>
      </li>
    </ol>

    <v-btn class="m-steps__skip" variant="text" size="small" @click="$emit('dismiss')">{{ $t(allDone ? 'guide.close' : 'guide.dismiss') }}</v-btn>
  </section>
</template>

<script>
import GitQuestion from './GitQuestion.vue'
import { api } from '../api.js'
import { readGit, refusalLines } from '../lib/gitView.js'

// FirstSteps is the guide at the head of the To-do page: three numbered lines,
// their state in words, one action for the step at hand. It covers nothing. What
// it says comes from guideSteps, and the answer to the Git question from git_answer.
export default {
  name: 'FirstSteps',
  components: { GitQuestion },
  props: {
    steps: { type: Array, required: true },
    // git is guideGitQuestion: the project to ask about, or null.
    git: { type: Object, default: null },
  },
  emits: ['dismiss'],
  data() {
    return { gitView: null, gitFailure: null }
  },
  computed: {
    allDone() {
      return this.steps.every((s) => s.done)
    },
    asked() {
      return this.git?.mode === 'ask' ? this.git.name : ''
    },
  },
  watch: {
    asked: { immediate: true, handler: 'loadGit' },
    '$ui.lang'() {
      this.loadGit()
    },
  },
  methods: {
    stateOf(s) {
      if (s.done) return 'done'
      return s.current ? 'current' : 'next'
    },
    async loadGit() {
      const name = this.asked
      this.gitView = null
      this.gitFailure = null
      if (!name) return
      try {
        const view = await readGit(api.get, name, this.$ui.lang)
        if (name === this.asked) this.gitView = view
      } catch (err) {
        if (err?.status !== 401 && name === this.asked) this.gitFailure = refusalLines(err)
      }
    },
    /** focus brings the keyboard to the guide when it was asked for. */
    focus() {
      this.$refs.title?.focus({ preventScroll: false })
    },
  },
}
</script>

<style scoped>
.m-steps { padding: 1rem 0.9rem 0.6rem; margin-bottom: 1.25rem; }
.m-steps p { margin: 0; }
.m-steps__title { font-size: 1.05rem; font-weight: 650; margin: 0; outline: none; }
.m-steps__intro { margin-top: 0.2rem !important; }
.m-steps__list { list-style: none; margin: 0.75rem 0 0; padding: 0; }
.m-steps__row { display: flex; gap: 0.75rem; padding: 0.75rem 0; }
.m-steps__row + .m-steps__row { border-top: 1px solid var(--m-line); }
.m-steps__num {
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.75rem;
  height: 1.75rem;
  border-radius: 50%;
  font-size: 0.9rem;
  font-weight: 650;
  border: 1px solid var(--m-line);
}
.m-steps__num--now { border-color: transparent; background: rgb(var(--v-theme-primary)); color: rgb(var(--v-theme-on-primary)); }
.m-steps__num--done { border-color: transparent; background: rgb(var(--v-theme-tag-done)); color: rgb(var(--v-theme-success)); }
.m-steps__body { flex: 1 1 auto; min-width: 0; display: grid; gap: 0.35rem; justify-items: start; }
.m-steps__line { display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem 0.6rem; min-height: 1.75rem; }
.m-steps__name { font-weight: 600; line-height: 1.35; }
.m-steps__word { flex: none; }
.m-steps__text { line-height: 1.5; }
.m-steps__action { margin-top: 0.25rem; }
.m-steps__git { width: 100%; display: grid; gap: 0.5rem; margin-top: 0.5rem; padding-top: 0.6rem; border-top: 1px dashed var(--m-line); }
.m-steps__git-for { font-weight: 600; overflow-wrap: anywhere; }
.m-steps__skip { margin-left: -0.5rem; }

/* On a phone the button of the step takes the whole width. */
@media (max-width: 599px) {
  .m-steps__action { width: 100%; }
}
</style>
