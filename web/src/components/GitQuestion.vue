<template>
  <div class="m-gitq">
    <div v-if="view.refusal" class="m-gitq__refusal" role="alert">
      <p>{{ view.refusal.error }}</p>
      <p v-if="view.refusal.hint" class="m-small">{{ view.refusal.hint }}</p>
    </div>

    <p v-if="showsState" ref="state" class="m-gitq__state" :class="{ 'm-gitq__state--stop': view.changed }" tabindex="-1" role="status">{{ $t(state.key, state.params) }}</p>
    <p v-if="view.repo === 'none'" class="m-small">{{ $t('git.none_how') }}</p>
    <v-btn v-if="canChange && !open" ref="change" class="m-gitq__change" size="small" variant="tonal" color="primary" @click="openQuestion">
      {{ $t(view.answer ? 'git.change' : 'git.answer_now') }}
    </v-btn>

    <section v-if="open" class="m-gitq__ask" :aria-labelledby="titleId">
      <div class="m-gitq__head">
        <component :is="heading" :id="titleId" ref="title" class="m-gitq__title" tabindex="-1">{{ $t('git.question') }}</component>
        <FieldHelp id="project.git" :field="$t('git.question')" />
      </div>
      <p>{{ $t('git.why') }}</p>
      <p v-if="question.sentence.key !== state.key">{{ $t(question.sentence.key, question.sentence.params) }}</p>
      <p v-if="question.credential" class="m-gitq__warn">{{ $t('git.credential') }}</p>

      <!-- Three buttons of the same weight: the suggestion above is only a sentence. -->
      <div v-if="!confirming" class="m-gitq__answers" role="group" :aria-labelledby="titleId">
        <v-btn
          v-for="o in question.options"
          :key="o"
          :ref="(el) => setOption(o, el)"
          variant="outlined"
          color="primary"
          :aria-disabled="busy ? 'true' : undefined"
          @click="answer(o)"
        >
          {{ $t(`git.answer.${o}`) }}
        </v-btn>
        <v-btn v-if="changing" ref="cancel" variant="text" :aria-disabled="busy ? 'true' : undefined" @click="closeQuestion">{{ $t('common.cancel') }}</v-btn>
      </div>
      <div v-else class="m-gitq__confirm">
        <p>{{ $t('git.yes_detail', { host: view.host }) }}</p>
        <div class="m-gitq__answers">
          <v-btn ref="confirm" variant="flat" color="primary" :aria-disabled="busy ? 'true' : undefined" @click="send('yes')">{{ $t('git.confirm') }}</v-btn>
          <v-btn variant="text" :aria-disabled="busy ? 'true' : undefined" @click="backFromYes">{{ $t('git.back') }}</v-btn>
        </div>
      </div>

      <p v-if="busy" class="m-gitq__busy m-small" role="status">
        <v-progress-circular indeterminate size="14" width="2" color="primary" />
        {{ $t('git.answering') }}
      </p>
    </section>

    <div v-if="failure" class="m-gitq__refusal" role="alert">
      <template v-if="failure.key"><p>{{ $t(failure.key) }}</p></template>
      <template v-else>
        <p>{{ failure.error }}</p>
        <p v-if="failure.hint" class="m-small">{{ failure.hint }}</p>
      </template>
    </div>
  </div>
</template>

<script>
import FieldHelp from './FieldHelp.vue'
import { api } from '../api.js'
import { canChangeAnswer, gitQuestion, gitState, questionOpen, refusalLines, showsGitState } from '../lib/gitView.js'

let seq = 0

// GitQuestion is the question "is this project on a Git service?", and then the
// sentence that says how the project stands, with "Changer ma réponse". Nothing is
// preselected, a yes names the host before it counts. The parent owns the view:
// answered brings the new one, reload asks to read it again. Buttons wear
// aria-disabled and not disabled while a request runs, so the keyboard stays on them.
export default {
  name: 'GitQuestion',
  components: { FieldHelp },
  props: {
    name: { type: String, required: true },
    // view is the GitView, or refusedView() of a refused look.
    view: { type: Object, required: true },
    heading: { type: String, default: 'h3' },
    // startOpen: the person came by "Rattacher ce projet", so the question opens at once, whatever was answered. Read at creation.
    startOpen: { type: Boolean, default: false },
  },
  emits: ['answered', 'reload'],
  data() {
    seq += 1
    return { titleId: `git-question-${seq}`, changing: this.startOpen, confirming: false, busy: '', failure: null, options: {} }
  },
  computed: {
    question() {
      return gitQuestion(this.view)
    },
    state() {
      return gitState(this.view)
    },
    open() {
      return questionOpen(this.view, this.changing)
    },
    showsState() {
      return showsGitState(this.view)
    },
    canChange() {
      return canChangeAnswer(this.view)
    },
  },
  methods: {
    setOption(o, el) {
      this.options[o] = el
    },
    /** focus puts the keyboard on the first of the elements still on the page. */
    focus(...targets) {
      this.$nextTick(() => {
        for (const t of targets) {
          const el = t?.$el || t
          if (el?.isConnected) {
            el.focus()
            return
          }
        }
      })
    },
    openQuestion() {
      this.changing = true
      this.failure = null
      this.$nextTick(() => this.focus(this.$refs.title))
    },
    closeQuestion() {
      if (this.busy) return
      this.changing = false
      this.confirming = false
      this.failure = null
      this.$nextTick(() => this.focus(this.$refs.change, this.$refs.state))
    },
    answer(o) {
      if (this.busy) return
      if (o !== 'yes') {
        this.send(o)
        return
      }
      // The yes says what it allows before it counts.
      this.confirming = true
      this.failure = null
      this.$nextTick(() => this.focus(this.$refs.confirm))
    },
    backFromYes() {
      if (this.busy) return
      this.confirming = false
      this.$nextTick(() => this.focus(this.options.yes, this.$refs.title))
    },
    async send(answer) {
      if (this.busy) return
      this.busy = answer
      this.failure = null
      const body = answer === 'yes' ? { answer, remote_id: this.view.remote_id } : { answer }
      try {
        const v = await api.post(`/projects/${encodeURIComponent(this.name)}/git/answer?lang=${encodeURIComponent(this.$ui.lang)}`, body)
        this.changing = false
        this.confirming = false
        this.$emit('answered', v)
        // Saved, though the folder cannot be read: the refusal says why.
        if (v?.repo === 'unreadable') this.$emit('reload')
        this.$nextTick(() => this.focus(this.$refs.state, this.$refs.change))
      } catch (err) {
        if (err?.status === 401) return
        this.failure = refusalLines(err)
        // Refused: what was shown may be old (an address changed).
        this.confirming = false
        this.$emit('reload')
        this.$nextTick(() => this.focus(this.$refs.title, this.$refs.change))
      } finally {
        this.busy = ''
      }
    },
  },
}
</script>

<style scoped>
.m-gitq { display: grid; gap: 0.6rem; line-height: 1.5; min-width: 0; }
.m-gitq p { margin: 0; overflow-wrap: anywhere; }
.m-gitq__ask, .m-gitq__confirm { display: grid; gap: 0.6rem; min-width: 0; }
.m-gitq__head { display: flex; flex-wrap: wrap; align-items: flex-start; gap: 0.25rem 0.5rem; }
.m-gitq__title { font-size: 1rem; font-weight: 650; line-height: 1.35; margin: 0; outline: none; flex: 1 1 12rem; min-width: 0; }
.m-gitq__state { outline: none; }
.m-gitq__state--stop, .m-gitq__warn { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-look)); }
.m-gitq__refusal { display: grid; gap: 0.25rem; padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-look)); overflow-wrap: anywhere; }
.m-gitq__answers { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.m-gitq__answers :deep(.v-btn) { max-width: 100%; height: auto; min-height: 36px; white-space: normal; padding-block: 0.35rem; }
.m-gitq__answers :deep(.v-btn[aria-disabled='true']) { cursor: progress; }
.m-gitq__change { justify-self: start; }
.m-gitq__busy { display: flex; align-items: center; gap: 0.5rem; }
</style>
