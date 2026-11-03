<template>
  <section class="m-guide" aria-labelledby="fix-guide-title">
    <component :is="$ui.advanced ? 'h2' : 'h1'" id="fix-guide-title" class="m-guide__title">
      {{ title }}
    </component>
    <p class="m-small m-muted m-guide__where">
      <span v-if="project">{{ $t('fix.in_project', { project }) }}</span>
      <span class="m-sev" :class="`m-sev--${severity}`">{{ $t(`severity.${severity}`) }}</span>
    </p>

    <FailurePath :steps="steps" />

    <p v-if="path.note" class="m-guide__note" :class="{ 'm-guide__note--stop': stopped }" role="status">
      <MaskedText v-if="path.note.cause" :text="causeText" />
      <template v-else>{{ $t(`path.note.${path.note.key}`, path.note.params || {}) }}</template>
    </p>

    <section v-if="merge.mode === 'manual'" class="m-guide__merge m-panel" aria-labelledby="fix-merge-lead">
      <p id="fix-merge-lead">{{ $t('git.manual.lead') }}</p>
      <div class="m-guide__cmd">
        <code class="m-code m-guide__code">{{ merge.command }}</code>
        <v-btn size="small" variant="tonal" color="primary" @click="copy">{{ copied ? $t('git.manual.copied') : $t('git.manual.copy') }}</v-btn>
      </div>
      <p v-if="copyFailed" class="m-small" role="alert">{{ $t('git.manual.copy_failed') }}</p>
      <p v-if="copied" class="m-guide__hidden" role="status">{{ $t('git.manual.copied') }}</p>
      <p>{{ $t('git.manual.next') }}</p>
      <a href="#/projects" class="m-guide__link">{{ $t('git.manual.projects') }}</a>
    </section>

    <v-btn v-if="proposed" class="m-guide__go" color="primary" variant="flat" block @click="$emit('to-proposal')">{{ $t('path.to_proposal') }}</v-btn>

    <div class="m-guide__two">
      <section class="m-guide__block m-panel" aria-labelledby="fix-means-title">
        <h3 id="fix-means-title" class="m-guide__sub">{{ $t('path.means') }}</h3>
        <p class="m-guide__text">{{ risk }}</p>
      </section>
      <section v-if="plan && plan.lines.length" class="m-guide__block m-panel" aria-labelledby="fix-plan-title">
        <h3 id="fix-plan-title" class="m-guide__sub">{{ $t(plan.title) }}</h3>
        <ul class="m-guide__lines">
          <li v-for="l in plan.lines" :key="l.key">{{ $t(l.key, l.params || {}) }}</li>
        </ul>
        <template v-if="showStart">
          <v-btn color="primary" variant="flat" size="large" class="m-guide__start" :loading="starting" :disabled="starting || !canStart" @click="$emit('start')">
            {{ $t('plan.project.start') }}
          </v-btn>
          <p v-if="starting" class="m-voice m-guide__busy" role="status">{{ $t('fix.chat.starting') }}</p>
        </template>
      </section>
    </div>
  </section>
</template>

<script>
import FailurePath from './FailurePath.vue'
import MaskedText from './MaskedText.vue'
import { severityOf } from '../lib/digestView.js'
import { causeSentence } from '../lib/fixView.js'
import { canRestart, failurePath, mergeStep, pathSteps, plainRisk, projectPlan, showsPlan } from '../lib/pathView.js'

// FailureGuide is the head of a project's flaw: where it stands, what it means,
// what will truly happen, and the one button. FixPage owns the requests: the
// button only asks for its start, so the AI consent stays in front of it.
export default {
  name: 'FailureGuide',
  components: { FailurePath, MaskedText },
  props: {
    // attempt is the AttemptView shown, null for a flaw without a fix.
    attempt: { type: Object, default: null },
    // finding is the attempt's finding, or the open finding chosen.
    finding: { type: Object, default: () => ({}) },
    // sheet is GET /findings/{id}, null while it comes.
    sheet: { type: Object, default: null },
    // projectView is the element of GET /projects, null while it comes.
    projectView: { type: Object, default: null },
    canStart: { type: Boolean, default: true },
    starting: { type: Boolean, default: false },
  },
  emits: ['start', 'to-proposal'],
  data() {
    return { copied: false, copyFailed: false }
  },
  computed: {
    // A flaw gone without a fix of Michel's has nothing left to start.
    vanished() {
      return !this.attempt && (this.sheet?.status || this.finding.status) === 'gone'
    },
    path() {
      return failurePath({ attempt: this.attempt, vanished: this.vanished })
    },
    stopped() {
      return this.path.steps.some((s) => s.state === 'stopped')
    },
    causeText() {
      return causeSentence(this.path.note?.cause)
    },
    project() {
      return this.attempt?.project || this.sheet?.project || this.finding.project || ''
    },
    severity() {
      return severityOf(this.sheet?.severity || this.finding.severity)
    },
    title() {
      return this.$t('todo.flaw', { package: this.finding.package || this.sheet?.package || '' })
    },
    risk() {
      return plainRisk(this.finding, this.sheet, this.$ui.lang, this.$ui.advanced)
    },
    plan() {
      if (!showsPlan(this.attempt) || this.vanished) return null
      return projectPlan({ finding: this.sheet || this.finding, project: this.projectView, attempt: this.attempt })
    },
    steps() {
      return pathSteps(this.path, this.plan, this.attempt)
    },
    showStart() {
      return this.plan?.action === 'start' && canRestart(this.attempt)
    },
    merge() {
      return mergeStep({ attempt: this.attempt, project: this.projectView })
    },
    proposed() {
      return this.attempt?.state === 'proposed'
    },
  },
  watch: {
    'attempt.id'() {
      this.copied = false
      this.copyFailed = false
    },
  },
  methods: {
    async copy() {
      this.copyFailed = false
      try {
        await navigator.clipboard.writeText(this.merge.command)
        this.copied = true
      } catch {
        this.copied = false
        this.copyFailed = true
      }
    },
  },
}
</script>

<style scoped>
.m-guide { display: grid; gap: 0.85rem; min-width: 0; }
.m-guide p { margin: 0; }
.m-guide__title { font-family: var(--m-voice); font-size: 1.5rem; font-weight: 600; line-height: 1.25; margin: 0; overflow-wrap: anywhere; }
.m-guide__where { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem 0.75rem; margin-top: -0.5rem !important; }
.m-guide__note { line-height: 1.5; padding: 0.5rem 0.75rem; border-radius: 8px; background: rgb(var(--v-theme-tag-info)); overflow-wrap: anywhere; }
.m-guide__note--stop { background: rgb(var(--v-theme-tag-look)); }
.m-guide__two { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 15rem), 1fr)); gap: 0.85rem; }
.m-guide__block { padding: 0.75rem 0.9rem; display: grid; gap: 0.5rem; align-content: start; min-width: 0; }
.m-guide__sub { font-size: 0.95rem; font-weight: 650; margin: 0; }
.m-guide__text { line-height: 1.5; }
.m-guide__lines { margin: 0; padding-left: 1.1rem; display: grid; gap: 0.4rem; line-height: 1.45; }
.m-guide__start { justify-self: start; margin-top: 0.25rem; max-width: 100%; }
.m-guide__busy { line-height: 1.45; }
.m-guide__merge { padding: 0.75rem 0.9rem; display: grid; gap: 0.6rem; line-height: 1.5; }
.m-guide__cmd { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.m-guide__code {
  flex: 1 1 12rem;
  min-width: 0;
  padding: 0.4rem 0.6rem;
  border-radius: 6px;
  background: rgb(var(--v-theme-surface-variant));
  overflow-wrap: anywhere;
  user-select: all;
}
.m-guide__link { justify-self: start; color: rgb(var(--v-theme-primary)); font-weight: 600; }
.m-guide__hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
.m-guide__go { display: none; }
@media (max-width: 900px) {
  .m-guide__go { display: inline-flex; }
}
</style>
