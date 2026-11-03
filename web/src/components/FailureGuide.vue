<template>
  <section class="m-guide" :aria-label="card ? $t('path.label') : undefined" :aria-labelledby="card ? undefined : 'fix-guide-title'">
    <template v-if="!card">
      <component :is="nested ? 'h2' : 'h1'" id="fix-guide-title" class="m-guide__title" tabindex="-1">
        {{ title }}
      </component>
      <p class="m-small m-muted m-guide__where">
        <span v-if="serverName">{{ $t('srvfix.flaw_on', { name: serverName }) }}</span>
        <span v-else-if="project">{{ $t('fix.in_project', { project }) }}</span>
        <span class="m-sev" :class="`m-sev--${severity}`">{{ $t(`severity.${severity}`) }}</span>
      </p>
    </template>

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

    <v-btn v-if="proposed && !card" class="m-guide__go" color="primary" variant="flat" block @click="$emit('to-proposal')">{{ $t('path.to_proposal') }}</v-btn>

    <div class="m-guide__two">
      <section v-if="!card && !fromProposal" class="m-guide__block m-panel" aria-labelledby="fix-means-title">
        <component :is="subHeading" id="fix-means-title" class="m-guide__sub">{{ $t('path.means') }}</component>
        <p class="m-guide__text">{{ risk }}</p>
      </section>
      <section v-if="plan && plan.lines.length" class="m-guide__block m-panel" :aria-labelledby="planTitleId">
        <component :is="subHeading" :id="planTitleId" class="m-guide__sub">{{ $t(plan.title) }}</component>
        <ul class="m-guide__lines">
          <li v-for="l in plan.lines" :key="l.key">{{ $t(l.key, l.params || {}) }}</li>
        </ul>
        <p v-if="plan.warn" class="m-guide__warn">{{ $t(plan.warn) }}</p>
        <template v-if="showStart">
          <v-btn color="primary" variant="flat" size="large" class="m-guide__start" :loading="starting" :disabled="starting || !canStart" @click="$emit('start')">
            {{ $t(server ? 'plan.server.prepare' : 'plan.project.start') }}
          </v-btn>
          <p v-if="starting" class="m-voice m-guide__busy" role="status">{{ $t(server ? 'servers.line.preparing' : 'fix.chat.starting') }}</p>
        </template>
      </section>
    </div>
    <p v-if="laterWarn" class="m-guide__warn">{{ $t(laterWarn) }}</p>
  </section>
</template>

<script>
import FailurePath from './FailurePath.vue'
import MaskedText from './MaskedText.vue'
import { severityOf } from '../lib/digestView.js'
import { causeSentence } from '../lib/fixView.js'
import { canPrepareServer, canRestart, failurePath, isGone, mergeStep, pathSteps, plainRisk, projectPlan, serverPlan, showsPlan } from '../lib/pathView.js'
import { guideServerTitle } from '../lib/serversView.js'
import { guideTitle } from '../lib/todoView.js'

// FailureGuide is the head of a flaw: where it stands, what it means, what will
// truly happen, and the one button. FixPage and ServerSheet own the requests:
// the button only asks for its start, so the AI consent and the warning of a fix
// of unknown outcome stay in front of it. On a server's card (card) the card
// holds the title and what the flaw means.
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
    // server: a server's flaw. sheet is then the TargetFindingView, target the
    // TargetView (null while it comes): the plan and the path read their settings.
    server: { type: Boolean, default: false },
    target: { type: Object, default: null },
    card: { type: Boolean, default: false },
    // tried: an attempt on the preprod was made for this flaw. preprodHealth: the
    // preprod holds health data. The sheet knows both; serverPlan reads them.
    tried: { type: Boolean, default: false },
    preprodHealth: { type: Boolean, default: false },
  },
  emits: ['start', 'to-proposal'],
  data() {
    return { copied: false, copyFailed: false }
  },
  computed: {
    // A flaw gone has nothing left to start, whether an attempt went nowhere or none ran.
    gone() {
      // On a server the attempt is read again and again, the server's sheet is not.
      if (this.server && this.attempt) return isGone(this.attempt.finding || this.finding, null)
      return isGone(this.finding, this.sheet)
    },
    path() {
      return failurePath({ attempt: this.attempt, vanished: this.gone, target: this.target })
    },
    // nested: the page already has its h1 (the advanced mode).
    nested() {
      return this.$ui.advanced
    },
    // subHeading follows the title: an h1 alone on the page, an h2 under the page's h1 otherwise.
    subHeading() {
      if (this.card) return 'h4'
      return this.nested ? 'h3' : 'h2'
    },
    planTitleId() {
      return this.card ? `fix-plan-title-${this.finding.id}` : 'fix-plan-title'
    },
    serverName() {
      return this.server ? this.attempt?.server?.target?.name || this.target?.name || '' : ''
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
      if (!this.server) return guideTitle(this.finding, this.sheet, this.$ui.lang)
      return guideServerTitle(this.finding, this.sheet, this.attempt, this.$ui.lang)
    },
    // fromProposal: the flaw left the server's sheet (it is verified), so all that is
    // known of it is the proposal, in the title, and Go's English, which is not shown.
    fromProposal() {
      return this.server && !this.sheet
    },
    risk() {
      return plainRisk(this.finding, this.sheet, this.$ui.lang, this.$ui.advanced)
    },
    plan() {
      if (!showsPlan(this.attempt, this.gone)) return null
      if (this.server) return serverPlan({ finding: this.sheet || this.finding, target: this.target, attempt: this.attempt, tried: this.tried, preprodHealth: this.preprodHealth })
      return projectPlan({ finding: this.sheet || this.finding, project: this.projectView, attempt: this.attempt })
    },
    steps() {
      return pathSteps(this.path, this.plan, this.attempt)
    },
    showStart() {
      if (this.server) return this.plan?.action === 'prepare' && canPrepareServer(this.attempt, this.gone)
      return this.plan?.action === 'start' && canRestart(this.attempt, this.gone)
    },
    // laterWarn: a proposal at level 3 may still leave alone: the plan has gone, its warning stays.
    laterWarn() {
      return this.server && !this.plan && this.attempt?.state === 'proposed' && this.target?.fix_level === 3 ? 'servers.level.3.warn' : ''
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
.m-guide__title { font-family: var(--m-voice); font-size: 1.5rem; font-weight: 600; line-height: 1.25; margin: 0; overflow-wrap: anywhere; outline: none; }
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
.m-guide__warn { line-height: 1.45; padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-look)); }
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
