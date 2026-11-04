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

    <template v-if="merge.mode !== 'none'">
      <p v-if="gitLoading" class="m-small m-muted" role="status">{{ $t('fix.loading') }}</p>
      <MergeStep
        v-else
        :key="attempt.id"
        :attempt="attempt"
        :project="project"
        :project-view="projectView"
        :git="git"
        :heading="subHeading"
        @git="git = $event"
        @reload-git="loadGit"
        @refresh="$emit('refresh', $event)"
      />
    </template>

    <section v-if="hold" class="m-guide__hold m-panel" aria-labelledby="fix-hold-title">
      <component :is="subHeading" id="fix-hold-title" class="m-guide__sub" tabindex="-1">{{ $t('path.hold.title', { n: hold.count }) }}</component>
      <p>{{ $t('path.hold.stopped') }}</p>
      <p>{{ $t('path.hold.check') }}</p>
      <ul class="m-guide__keys">
        <li v-for="f in hold.files" :key="f.file">
          <span class="m-code m-guide__file"><MaskedText :text="f.file" /></span>
          <span class="m-small">{{ $t(f.linesKey, { lines: f.lines }) }}</span>
        </li>
      </ul>
      <p v-if="hold.more" class="m-small">{{ $t('path.hold.more', { n: hold.more, more: hold.more }) }}</p>
      <p class="m-guide__warn">{{ $t('path.hold.if_continue', { n: hold.count }) }}</p>
      <p>{{ $t('path.hold.how', { n: hold.count }) }}</p>
      <div class="m-guide__answers">
        <v-btn color="primary" variant="flat" :loading="holdBusy === 'withdraw'" :disabled="!!holdBusy" @click="$emit('hold-withdraw')">{{ $t('path.hold.withdraw') }}</v-btn>
        <v-btn
          v-if="hold.canContinue"
          color="warning"
          variant="outlined"
          :loading="holdBusy === 'continue'"
          :disabled="!!holdBusy || !canStart"
          @click="$emit('hold-continue', hold.hash)"
        >
          {{ $t('path.hold.continue') }}
        </v-btn>
      </div>
      <p v-if="!hold.canContinue" class="m-small">{{ $t('path.hold.gone') }}</p>
      <p v-else-if="holdBusy === 'continue'" class="m-voice m-guide__busy" role="status">{{ $t('path.hold.continuing') }}</p>
      <p v-else class="m-small m-muted">{{ $t('path.hold.once') }}</p>
    </section>

    <v-btn v-if="proposed && !card" class="m-guide__go" color="primary" variant="flat" block @click="$emit('to-proposal')">{{ $t('path.to_proposal') }}</v-btn>

    <div class="m-guide__two">
      <section v-if="!card && !fromProposal && !path.verified" class="m-guide__block m-panel" aria-labelledby="fix-means-title">
        <component :is="subHeading" id="fix-means-title" class="m-guide__sub">{{ $t('path.means') }}</component>
        <p class="m-guide__text">{{ risk }}</p>
      </section>
      <section v-if="plan && plan.lines.length" class="m-guide__block m-panel" :aria-labelledby="planTitleId">
        <component :is="subHeading" :id="planTitleId" class="m-guide__sub">{{ $t(plan.title) }}</component>
        <ul class="m-guide__lines">
          <li v-for="l in plan.lines" :key="l.key">
            {{ $t(l.key, l.params || {}) }}
            <a v-if="l.link" :href="l.link.href">{{ $t(l.link.key) }}</a>
          </li>
        </ul>
        <p v-if="plan.warn" class="m-guide__warn">{{ $t(plan.warn) }}</p>
        <template v-if="showStart">
          <v-btn color="primary" variant="flat" size="large" class="m-guide__start" :loading="starting" :disabled="starting || !canStart" @click="$emit('start')">
            {{ $t(server ? 'plan.server.prepare' : 'plan.project.start') }}
          </v-btn>
          <p v-if="!canStart && whyNot" class="m-small m-guide__warn">{{ whyNot }}</p>
          <p v-if="starting" class="m-voice m-guide__busy" role="status">{{ $t(server ? 'servers.line.preparing' : 'fix.chat.starting') }}</p>
        </template>
      </section>
    </div>
    <p v-if="laterWarn" class="m-guide__warn">{{ $t(laterWarn) }}</p>
  </section>
</template>

<script>
import FailurePath from './FailurePath.vue'
import { markGuideRead } from '../lib/guideView.js'
import { save } from '../lib/storage.js'
import MaskedText from './MaskedText.vue'
import MergeStep from './MergeStep.vue'
import { api } from '../api.js'
import { severityOf } from '../lib/digestView.js'
import { causeSentence } from '../lib/fixView.js'
import { readGit } from '../lib/gitView.js'
import { canPrepareServer, canRestart, exposurePath, failurePath, holdView, isGone, mergeStep, pathSteps, plainRisk, projectPlan, serverPlan, showsPlan } from '../lib/pathView.js'
import { guideServerTitle } from '../lib/serversView.js'
import { guideTitle } from '../lib/todoView.js'

// FailureGuide is the head of a flaw: where it stands, what it means, what will
// truly happen, and the one button. FixPage and ServerSheet own the requests:
// the button only asks for its start, so the AI consent and the warning of a fix
// of unknown outcome stay in front of it. On a server's card (card) the card
// holds the title and what the flaw means.
export default {
  name: 'FailureGuide',
  components: { FailurePath, MaskedText, MergeStep },
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
    // whyNot says, beside the disabled button, why it cannot start.
    whyNot: { type: String, default: '' },
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
    // preprodTarget: the preprod's TargetView, whose settings the first script follows.
    preprodTarget: { type: Object, default: null },
    // holdBusy: the answer to a held attempt running: withdraw, continue, or ''.
    holdBusy: { type: String, default: '' },
  },
  emits: ['start', 'to-proposal', 'hold-continue', 'hold-withdraw', 'refresh'],
  data() {
    // git is how the project stands with its Git service, read only for a fix on its branch.
    return { git: null, gitLoading: false }
  },
  computed: {
    // A flaw gone has nothing left to start, whether an attempt went nowhere or none ran.
    gone() {
      // On a server the attempt is read again and again, the server's sheet is not.
      if (this.server && this.attempt) return isGone(this.attempt.finding || this.finding, null)
      return isGone(this.finding, this.sheet)
    },
    hold() {
      return holdView(this.attempt, this.gone)
    },
    // exposure: a service open to all has no fix, so neither « Corrigée » nor « Vérifiée » (R47).
    exposure() {
      return !this.attempt && (this.sheet?.kind || this.finding.kind) === 'server_exposure'
    },
    path() {
      if (this.exposure) return exposurePath({ gone: this.gone, decided: (this.sheet?.status || this.finding.status) === 'decided' })
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
      if (this.server) return serverPlan({ finding: this.sheet || this.finding, target: this.target, attempt: this.attempt, tried: this.tried, preprodHealth: this.preprodHealth, preprodTarget: this.preprodTarget })
      return projectPlan({ finding: this.sheet || this.finding, project: this.projectView, attempt: this.attempt })
    },
    steps() {
      // « À toi d'agir » is the person's step: it stays lit, though Michel prepares nothing.
      return this.exposure ? this.path.steps : pathSteps(this.path, this.plan, this.attempt)
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
      return mergeStep({ attempt: this.attempt, project: this.projectView, git: this.git })
    },
    // gitFor is the project to read: a server's fix and a fix without a branch have nothing to send.
    gitFor() {
      return this.server || this.attempt?.state !== 'applied' || !this.attempt.branch ? '' : this.project
    },
    proposed() {
      return this.attempt?.state === 'proposed'
    },
  },
  mounted() {
    markGuideRead(this.$ui.guide, save)
  },
  watch: {
    gitFor: {
      immediate: true,
      handler(name) {
        this.git = null
        this.gitLoading = !!name
        if (name) this.loadGit()
      },
    },
    '$ui.lang'() {
      if (this.gitFor) this.loadGit()
    },
  },
  beforeUnmount() {
    this.gitAsked = ''
  },
  methods: {
    /** loadGit reads the view; a late answer, for another project or a page gone, is dropped. */
    async loadGit() {
      const name = this.gitFor
      if (!name) return
      this.gitAsked = name
      let view = null
      try {
        view = await readGit(api.get, name, this.$ui.lang)
      } catch {
        // The attempt still says whether it is attached: the step does not wait for this.
      }
      if (this.gitAsked !== name || this.gitFor !== name) return
      this.git = view
      this.gitLoading = false
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
.m-guide__hold { padding: 0.75rem 0.9rem; display: grid; gap: 0.6rem; line-height: 1.5; min-width: 0; }
.m-guide__keys { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.3rem; }
.m-guide__keys li { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.1rem 0.6rem; min-width: 0; }
.m-guide__file { min-width: 0; overflow-wrap: anywhere; }
.m-guide__answers { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.m-guide__answers :deep(.v-btn) { max-width: 100%; }
.m-guide__go { display: none; }
@media (max-width: 900px) {
  .m-guide__go { display: inline-flex; }
}
</style>
