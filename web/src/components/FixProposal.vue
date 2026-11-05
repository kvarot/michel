<template>
  <aside class="m-prop">
    <section class="m-prop__block" aria-labelledby="fix-flaw-title">
      <h2 id="fix-flaw-title" class="m-prop__title">{{ $t('fix.flaw.title') }}</h2>
      <p v-if="sheetLoading" class="m-muted m-small" role="status">{{ $t('fix.flaw.loading') }}</p>
      <template v-else>
        <p class="m-prop__id">
          <span class="m-code">{{ finding.package }}</span>
          <span v-if="$ui.advanced && finding.osv_id" class="m-code m-muted">{{ finding.osv_id }}</span>
          <span class="m-sev" :class="`m-sev--${severity}`">{{ $t(`severity.${severity}`) }}</span>
        </p>
        <p v-if="project" class="m-muted m-small m-prop__project">{{ $t('fix.in_project', { project }) }}</p>
        <div v-if="sentences.length" class="m-prop__sentences">
          <section v-for="s in sentences" :key="s.key">
            <h3 class="m-prop__label">{{ $t(s.label) }}</h3>
            <p class="m-voice m-prop__sentence">{{ $ui.advanced ? s.text : strip(s.text) }}</p>
          </section>
        </div>
        <p v-else-if="finding.summary" class="m-small">{{ finding.summary }}</p>
      </template>
    </section>

    <section v-if="attempt" class="m-prop__block" aria-labelledby="fix-proposal-title">
      <h2 id="fix-proposal-title" class="m-prop__title">{{ $t('fix.proposal.title') }}</h2>

      <template v-if="p">
        <p v-if="updated" class="m-prop__note m-small" role="status">{{ $t('fix.proposal.updated') }}</p>
        <p class="m-voice m-prop__sentence m-prop__main">{{ sentence }}</p>
        <div v-if="p.summary" class="m-prop__agent">
          <h3 class="m-prop__label">{{ $t('fix.proposal.agent_says') }}</h3>
          <p class="m-prop__summary"><MaskedText :text="p.summary" /></p>
        </div>
        <p class="m-small">{{ $t(rescanText) }}</p>
        <p v-if="testsKey === 'not_run'" class="m-prop__warn m-small">{{ $t('fix.proposal.tests_not_run_hint') }}</p>
        <p v-else-if="testsKey === 'failed'" class="m-prop__warn m-small">{{ $t('fix.proposal.tests_failed_hint') }}</p>
        <div v-else-if="testsKey === 'awaiting'" class="m-prop__warn m-small m-prop__await">
          <p>{{ $t('fix.proposal.tests_awaiting_hint') }}</p>
          <template v-if="codeFiles.shown.length">
            <p>{{ $t('fix.proposal.code_files') }}</p>
            <ul class="m-prop__files">
              <li v-for="f in codeFiles.shown" :key="f" class="m-code">{{ f }}</li>
            </ul>
            <p v-if="codeFiles.more">{{ $t('fix.proposal.code_files_more', { n: codeFiles.more }) }}</p>
          </template>
          <p v-else>{{ $t('fix.proposal.code_files_deps') }}</p>
          <v-btn variant="text" size="small" class="m-prop__see" @click="openChange">{{ $t('fix.proposal.read_change') }}</v-btn>
        </div>
        <p v-if="p.risk > 0" class="m-muted m-small">{{ $t('fix.proposal.risk', { risk: p.risk }) }}</p>

        <template v-if="approvable">
          <div class="m-prop__actions">
            <v-btn
              v-if="testsRunnable"
              color="primary"
              variant="outlined"
              :loading="runningTests"
              :disabled="busy"
              @click="$emit('run-tests', p.hash)"
            >
              {{ $t('fix.proposal.run_tests') }}
            </v-btn>
            <v-btn color="primary" variant="flat" :loading="approving" :disabled="busy" @click="$emit('approve')">
              {{ $t('fix.proposal.approve') }}
            </v-btn>
            <v-btn variant="outlined" :loading="refusing" :disabled="busy" @click="refuseOpen = true">
              {{ $t('fix.proposal.refuse') }}
            </v-btn>
          </div>
          <FieldHelp named id="fix.approve" :field="$t('fix.proposal.approve')" />
          <FieldHelp named id="fix.refuse" :field="$t('fix.proposal.refuse')" />
          <p v-if="approving" class="m-voice m-prop__busy" role="status">
            <v-progress-circular indeterminate size="16" width="2" color="primary" />
            {{ $t('fix.proposal.approving') }}
          </p>
          <p v-else-if="runningTests" class="m-voice m-prop__busy" role="status">
            <v-progress-circular indeterminate size="16" width="2" color="primary" />
            {{ $t('fix.proposal.running_tests') }}
          </p>
          <template v-else>
            <p v-if="testsKey === 'awaiting'" class="m-muted m-small">{{ $t('fix.proposal.approve_untested') }}</p>
            <p class="m-muted m-small">{{ $t('fix.proposal.approve_hint') }}</p>
          </template>
        </template>

        <v-btn v-if="!$ui.advanced && !showChange" variant="text" size="small" class="m-prop__see" @click="showChange = true">
          {{ $t('fix.proposal.see_change') }}
        </v-btn>
        <details v-if="$ui.advanced || showChange" ref="detail" class="m-prop__detail" :open="showChange || undefined">
          <summary>{{ $t('fix.proposal.detail') }}</summary>
          <h3 class="m-prop__label">{{ $t('fix.proposal.files') }}</h3>
          <ul class="m-prop__files">
            <li v-for="f in p.files || []" :key="f" class="m-code">{{ f }}</li>
          </ul>
          <template v-if="p.diff">
            <h3 class="m-prop__label">{{ $t('fix.proposal.diff') }}</h3>
            <pre class="m-code m-prop__pre"><MaskedText :text="p.diff" /></pre>
          </template>
          <h3 class="m-prop__label">{{ $t('fix.proposal.tests') }}</h3>
          <p class="m-small">{{ $t(`fix.proposal.tests_${testsKey}`) }}</p>
          <pre v-if="p.tests_output" class="m-code m-prop__pre"><MaskedText :text="p.tests_output" /></pre>
          <p v-else-if="testsKey === 'passed' || testsKey === 'failed'" class="m-muted m-small">{{ $t('fix.proposal.tests_output_none') }}</p>
          <template v-if="$ui.advanced && commands.length">
            <h3 class="m-prop__label">{{ $t('fix.proposal.commands') }}</h3>
            <ul class="m-prop__files">
              <li v-for="(c, i) in commands" :key="`${c.what}-${i}`" class="m-small">
                <template v-if="c.what === 'tests'">{{ $t('fix.proposal.cmd.tests') }}</template>
                <template v-else>{{ $t(`fix.proposal.cmd.${c.what}`) }} <span class="m-code">{{ c.argv }}</span></template>
              </li>
            </ul>
          </template>
          <h3 class="m-prop__label">{{ $t('fix.proposal.rescan') }}</h3>
          <p class="m-small">{{ $t(rescanText) }}</p>
          <p v-if="$ui.advanced" class="m-muted m-small">{{ $t('fix.proposal.hash', { hash: shortHash }) }}</p>
        </details>
      </template>
      <p v-else class="m-muted">{{ $t(attempt.state === 'preparing' ? 'fix.proposal.none' : 'fix.proposal.none_idle') }}</p>
      <v-btn
        v-if="attempt.state === 'preparing'"
        variant="text"
        size="small"
        class="m-prop__stop"
        :loading="refusing"
        :disabled="refusing"
        @click="refuseOpen = true"
      >
        {{ $t('fix.proposal.stop') }}
      </v-btn>

      <p v-if="doneText" class="m-prop__done m-voice">{{ doneText }}</p>
    </section>

    <v-dialog v-model="refuseOpen" max-width="440">
      <v-card aria-labelledby="fix-refuse-title">
        <v-card-title id="fix-refuse-title" class="m-prop__dialog-title">{{ $t('fix.refuse.title') }}</v-card-title>
        <v-card-text>
          <p class="m-prop__dialog-body">{{ $t('fix.refuse.body') }}</p>
          <v-textarea v-model="reason" :label="$t('fix.refuse.reason')" rows="2" auto-grow counter="500" maxlength="500" hide-details="auto" />
        </v-card-text>
        <v-card-actions class="m-prop__dialog-actions">
          <v-btn variant="text" @click="refuseOpen = false">{{ $t('fix.refuse.keep') }}</v-btn>
          <v-btn color="error" variant="flat" @click="refuse">{{ $t('fix.proposal.refuse') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </aside>
</template>

<script>
import FieldHelp from './FieldHelp.vue'
import MaskedText from './MaskedText.vue'
import { severityOf } from '../lib/digestView.js'
import { canApprove, canRunTests, codeFilesShown, proposalFacts, proposalSentence, testsState } from '../lib/fixView.js'
import { plainSentence } from '../lib/modeView.js'
import { cameBack, rescanKey } from '../lib/pathView.js'

// FixProposal is the right of the Fix page: the flaw in plain words (the
// three sentences of its sheet), then the proposal in plain words with
// Valider / Refuser, and "Voir le détail" folded (diff, tests, re-scan).
export default {
  name: 'FixProposal',
  components: { FieldHelp, MaskedText },
  props: {
    attempt: { type: Object, default: null },
    // finding is the attempt's FixFindingView, or the open finding chosen.
    finding: { type: Object, default: () => ({}) },
    // sheet is GET /findings/{id}: the three sentences and the analysis.
    sheet: { type: Object, default: null },
    sheetLoading: { type: Boolean, default: false },
    approving: { type: Boolean, default: false },
    refusing: { type: Boolean, default: false },
    // runningTests: the tests the person asked for are running.
    runningTests: { type: Boolean, default: false },
    // updated says the agent replaced the proposal since it was first shown.
    updated: { type: Boolean, default: false },
  },
  // run-tests carries the hash of the proposal shown.
  emits: ['approve', 'refuse', 'run-tests'],
  data() {
    // showChange opens the diff and the test output in the simple mode.
    return { refuseOpen: false, reason: '', showChange: false }
  },
  computed: {
    p() {
      return this.attempt?.proposal || null
    },
    project() {
      return this.attempt?.project || this.sheet?.project || this.finding.project || ''
    },
    severity() {
      return severityOf(this.sheet?.severity || this.finding.severity)
    },
    sentences() {
      const ex = this.sheet?.explanation || {}
      return [
        { key: 'what', label: 'sheet.what', text: ex.what },
        { key: 'impact', label: 'sheet.impact', text: ex.impact },
        { key: 'cost', label: 'sheet.cost', text: ex.cost },
      ].filter((s) => s.text)
    },
    sentence() {
      return proposalSentence(proposalFacts(this.attempt, this.sheet), this.$ui.lang)
    },
    rescanText() {
      return rescanKey(this.attempt)
    },
    approvable() {
      return canApprove(this.attempt)
    },
    testsKey() {
      return testsState(this.p?.tests_status)
    },
    testsRunnable() {
      return canRunTests(this.attempt)
    },
    // codeFiles: the code files the agent changed, 10 at most, and how many more.
    codeFiles() {
      return codeFilesShown(this.p?.code_files)
    },
    busy() {
      return this.approving || this.refusing || this.runningTests
    },
    // commands: what Michel ran for the proposal (update, install, tests).
    commands() {
      return (this.p?.commands || []).filter((c) => ['update', 'install', 'tests'].includes(c.what))
    },
    shortHash() {
      return String(this.p?.hash || '').slice(0, 12)
    },
    doneText() {
      const a = this.attempt
      if (!a) return ''
      switch (a.state) {
        case 'applied':
          return this.$t('fix.chat.applied', { branch: a.branch })
        case 'proven_fixed':
          if (cameBack(a)) return this.$t('fix.done.came_back')
          return `${this.$t('fix.chat.applied', { branch: a.branch })} ${this.$t('fix.done.proven')}`
        case 'inconclusive':
          return this.$t('fix.done.inconclusive', { branch: a.branch })
        case 'approved':
          return this.$t('fix.done.approved')
        case 'refused':
        case 'failed':
        case 'superseded':
        case 'withdrawn':
          return this.$t(`fix.done.${a.state}`)
        default:
          return ''
      }
    },
  },
  watch: {
    'attempt.id'() {
      this.refuseOpen = false
      this.reason = ''
    },
  },
  methods: {
    // strip removes identifiers and file names from a sentence shown in the simple mode.
    strip(text) {
      return plainSentence(text, this.sheet)
    },
    // openChange shows the change the tests would run, folded below.
    openChange() {
      this.showChange = true
      this.$nextTick(() => {
        const d = this.$refs.detail
        if (!d) return
        d.open = true
        if (typeof d.scrollIntoView === 'function') d.scrollIntoView({ block: 'start', behavior: 'smooth' })
      })
    },
    refuse() {
      this.refuseOpen = false
      this.$emit('refuse', this.reason.trim())
      this.reason = ''
    },
  },
}
</script>

<style scoped>
.m-prop { display: grid; gap: 1.5rem; align-content: start; min-width: 0; }
.m-prop__block { display: grid; gap: 0.6rem; }
.m-prop__block p { margin: 0; }
.m-prop__title { font-family: var(--m-voice); font-size: 1.25rem; font-weight: 600; margin: 0; }
.m-prop__id { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.35rem 0.75rem; font-weight: 600; }
.m-prop__project { margin-top: -0.4rem !important; }
.m-prop__sentences { display: grid; gap: 0.7rem; }
.m-prop__label { font-size: 0.85rem; font-weight: 650; margin: 0.4rem 0 0.15rem; color: rgba(var(--v-theme-on-surface), 0.72); }
.m-prop__sentence { font-size: 1.04rem; line-height: 1.55; }
.m-prop__main { font-size: 1.12rem; }
.m-prop__summary { white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.5; }
.m-prop__note { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgba(var(--v-theme-info), 0.12); }
.m-prop__warn { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgba(var(--v-theme-warning), 0.12); }
.m-prop__await { display: grid; gap: 0.35rem; }
.m-prop__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.25rem; }
.m-prop__busy { display: flex; align-items: center; gap: 0.5rem; }
.m-prop__detail summary { cursor: pointer; font-size: 0.9rem; font-weight: 600; color: rgb(var(--v-theme-primary)); padding: 0.25rem 0; }
.m-prop__files { list-style: none; padding: 0; margin: 0; display: grid; gap: 0.1rem; }
.m-prop__pre {
  margin: 0.25rem 0 0.5rem;
  padding: 0.6rem 0.75rem;
  border-radius: 8px;
  max-height: 22rem;
  overflow: auto;
  white-space: pre;
  font-size: 0.78rem;
  background: rgba(var(--v-theme-on-surface), 0.05);
}
.m-prop__see { justify-self: start; margin-left: -0.6rem; }
.m-prop__stop { justify-self: start; margin-left: -0.6rem; }
.m-prop__done { font-size: 1.05rem; line-height: 1.5; }
.m-prop__dialog-title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-prop__dialog-body { margin: 0 0 0.75rem; }
.m-prop__dialog-actions { justify-content: flex-end; }
</style>
