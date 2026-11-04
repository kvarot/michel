<template>
  <div class="m-fix">
    <template v-if="noList">
      <a href="#/" class="m-fix__back">{{ $t('path.back') }}</a>
      <p v-if="isServer" class="m-muted m-fix__intro">{{ $t('fix.intro_server') }}</p>
    </template>
    <header v-else class="m-fix__head">
      <h1 class="m-fix__title">{{ $t('fix.title') }}</h1>
      <p v-if="loading || failure || !isEmpty" class="m-muted m-fix__intro">{{ serverOnly ? $t('fix.intro_server') : $t('fix.intro') }}</p>
    </header>

    <v-alert v-if="agentProblem && !serverOnly" type="warning" variant="tonal" density="comfortable" class="m-fix__agent" role="status">
      <p v-if="agentProblem.title" class="m-fix__agent-title">{{ agentProblem.title }}</p>
      <p>{{ agentProblem.text }}</p>
      <v-btn size="small" variant="text" color="primary" class="m-fix__agent-btn" :loading="agentLoading" @click="loadAgent(true)">
        {{ $t('fix.agent.recheck') }}
      </v-btn>
    </v-alert>

    <div v-if="loading" class="m-fix__state m-muted" role="status">
      <v-progress-circular indeterminate size="22" width="2" color="primary" />
      {{ $t('fix.loading') }}
    </div>

    <div v-else-if="failure" class="m-fix__state" role="alert">
      <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
      <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
      <v-btn size="small" variant="tonal" color="primary" @click="loadAll">{{ $t('app.retry') }}</v-btn>
    </div>

    <div v-else-if="isEmpty" class="m-fix__state m-fix__empty">
      <p class="m-voice">{{ $t('empty.fix') }}</p>
      <v-btn color="primary" variant="flat" href="#/">{{ $t('empty.fix_action') }}</v-btn>
    </div>

    <div v-else class="m-fix__grid" :class="{ 'm-fix__grid--guided': noList }">
      <nav v-if="!noList" class="m-fix__list" :aria-label="$t('fix.list_label')">
        <section v-for="g in groups" :key="g.key" class="m-fix__group" :aria-labelledby="`fix-group-${g.key}`">
          <h2 :id="`fix-group-${g.key}`" class="m-fix__group-title">
            {{ $t(`fix.group.${g.key}`) }}
            <span v-if="g.items.length" class="m-fix__count">{{ g.items.length }}</span>
          </h2>
          <p v-if="!g.items.length" class="m-muted m-small m-fix__none">{{ $t('fix.group.empty') }}</p>
          <ul v-else class="m-fix__items">
            <li v-for="item in g.items" :key="itemKey(item)">
              <a
                :href="itemHref(item)"
                class="m-fix__item"
                :class="{ 'm-fix__item--on': isSelected(item) }"
                :aria-current="isSelected(item) ? 'page' : undefined"
              >
                <span class="m-fix__item-top">
                  <span class="m-code m-fix__pkg">{{ itemFinding(item).package }}</span>
                  <span class="m-sev" :class="`m-sev--${sev(itemFinding(item).severity)}`">{{ $t(`severity.${sev(itemFinding(item).severity)}`) }}</span>
                </span>
                <span class="m-small m-muted">{{ itemWhere(item) }}</span>
                <span class="m-small m-voice">{{ lineText(item) }}</span>
              </a>
            </li>
          </ul>
        </section>
      </nav>

      <div class="m-fix__center">
        <div v-if="waiting" class="m-fix__state m-muted" role="status">
          <v-progress-circular indeterminate size="18" width="2" color="primary" />
          {{ $t('fix.loading') }}
        </div>
        <p v-else-if="!selectedFinding" class="m-voice m-fix__pick">{{ $t('fix.pick') }}</p>
        <div v-else-if="viewLoading" class="m-fix__state m-muted" role="status">
          <v-progress-circular indeterminate size="18" width="2" color="primary" />
          {{ $t('fix.loading') }}
        </div>
        <FailureGuide
          v-else-if="guided"
          class="m-fix__guide"
          :attempt="current"
          :finding="selectedFinding"
          :sheet="isServer ? serverFlaw : sheetOfSelected"
          :project-view="projectOfSelected"
          :server="isServer"
          :target="isServer ? target : null"
          :can-start="isServer || canStart"
          :starting="isServer ? acting === 'again' : starting"
          :hold-busy="holdBusy"
          @start="isServer ? again() : start()"
          @to-proposal="toProposal"
          @hold-continue="holdContinue"
          @hold-withdraw="holdWithdraw"
          @refresh="refreshAttempt"
        />
        <!-- Here in the template as on the screen: it is read and tabbed to before what follows. -->
        <v-alert v-if="actionError" type="error" variant="tonal" density="comfortable" class="m-fix__error" role="alert" closable @click:close="actionError = null">
          <p>{{ actionError.offline ? $t('offline.hint') : actionError.error || $t('error.generic') }}</p>
          <p v-if="actionError.hint" class="m-small">{{ actionError.hint }}</p>
          <details v-if="actionError.data && actionError.data.detail" class="m-fix__detail">
            <summary class="m-small">{{ $t('fix.proposal.detail') }}</summary>
            <p class="m-code m-small">{{ actionError.data.detail }}</p>
          </details>
        </v-alert>
        <div v-if="serverOnly && !waiting && !viewLoading" class="m-fix__server">
          <h2 class="m-fix__server-title">{{ $t('srvfix.center_title', { name: current.server.target.name }) }}</h2>
          <p class="m-muted m-small">{{ $t('srvfix.no_agent_chat') }}</p>
          <template v-if="current.proposal && (current.proposal.steps_server || []).length">
            <h3 class="m-fix__server-sub">{{ $t('srvfix.what') }}</h3>
            <ol class="m-fix__server-list">
              <li v-for="(line, i) in current.proposal.steps_server" :key="i" class="m-voice">{{ line }}</li>
            </ol>
          </template>
          <template v-if="(current.server.steps || []).length">
            <h3 class="m-fix__server-sub">{{ $t('srvfix.steps') }}</h3>
            <ul class="m-fix__steps" aria-live="polite">
              <li v-for="(st, i) in current.server.steps" :key="i" :class="st.ok ? 'm-fix__step--ok' : 'm-fix__step--bad'">
                <span aria-hidden="true">{{ st.ok ? '✓' : '✗' }}</span>
                {{ stepText(st) }}
              </li>
            </ul>
          </template>
        </div>
        <template v-if="showsWork">
          <DecisionPanel v-if="toDecide" :key="toDecide.id" :finding="toDecide" @decided="onDecided" />
          <details v-if="noList && current" class="m-fix__chat" :open="hasConversation || undefined">
            <summary>{{ $t('path.chat') }}</summary>
            <FixChat
              :attempt="current"
              :messages="messages"
              :activity="activity"
              :can-start="canStart"
              :starting="starting"
              :sending="sending"
              :reconnecting="reconnecting"
              no-start
              @send="send"
            />
          </details>
          <FixChat
            v-else-if="!noList"
            :attempt="current"
            :messages="messages"
            :activity="activity"
            :can-start="canStart"
            :starting="starting"
            :sending="sending"
            :reconnecting="reconnecting"
            :no-start="chatHidesStart"
            @start="start"
            @send="send"
          />
        </template>
      </div>

      <ServerProposal
        v-if="current && current.server"
        class="m-fix__right"
        :attempt="current"
        :flaw="serverFlaw"
        :target="target"
        :approving="approving"
        :refusing="refusing"
        :acting="acting"
        :updated="proposalUpdated"
        @approve="approve"
        @refuse="refuse"
        @snapshot="serverAction('snapshot-done', 'snapshot')"
        @applied="serverAction('applied-by-me', 'applied')"
        @handover="(hash) => serverAction('hand-over', 'handover', { hash })"
        @resolve="serverAction('resolve', 'resolve')"
        @again="again"
      />
      <div v-else-if="selectedFinding" class="m-fix__right m-fix__side">
        <FixProposal
          :attempt="current"
          :finding="selectedFinding"
          :sheet="sheet"
          :sheet-loading="sheetLoading"
          :approving="approving"
          :refusing="refusing"
          :updated="proposalUpdated"
          @approve="approve"
          @refuse="refuse"
        />
      </div>
    </div>

    <v-dialog v-model="consent.open" max-width="520" scrollable persistent>
      <AiConsentDialog
        :project="consent.project"
        :lines="consent.lines"
        :switch-mode="consent.switchMode"
        :busy="consent.busy"
        :error="consent.error"
        @accept="acceptConsent"
        @cancel="consent.open = false"
      />
    </v-dialog>
  </div>
</template>

<script>
import AiConsentDialog from './AiConsentDialog.vue'
import DecisionPanel from './DecisionPanel.vue'
import FailureGuide from './FailureGuide.vue'
import FixChat from './FixChat.vue'
import FixProposal from './FixProposal.vue'
import ServerProposal from './ServerProposal.vue'
import { api } from '../api.js'
import { severityOf } from '../lib/digestView.js'
import { acceptResult, activityLine, canDecide, decidingAttempt, fixHash, groupAttempts, isFinal, isOpen, mergeMessages, selectAction, stateLine } from '../lib/fixView.js'
import { chatNoStart, isGone } from '../lib/pathView.js'
import { isServerFinal, serverAttemptLine, serverPollDelay, stepLine } from '../lib/serversView.js'


// listEvery is how often the list is read again while the page is open: an
// attempt started alone (level 2) or proposed through michel mcp shows up.
const listEvery = 15000

// FixPage is the "Corriger" page: the list by state on the left, the path of
// the flaw and the conversation with the agent in the middle, the flaw and the
// proposal on the right. In the simple mode, a chosen flaw has no list and
// its conversation is folded. route is {attempt, finding} from the address.
export default {
  name: 'FixPage',
  components: { AiConsentDialog, DecisionPanel, FailureGuide, FixChat, FixProposal, ServerProposal },
  props: {
    route: { type: Object, default: () => ({ attempt: '', finding: '' }) },
  },
  emits: ['changed'],
  data() {
    return {
      loading: true,
      failure: null,
      attempts: [],
      findings: [],
      // projects is GET /projects: FailureGuide says what will happen from it.
      projects: [],
      agent: null,
      agentError: null,
      agentLoading: false,
      // The selected attempt, in full, and its live conversation.
      current: null,
      messages: [],
      activity: '',
      reconnecting: false,
      viewLoading: false,
      proposalUpdated: false,
      // shownHash is the hash of the proposal on screen: Valider sends it.
      shownHash: '',
      sheet: null,
      sheetFor: '',
      sheetLoading: false,
      // startingFor is the finding whose start is running ('' for none).
      startingFor: '',
      // focusGuide: the start's button is gone with the start: the next attempt
      // shown takes the keyboard to its heading.
      focusGuide: false,
      approving: false,
      refusing: false,
      // holdBusy is the answer to a held attempt running: withdraw, continue, or ''.
      holdBusy: '',
      // acting is the server fix action running: snapshot, applied, handover, resolve, again.
      acting: '',
      // target is the sheet of the server of the attempt shown (a server fix).
      target: null,
      serverTimer: null,
      sending: false,
      actionError: null,
      consent: { open: false, project: '', lines: [], switchMode: false, busy: false, error: '', findingId: '' },
      conn: null,
      timer: null,
      // alive is false once the page is gone: late answers are dropped.
      alive: true,
      // pending is the attempt asked and not answered yet (null for none).
      pending: null,
    }
  },
  computed: {
    lang() {
      return this.$ui.lang
    },
    groups() {
      return groupAttempts(this.attempts, this.findings)
    },
    isEmpty() {
      return this.groups.every((g) => !g.items.length) && !this.route.attempt && !this.route.finding
    },
    // selectedFinding is the finding the middle and the right show.
    selectedFinding() {
      if (this.current) return this.current.finding
      if (!this.route.finding) return null
      const f = this.findings.find((x) => x.id === this.route.finding)
      if (f) return f
      if (this.sheet && this.sheet.id === this.route.finding) return this.sheet
      return { id: this.route.finding, package: '', severity: '' }
    },
    // guided: a flaw under its path, of a project or of a server.
    guided() {
      return !!this.selectedFinding
    },
    isServer() {
      return !!this.current?.server
    },
    // noList: the simple mode leaves a chosen flaw alone on the page, of a project or of a server.
    noList() {
      return !this.$ui.advanced && !!(this.route.attempt || this.route.finding)
    },
    starting() {
      return this.startingFor !== '' && this.startingFor === this.selectedFinding?.id
    },
    sheetOfSelected() {
      return this.sheet && this.sheet.id === this.selectedFinding?.id ? this.sheet : null
    },
    projectOfSelected() {
      const name = this.current?.project || this.sheetOfSelected?.project || this.selectedFinding?.project
      return (name && this.projects.find((p) => p.name === name)) || null
    },
    // showsWork: the middle is on the flaw itself, not on a wait or a server's own view.
    showsWork() {
      return !this.waiting && !!this.selectedFinding && !this.viewLoading && !this.serverOnly
    },
    chatHidesStart() {
      return chatNoStart({
        guided: this.guided,
        project: this.projectOfSelected,
        gone: isGone(this.selectedFinding, this.sheetOfSelected),
      })
    },
    // hasConversation opens the folded conversation: the agent works or has spoken.
    hasConversation() {
      return !!this.messages.length || this.current?.state === 'preparing'
    },
    // toDecide is the flaw's sheet when the page offers its decision.
    toDecide() {
      const id = this.selectedFinding?.id
      return id && this.sheet?.id === id && !this.startingFor && canDecide(decidingAttempt(this.attempts, id, this.current)) ? this.sheet : null
    },
    agentProblem() {
      if (this.agentError) {
        // The server's own sentence (no fix service here, or offline).
        return { title: '', text: this.agentError.offline ? this.$t('offline.hint') : this.agentError.error || this.$t('fix.agent.unknown') }
      }
      if (this.agent && !this.agent.ready) {
        return { title: this.$t('fix.agent.not_ready'), text: this.agent.hint || this.$t('fix.agent.unknown') }
      }
      return null
    },
    canStart() {
      return !this.agentProblem
    },
    // serverOnly: a server fix Michel prepares alone (no agent, no conversation).
    serverOnly() {
      const a = this.current
      return !!a && !!a.server && !String(a.origin || '').startsWith('agent') && !this.messages.length
    },
    // serverFlaw is the finding as the server's sheet tells it.
    serverFlaw() {
      if (!this.current?.server || !this.target) return null
      return (this.target.findings || []).find((f) => f.id === this.current.finding?.id) || null
    },
    // waiting: the attempt the address names is on its way (a direct link).
    waiting() {
      return !!this.route.attempt && !this.current && this.pending === this.route.attempt
    },
  },
  watch: {
    route: {
      handler() {
        this.select()
      },
      deep: true,
    },
    // A state that changes takes buttons away, also when no click asked for it
    // (a poll, a rule): the keyboard never falls to nothing with them.
    'current.state': {
      flush: 'pre',
      handler() {
        const el = document.activeElement
        if (!el || el === document.body) return
        this.$nextTick(() => {
          if (!el.isConnected) this.guardFocus()
        })
      },
    },
    lang() {
      // Michel's sentences (the flaw, the refusals) come in the page's language.
      this.sheetFor = ''
      this.loadAgent(false)
      this.loadList(true).then(() => {
        if (this.current) this.openAttempt(this.current.id)
        else if (this.route.finding) this.loadSheet(this.route.finding)
      })
    },
  },
  created() {
    this.loadAll()
    this.loadAgent(false)
    this.timer = setInterval(() => this.loadList(true, false), listEvery)
  },
  beforeUnmount() {
    this.alive = false
    this.pending = null
    this.closeStream()
    clearInterval(this.timer)
    clearTimeout(this.serverTimer)
  },
  methods: {
    q(path) {
      return `${path}${path.includes('?') ? '&' : '?'}lang=${encodeURIComponent(this.lang)}`
    },
    sev(s) {
      return severityOf(s)
    },
    itemFinding(item) {
      return item.kind === 'attempt' ? item.attempt.finding || {} : item.finding
    },
    itemProject(item) {
      return item.kind === 'attempt' ? item.attempt.project : item.finding.project
    },
    itemWhere(item) {
      if (item.kind === 'attempt' && item.attempt.server) return this.$t('srvfix.flaw_on', { name: item.attempt.server.target.name })
      return this.$t('fix.in_project', { project: this.itemProject(item) })
    },
    stepText(st) {
      return stepLine(st, this.lang)
    },
    itemKey(item) {
      return item.kind === 'attempt' ? `a:${item.attempt.id}` : `f:${item.finding.id}`
    },
    itemHref(item) {
      return item.kind === 'attempt' ? fixHash({ attempt: item.attempt.id }) : fixHash({ finding: item.finding.id })
    },
    isSelected(item) {
      if (item.kind === 'attempt') return this.route.attempt === item.attempt.id
      return !this.route.attempt && this.route.finding === item.finding.id
    },
    lineText(item) {
      if (item.kind === 'attempt' && item.attempt.server) return serverAttemptLine(item.attempt, this.lang)
      return stateLine(item, this.lang)
    },

    /** loadAll reads the list, then shows what the address names. */
    async loadAll() {
      this.loading = !this.attempts.length && !this.findings.length
      this.failure = null
      try {
        await this.loadList(false)
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
      }
      this.select()
    },
    /**
     * loadList reads the attempts and, with findings, the open findings of
     * every project (the periodic read skips them). quiet keeps errors silent.
     */
    async loadList(quiet, findings = true) {
      try {
        const [attempts, projects] = await Promise.all([api.get(this.q('/fixes')), findings ? api.get('/projects') : null])
        if (findings) {
          this.projects = projects || []
          const lists = await Promise.all((projects || []).map((p) =>
            api.get(this.q(`/projects/${encodeURIComponent(p.name)}/findings`)).catch(() => [])))
          this.findings = lists.flat().filter(isOpen)
        }
        this.attempts = attempts || []
      } catch (err) {
        if (!quiet) throw err
      }
    },
    async loadAgent(fresh) {
      this.agentLoading = fresh
      try {
        this.agent = await api.get(this.q('/agent/status'))
        this.agentError = null
      } catch (err) {
        if (err?.status !== 401) this.agentError = err
      } finally {
        this.agentLoading = false
      }
    },
    async loadSheet(id) {
      if (!id || (this.sheetFor === id && this.sheet)) return
      this.sheetFor = id
      this.sheet = null
      this.sheetLoading = true
      try {
        const s = await api.get(this.q(`/findings/${encodeURIComponent(id)}`))
        if (this.sheetFor === id) this.sheet = s
      } catch {
        // The right side then shows what the list knows of the finding.
      } finally {
        if (this.sheetFor === id) this.sheetLoading = false
      }
    },

    /** toProposal brings the proposal and its Valider into view, on a phone far below the path. */
    toProposal() {
      const el = document.getElementById('fix-proposal-title') || document.getElementById('sfix-proposal-title')
      if (!el) return
      el.setAttribute('tabindex', '-1')
      el.focus({ preventScroll: true })
      el.scrollIntoView({ block: 'start' })
    },

    /**
     * onDecided takes the answer as the new sheet, as FindingSheet does: the
     * panel stays on screen with its confirmation and its proof.
     */
    onDecided(view) {
      this.sheet = view
      this.sheetFor = view.id
      this.$emit('changed')
      this.loadList(true)
    },

    /** select shows the address's attempt or finding. */
    select() {
      if (!this.alive) return
      const act = selectAction(this.route, this.pending ?? this.current?.id ?? null, this.attempts)
      if (act.kind === 'keep') return
      this.actionError = null
      if (act.kind === 'open') {
        this.openAttempt(act.id)
        return
      }
      // A finding already tried shows its newest attempt (its history, "OK, réessaie").
      if (act.kind === 'redirect') {
        window.location.replace(fixHash({ attempt: act.id }))
        return
      }
      this.pending = null
      this.closeStream()
      clearTimeout(this.serverTimer)
      this.current = null
      this.target = null
      this.messages = []
      this.activity = ''
      this.shownHash = ''
      this.proposalUpdated = false
      if (act.kind === 'finding') this.loadSheet(act.id)
    },
    /** openAttempt reads the attempt in full and follows its stream until it is over. */
    async openAttempt(id) {
      this.pending = id
      this.closeStream()
      this.viewLoading = !!this.current && this.current.id !== id
      this.proposalUpdated = false
      let v = null
      let failure = null
      try {
        v = await api.get(this.q(`/fix/${encodeURIComponent(id)}`))
      } catch (err) {
        failure = err
      }
      // A late answer (page gone, or another attempt asked since) is dropped.
      if (!acceptResult(this, id)) return
      this.pending = null
      this.viewLoading = false
      if (failure) {
        if (failure?.status !== 401) this.actionError = failure
        this.current = null
        return
      }
      this.show(v)
      if (v.server) {
        this.pollServer(id)
        if (!isServerFinal(v.state)) this.follow(id)
      } else if (!isFinal(v.state)) {
        this.follow(id)
      }
    },
    /** pollServer reads a server fix again while it is under way (its steps are not on the stream). */
    pollServer(id) {
      clearTimeout(this.serverTimer)
      if (!this.alive || !this.current || this.current.id !== id || isServerFinal(this.current.state)) return
      // 3 s while Michel works on it, 30 s while it waits for the user.
      const delay = serverPollDelay(this.current)
      if (!delay) return
      this.serverTimer = setTimeout(async () => {
        if (!this.alive || this.current?.id !== id) return
        try {
          const v = await api.get(this.q(`/fix/${encodeURIComponent(id)}`))
          if (!this.alive || this.current?.id !== id) return
          const was = this.current.state
          this.show(v)
          if (was !== v.state) this.$emit('changed')
        } catch {
          // Tried again at the next turn.
        }
        this.pollServer(id)
      }, delay)
    },
    /** loadTarget reads the sheet of the server of a server fix (the flaw in words). */
    async loadTarget(id) {
      if (!id || this.target?.id === id) return
      try {
        const t = await api.get(this.q(`/targets/${encodeURIComponent(id)}`))
        if (this.alive && this.current?.server?.target?.id === id) this.target = t
      } catch {
        // The right side then shows what the attempt knows of the flaw.
      }
    },
    /** serverAction sends the user's word on a server fix: snapshot-done, applied-by-me, resolve. */
    async serverAction(path, what, body) {
      if (!this.current || this.acting) return
      const id = this.current.id
      this.acting = what
      this.actionError = null
      this.focusGuide = true
      try {
        const v = await api.post(this.q(`/fix/${encodeURIComponent(id)}/${path}`), body)
        if (!this.alive || this.current?.id !== id) return
        this.show(v)
        this.pollServer(id)
        this.$emit('changed')
      } catch (err) {
        if (err?.status === 401) return
        this.actionError = err
        if (this.alive) {
          await this.openAttempt(id)
          if (this.alive) this.actionError = err
        }
      } finally {
        this.acting = ''
        this.guardFocus()
      }
    },
    /** again prepares a new fix of the same server finding (after a failure or a refusal). */
    async again() {
      const a = this.current
      if (!a?.server || this.acting) return
      this.acting = 'again'
      this.actionError = null
      this.focusGuide = true
      try {
        const r = await api.post(this.q(`/targets/${encodeURIComponent(a.server.target.id)}/fix/${encodeURIComponent(a.finding.id)}`))
        if (!this.alive) return
        if (r?.attempt) {
          this.attempts.unshift({ ...r.attempt, messages: null })
          this.$emit('changed')
          window.location.hash = fixHash({ attempt: r.attempt.id })
        }
      } catch (err) {
        if (err?.status !== 401) this.actionError = err
        this.focusGuide = false
      } finally {
        this.acting = ''
        this.guardFocus()
      }
    },
    /**
     * refreshAttempt reads the attempt on screen again after a click on the Git buttons
     * or during the check. final: the check ended, the flaw may have left: its sheet and
     * the lists are read again too.
     */
    async refreshAttempt({ final = false, done } = {}) {
      const id = this.current?.id
      if (!id) return
      try {
        if (final) {
          this.sheetFor = ''
          await this.loadList(true)
        }
        const v = await api.get(this.q(`/fix/${encodeURIComponent(id)}`))
        if (!this.alive || this.current?.id !== id) return
        const was = this.current.state
        this.show(v)
        if (was !== v.state) this.$emit('changed')
        done?.(true)
      } catch {
        // Tried again at the next look; the page keeps what it holds.
        done?.(false)
      }
    },
    /** guardFocus: when the button in focus went away with what it did, the keyboard goes to the flaw's heading. */
    guardFocus() {
      this.$nextTick(() => {
        const el = document.activeElement
        if (this.alive && (!el || el === document.body)) document.getElementById('fix-guide-title')?.focus()
      })
    },
    /** show puts an AttemptView (in full) on screen. */
    show(v) {
      this.current = v
      const all = v.messages || []
      this.messages = all.filter((m) => m.role !== 'tool')
      const tools = all.filter((m) => m.role === 'tool')
      this.activity = tools.length ? activityLine(tools[tools.length - 1], this.lang) : ''
      this.shownHash = v.proposal?.hash || ''
      this.patchList(v)
      if (v.server) this.loadTarget(v.server.target?.id)
      else this.loadSheet(v.finding?.id)
      if (this.focusGuide) {
        this.focusGuide = false
        this.guardFocus()
      }
    },
    /** patchList updates the attempt's line in the list. */
    patchList(v) {
      const i = this.attempts.findIndex((a) => a.id === v.id)
      const line = { ...v, messages: null }
      if (i >= 0) this.attempts.splice(i, 1, { ...this.attempts[i], ...line })
      else this.attempts.unshift(line)
    },
    follow(id) {
      if (!this.alive) return
      this.closeStream()
      this.conn = api.stream(this.q(`/fix/${encodeURIComponent(id)}/events`), (ev) => this.onEvent(id, ev), (status) => {
        this.reconnecting = status === 'reconnecting'
      })
    },
    closeStream() {
      if (this.conn) this.conn.close()
      this.conn = null
      this.reconnecting = false
    },
    onEvent(id, ev) {
      if (!this.current || this.current.id !== id || !ev.data) return
      const d = ev.data
      switch (ev.event) {
        case 'message':
          this.messages = mergeMessages(this.messages, d)
          break
        case 'activity':
          this.activity = activityLine(d, this.lang)
          break
        case 'proposal':
          if (this.shownHash && d.hash !== this.shownHash) this.proposalUpdated = true
          this.current = { ...this.current, proposal: d }
          this.shownHash = d.hash || ''
          break
        case 'state': {
          const was = this.current.state
          this.current = { ...this.current, state: d.state, cause: d.cause, approved_by: d.approved_by, branch: d.branch || '', updated_at: d.updated_at }
          this.patchList(this.current)
          // The state event has no list of keys: only the attempt read in full has it.
          if (d.state === 'held' && !this.current.hold) this.openAttempt(id)
          if (isFinal(d.state)) {
            this.closeStream()
            this.activity = ''
          }
          if (was !== d.state) this.$emit('changed')
          break
        }
        default:
      }
    },

    /** start launches a fix on the selected finding; a missing consent opens the dialog. */
    async start() {
      const f = this.selectedFinding
      if (!f || this.startingFor) return
      this.startingFor = f.id
      this.actionError = null
      const project = this.current?.project || this.sheet?.project || f.project || ''
      try {
        const r = await api.post(this.q(`/findings/${encodeURIComponent(f.id)}/fix`))
        const a = r?.attempt
        if (!this.alive) return
        if (a) {
          this.attempts.unshift({ ...a, messages: null })
          this.$emit('changed')
          // Only while the user still looks at that finding.
          if (this.selectedFinding?.id === f.id) {
            this.focusGuide = true
            window.location.hash = fixHash({ attempt: a.id })
          }
        }
      } catch (err) {
        if (!this.alive || err?.status === 401) return
        const code = err?.data?.code
        if (err?.status === 409 && code === 'fix.err.consent_required') {
          this.consent = { open: true, project, lines: err.data.consent || [], switchMode: false, busy: false, error: '', findingId: f.id }
          return
        }
        // strict_local: the consent screen explains it and offers the switch (ruling 41).
        if (err?.status === 403 && code === 'fix.err.strict_local' && project) {
          try {
            const v = await api.get(this.q(`/projects/${encodeURIComponent(project)}/ai-consent`))
            if (!this.alive) return
            if (v?.switch_mode) {
              this.consent = { open: true, project, lines: v.lines || [], switchMode: true, busy: false, error: '', findingId: f.id }
              return
            }
          } catch {
            // The refusal below says it in plain words.
          }
        }
        this.actionError = err
      } finally {
        this.startingFor = ''
      }
    },
    async acceptConsent() {
      const c = this.consent
      if (!c.project) {
        c.open = false
        return
      }
      c.busy = true
      c.error = ''
      try {
        await api.post(this.q(`/projects/${encodeURIComponent(c.project)}/ai-consent`), c.switchMode ? { switch_to_standard: true } : undefined)
        if (!this.alive) return
        c.open = false
        this.start()
      } catch (err) {
        c.error = err?.offline ? this.$t('offline.hint') : err?.error || this.$t('error.generic')
      } finally {
        c.busy = false
      }
    },
    async send(text, clear) {
      if (!this.current) return
      this.sending = true
      this.actionError = null
      try {
        await api.post(this.q(`/fix/${encodeURIComponent(this.current.id)}/message`), { text })
        clear()
      } catch (err) {
        if (err?.status !== 401) this.actionError = err
      } finally {
        this.sending = false
      }
    },
    /** approve validates the proposal on screen (its hash); a changed one is reloaded. */
    async approve() {
      if (!this.current || !this.shownHash || this.approving) return
      const id = this.current.id
      this.approving = true
      this.actionError = null
      this.focusGuide = true
      try {
        const v = await api.post(this.q(`/fix/${encodeURIComponent(id)}/approve`), { hash: this.shownHash })
        if (!this.alive || this.current?.id !== id) return
        this.closeStream()
        this.show(v)
        this.proposalUpdated = false
        // approved (the branch is not there yet): keep following until it is.
        if (v.server) this.pollServer(id)
        else if (!isFinal(v.state)) this.follow(id)
        this.$emit('changed')
      } catch (err) {
        if (err?.status === 401) return
        this.actionError = err
        // A server fix that failed on the server (rolled back, unknown…) is read again.
        if (this.alive && (err?.status === 409 || err?.status === 502 || this.current?.server)) {
          await this.openAttempt(id)
          if (this.alive) this.actionError = err
        }
      } finally {
        this.approving = false
        this.guardFocus()
      }
    },
    /**
     * holdContinue is the person's yes for the list on screen (its hash). When the
     * code changed since, nothing starts: the attempt is read again with its refusal.
     */
    async holdContinue(hash) {
      if (!this.current || this.holdBusy) return
      const id = this.current.id
      this.holdBusy = 'continue'
      this.actionError = null
      this.focusGuide = true
      try {
        const v = await api.post(this.q(`/fix/${encodeURIComponent(id)}/continue`), { hash })
        if (!this.alive || this.current?.id !== id) return
        this.closeStream()
        this.show(v)
        if (!isFinal(v.state)) this.follow(id)
        this.$emit('changed')
      } catch (err) {
        if (err?.status === 401) return
        this.actionError = err
        if (this.alive && err?.status === 409) {
          await this.openAttempt(id)
          if (this.alive) this.actionError = err
          this.$emit('changed')
        }
      } finally {
        this.holdBusy = ''
        this.guardFocus()
      }
    },
    /** holdWithdraw is the person's no: the attempt ends, no agent. */
    async holdWithdraw() {
      if (!this.current || this.holdBusy) return
      const id = this.current.id
      this.holdBusy = 'withdraw'
      this.actionError = null
      this.focusGuide = true
      try {
        const v = await api.post(this.q(`/fix/${encodeURIComponent(id)}/withdraw`))
        if (!this.alive || this.current?.id !== id) return
        this.closeStream()
        this.show(v)
        this.$emit('changed')
      } catch (err) {
        if (err?.status !== 401) this.actionError = err
      } finally {
        this.holdBusy = ''
        this.guardFocus()
      }
    },
    async refuse(reason) {
      if (!this.current || this.refusing) return
      const id = this.current.id
      this.refusing = true
      this.actionError = null
      this.focusGuide = true
      try {
        const v = await api.post(this.q(`/fix/${encodeURIComponent(id)}/refuse`), reason ? { reason } : {})
        if (!this.alive || this.current?.id !== id) return
        this.closeStream()
        this.show(v)
        this.$emit('changed')
      } catch (err) {
        if (err?.status !== 401) this.actionError = err
      } finally {
        this.refusing = false
        this.guardFocus()
      }
    },
  },
}
</script>

<style scoped>
.m-fix { display: grid; gap: 1.25rem; }
.m-fix__head { display: grid; gap: 0.4rem; }
.m-fix__back { justify-self: start; color: rgb(var(--v-theme-primary)); font-weight: 600; font-size: 0.9rem; }
.m-fix__title { font-family: var(--m-voice); font-size: 2rem; font-weight: 600; margin: 0; }
.m-fix__intro { margin: 0; max-width: 70ch; line-height: 1.5; }
.m-fix__agent p { margin: 0; }
.m-fix__agent-title { font-weight: 650; }
.m-fix__agent-btn { margin: 0.25rem 0 0 -0.6rem; }
.m-fix__state { display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; }
.m-fix__state p { margin: 0; flex-basis: 100%; }
.m-fix__empty .m-voice { font-size: 1.2rem; }
.m-fix__grid {
  display: grid;
  grid-template-columns: minmax(13rem, 17rem) minmax(0, 1fr) minmax(17rem, 24rem);
  gap: 1.5rem;
  align-items: start;
}
.m-fix__list { display: grid; gap: 1rem; position: sticky; top: 1rem; }
.m-fix__group-title { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem; font-weight: 650; margin: 0 0 0.35rem; }
.m-fix__count {
  min-width: 1.4rem;
  padding: 0 0.4rem;
  border-radius: 999px;
  text-align: center;
  font-size: 0.8rem;
  background: rgba(var(--v-theme-primary), 0.14);
  color: rgb(var(--v-theme-primary));
}
.m-fix__none { margin: 0; }
.m-fix__items { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.25rem; }
.m-fix__item {
  display: grid;
  gap: 0.1rem;
  padding: 0.5rem 0.65rem;
  border-radius: 8px;
  color: inherit;
  text-decoration: none;
  border: 1px solid transparent;
}
.m-fix__item:hover { background: rgba(var(--v-theme-on-surface), 0.05); }
.m-fix__item--on { background: rgba(var(--v-theme-primary), 0.1); border-color: rgba(var(--v-theme-primary), 0.35); }
.m-fix__item-top { display: flex; justify-content: space-between; align-items: baseline; gap: 0.5rem; }
.m-fix__pkg { font-weight: 600; min-width: 0; }
.m-fix__side { display: grid; gap: 1rem; min-width: 0; }
.m-fix__center {
  display: grid;
  gap: 1rem;
  min-width: 0;
  padding: 1.25rem;
  border-radius: 12px;
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
}
.m-fix__grid--guided { grid-template-columns: minmax(0, 1fr) minmax(17rem, 24rem); }
.m-fix__grid--guided .m-fix__center { padding: 0; border: 0; background: none; }
.m-fix__chat > summary { cursor: pointer; font-weight: 600; color: rgb(var(--v-theme-primary)); padding: 0.25rem 0; }
.m-fix__pick { font-size: 1.1rem; margin: 0; }
.m-fix__server { display: grid; gap: 0.6rem; }
.m-fix__server p { margin: 0; }
.m-fix__server-title { font-family: var(--m-voice); font-size: 1.25rem; font-weight: 600; margin: 0; }
.m-fix__server-sub { font-size: 0.95rem; font-weight: 650; margin: 0.5rem 0 0; }
.m-fix__server-list { margin: 0; padding-left: 1.3rem; display: grid; gap: 0.35rem; line-height: 1.5; }
.m-fix__steps { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.3rem; }
.m-fix__step--ok span { color: rgb(var(--v-theme-success)); font-weight: 700; }
.m-fix__step--bad span { color: rgb(var(--v-theme-error)); font-weight: 700; }
.m-fix__error p { margin: 0; }
.m-fix__detail summary { cursor: pointer; }
.m-fix__detail p { margin: 0.25rem 0 0; overflow-wrap: anywhere; }
@media (max-width: 1100px) {
  .m-fix__grid { grid-template-columns: minmax(12rem, 16rem) minmax(0, 1fr); }
  .m-fix__right { grid-column: 2; }
}
@media (max-width: 1100px) {
  .m-fix__grid--guided { grid-template-columns: minmax(0, 1fr) minmax(15rem, 20rem); }
  .m-fix__grid--guided .m-fix__right { grid-column: 2; }
}
@media (max-width: 900px) {
  .m-fix__grid--guided { grid-template-columns: minmax(0, 1fr); }
  .m-fix__grid--guided .m-fix__right { grid-column: auto; }
}
@media (max-width: 760px) {
  .m-fix__grid { grid-template-columns: 1fr; }
  .m-fix__list { position: static; }
  .m-fix__right { grid-column: auto; }
}
</style>
