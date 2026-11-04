<template>
  <aside class="m-sprop">
    <section class="m-sprop__block" aria-labelledby="sfix-flaw-title">
      <h2 id="sfix-flaw-title" class="m-sprop__title">{{ $t('fix.flaw.title') }}</h2>
      <p class="m-sprop__id">
        <span class="m-sev" :class="`m-sev--${severity}`">{{ $t(`severity.${severity}`) }}</span>
        <span v-if="flawView.kev" class="m-tag m-tag--hot m-small">{{ $t('servers.sheet.kev') }}</span>
        <span v-if="$ui.advanced && flawView.kind === 'server_config'" class="m-code m-muted m-small">{{ flawView.package }}</span>
      </p>
      <p class="m-muted m-small">
        <a :href="serverHref">{{ $t('srvfix.flaw_on', { name: server.target.name }) }}</a>
        <template v-if="target"> · {{ envText }}</template>
      </p>
      <p class="m-voice m-sprop__sentence">{{ flawTitle }}</p>
      <p v-if="flawView.explain" class="m-small">{{ flawView.explain }}</p>
      <p v-if="flawView.location" class="m-muted m-small">{{ $t('servers.sheet.where', { where: flawView.location }) }}</p>
    </section>

    <section class="m-sprop__block" aria-labelledby="sfix-proposal-title">
      <h2 id="sfix-proposal-title" class="m-sprop__title">{{ $t('fix.proposal.title') }}</h2>

      <template v-if="p">
        <p v-if="updated" class="m-sprop__note m-small" role="status">{{ $t('fix.proposal.updated') }}</p>
        <p class="m-voice m-sprop__sentence m-sprop__main">{{ p.summary }}</p>
        <p v-if="server.for_production" class="m-small">{{ $t('srvfix.for_production', { name: server.for_production.name }) }}</p>
        <p v-if="server.mitigation" class="m-sprop__warn m-small">{{ $t('srvfix.mitigation') }}</p>

        <!-- A package upgrade: the snapshot first, then Valider. -->
        <div v-if="needsSnap" class="m-sprop__snap" :class="{ 'm-sprop__snap--done': server.snapshot_done }">
          <h3 class="m-sprop__label">{{ $t('srvfix.snapshot.title') }}</h3>
          <p class="m-small">{{ $t('srvfix.snapshot.body') }}</p>
          <p v-if="server.snapshot_done" class="m-small m-sprop__ok">{{ $t('srvfix.snapshot.noted', { date: dateText(server.snapshot_done_at) }) }}</p>
          <v-btn
            v-else-if="attempt.state === 'proposed'"
            size="small"
            variant="tonal"
            color="primary"
            :loading="acting === 'snapshot'"
            :disabled="!!acting"
            @click="$emit('snapshot')"
          >
            {{ $t('srvfix.snapshot.done') }}
          </v-btn>
          <FieldHelp id="server.snapshot" :field="$t('srvfix.snapshot.title')" />
        </div>

        <template v-if="attempt.state === 'proposed'">
          <div class="m-sprop__actions">
            <v-btn color="primary" variant="flat" :loading="approving" :disabled="!approvable || approving || refusing" @click="$emit('approve')">
              {{ $t('fix.proposal.approve') }}
            </v-btn>
            <v-btn variant="outlined" :loading="refusing" :disabled="approving || refusing" @click="refuseOpen = true">{{ $t('fix.proposal.refuse') }}</v-btn>
          </div>
          <FieldHelp named id="fix.approve_server" :field="$t('fix.proposal.approve')" />
          <FieldHelp named id="fix.refuse" :field="$t('fix.proposal.refuse')" />
          <p v-if="approving" class="m-voice m-sprop__busy" role="status">
            <v-progress-circular indeterminate size="16" width="2" color="primary" />
            {{ $t('srvfix.approving') }}
          </p>
          <p v-else-if="needsSnap && !server.snapshot_done" class="m-muted m-small">{{ $t('srvfix.approve_snapshot_first') }}</p>
          <p v-else class="m-muted m-small">{{ $t(server.executor === 'michel' ? 'srvfix.approve_hint.michel' : 'srvfix.approve_hint.user') }}</p>
        </template>

        <!-- Approved, for the user to run. -->
        <div v-if="attempt.state === 'approved' && server.executor === 'user'" class="m-sprop__user">
          <h3 class="m-sprop__label">{{ $t('srvfix.user.title') }}</h3>
          <p class="m-small">{{ $t('srvfix.user.body') }}</p>
          <p v-if="server.run_as_root" class="m-small m-sprop__warn">{{ $t('srvfix.user.root') }}</p>
          <div class="m-sprop__actions">
            <v-btn v-if="scripts" size="small" variant="tonal" @click="copy(scripts.apply, 'apply')">{{ $t('srvfix.copy') }} — {{ $t('srvfix.script.apply') }}</v-btn>
            <v-btn color="primary" variant="flat" size="small" :loading="acting === 'applied'" :disabled="!!acting" @click="$emit('applied')">{{ $t('srvfix.applied') }}</v-btn>
          </div>
          <p v-if="acting === 'applied'" class="m-voice m-small" role="status">{{ $t('srvfix.applying') }}</p>
          <!-- R62: the same script, run by Michel, once the server's settings allow it; else what to do. -->
          <template v-if="handOver === 'ready'">
            <p class="m-small">{{ $t('srvfix.handover.ready') }}</p>
            <div class="m-sprop__actions">
              <v-btn size="small" variant="tonal" color="primary" :loading="acting === 'handover'" :disabled="!!acting" @click="handOverOpen = true">{{ $t('srvfix.handover.action') }}</v-btn>
            </div>
            <p v-if="acting === 'handover'" class="m-voice m-small" role="status">{{ $t('srvfix.handover.busy') }}</p>
          </template>
          <p v-else-if="handOver === 'settings'" class="m-small">
            {{ $t('srvfix.handover.settings') }}
            <a :href="serverHref">{{ $t('srvfix.handover.settings_link') }}</a>
          </p>
        </div>
        <p v-else-if="attempt.state === 'approved' && attempt.approved_by === 'auto'" class="m-voice">{{ $t('srvfix.auto') }}</p>
        <p v-else-if="attempt.state === 'approved'" class="m-voice">{{ $t('srvfix.approved') }}</p>
        <p v-if="attempt.state === 'running'" class="m-voice" role="status">
          <v-progress-circular indeterminate size="16" width="2" color="primary" />
          {{ $t('srvfix.running') }}
        </p>

        <!-- Outcome unknown: the user checks the server, then says so. -->
        <v-alert v-if="attempt.state === 'unknown'" type="warning" variant="tonal" density="comfortable" class="m-sprop__alert">
          <p class="m-sprop__strong">{{ $t('srvfix.unknown.title') }}</p>
          <p class="m-small">{{ $t('srvfix.unknown.body') }}</p>
          <v-btn size="small" variant="flat" color="primary" class="m-sprop__alert-btn" :loading="acting === 'resolve'" :disabled="!!acting" @click="$emit('resolve')">
            {{ $t('srvfix.unknown.resolve') }}
          </v-btn>
        </v-alert>

        <!-- A package upgrade that went wrong: restore the snapshot. -->
        <v-alert v-if="restoreNow" type="error" variant="tonal" density="comfortable" class="m-sprop__alert" role="alert">
          <p class="m-sprop__strong">{{ $t('srvfix.restore.title') }}</p>
          <p class="m-small">{{ $t('srvfix.restore.body') }}</p>
        </v-alert>

        <p v-if="attempt.cause" class="m-small">{{ $t('fix.chat.cause', { cause: attempt.cause }) }}</p>
        <p v-if="server.judge_source" class="m-small"><a href="#/sources">{{ $t('servers.sheet.source_open') }}</a></p>
        <p v-if="doneText" class="m-sprop__done m-voice">{{ doneText }}</p>

        <section class="m-sprop__sub">
          <h3 class="m-sprop__label">{{ $t('srvfix.rollback') }}</h3>
          <p class="m-small">{{ $t(needsSnap ? 'srvfix.rollback.package' : 'srvfix.rollback.config') }}</p>
        </section>

        <v-btn v-if="scripts && !$ui.advanced && !showScripts" variant="text" size="small" class="m-sprop__see" @click="showScripts = true">
          {{ $t('srvfix.see_script') }}
        </v-btn>
        <details v-if="scripts && ($ui.advanced || showScripts)" class="m-sprop__detail" :open="showScripts || undefined">
          <summary>{{ $t('srvfix.scripts') }}</summary>
          <div v-for="s in scriptList" :key="s.key" class="m-sprop__script">
            <div class="m-sprop__script-head">
              <h3 class="m-sprop__label">{{ $t(`srvfix.script.${s.key}`) }}</h3>
              <v-btn size="x-small" variant="tonal" @click="copy(s.text, s.key)">{{ $t('srvfix.copy') }}</v-btn>
            </div>
            <pre class="m-code m-sprop__pre">{{ s.text }}</pre>
          </div>
          <p v-if="$ui.advanced" class="m-muted m-small">{{ $t('fix.proposal.hash', { hash: shortHash }) }}</p>
        </details>
        <p v-if="server.scripts_unreadable" class="m-sprop__warn m-small" role="alert">{{ $t('srvfix.scripts_unreadable') }}</p>
        <p v-if="copied" class="m-small m-sprop__ok" role="status">{{ copied }}</p>

        <section v-if="backupLines.length || serverBackups.length" class="m-sprop__sub">
          <h3 class="m-sprop__label">{{ $t('srvfix.backups') }}</h3>
          <ul class="m-sprop__list m-small">
            <li v-for="b in serverBackups" :key="`s:${b}`" class="m-code">{{ $t('srvfix.backup_server', { line: b }) }}</li>
            <li v-for="(b, i) in backupLines" :key="`w:${i}`">{{ b }}</li>
          </ul>
          <p v-if="showBackupHint" class="m-muted m-small">{{ $t('srvfix.backup_hint') }}</p>
        </section>

        <v-btn v-if="canAgain" size="small" variant="tonal" color="primary" class="m-sprop__again" :loading="acting === 'again'" :disabled="!!acting" @click="$emit('again')">
          {{ $t('srvfix.again') }}
        </v-btn>
      </template>
      <p v-else class="m-muted">{{ attempt.state === 'preparing' ? preparingLine : $t('fix.proposal.none_idle') }}</p>
    </section>

    <v-dialog v-model="handOverOpen" max-width="480">
      <v-card aria-labelledby="sfix-handover-title">
        <v-card-title id="sfix-handover-title" class="m-sprop__dialog-title">{{ $t('srvfix.handover.title') }}</v-card-title>
        <v-card-text>
          <p class="m-sprop__dialog-body">{{ $t(server.run_as_root ? 'srvfix.handover.body' : 'srvfix.handover.body_plain') }}</p>
        </v-card-text>
        <v-card-actions class="m-sprop__dialog-actions">
          <v-btn variant="text" @click="handOverOpen = false">{{ $t('srvfix.handover.no') }}</v-btn>
          <v-btn color="primary" variant="flat" @click="doHandOver">{{ $t('srvfix.handover.yes') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog v-model="refuseOpen" max-width="440">
      <v-card aria-labelledby="sfix-refuse-title">
        <v-card-title id="sfix-refuse-title" class="m-sprop__dialog-title">{{ $t('fix.refuse.title') }}</v-card-title>
        <v-card-text>
          <p class="m-sprop__dialog-body">{{ $t('fix.refuse.body') }}</p>
          <v-textarea v-model="reason" :label="$t('fix.refuse.reason')" rows="2" auto-grow counter="500" maxlength="500" hide-details="auto" />
        </v-card-text>
        <v-card-actions class="m-sprop__dialog-actions">
          <v-btn variant="text" @click="refuseOpen = false">{{ $t('fix.refuse.keep') }}</v-btn>
          <v-btn color="error" variant="flat" @click="refuse">{{ $t('fix.proposal.refuse') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </aside>
</template>

<script>
import FieldHelp from './FieldHelp.vue'
import { formatDate, severityOf } from '../lib/digestView.js'
import { canPrepareServer, isGone } from '../lib/pathView.js'
import { backupLine, canApproveServer, doneKey, envLabel, findingTitle, handOverOf, needsSnapshot, restoreNeeded, serverAttemptLine, serversHash } from '../lib/serversView.js'

// ServerProposal is the right of the Fix page for a fix of a server: the
// flaw in plain words, then the proposal: its sentence, « réduit le risque,
// ne corrige pas » for a mitigation, the snapshot step before a package
// upgrade (« Snapshot fait »), Valider / Refuser, « J'ai appliqué » when
// the user runs the script, the way back said plainly, « Voir les scripts »
// folded with « Copier », the copies of the files, and for a fix of unknown
// outcome the button that says the user checked the server.
export default {
  name: 'ServerProposal',
  components: { FieldHelp },
  props: {
    attempt: { type: Object, required: true },
    // flaw is the finding as the server's sheet lists it (TargetFindingView), or null.
    flaw: { type: Object, default: null },
    // target is the server's sheet (TargetView), or null.
    target: { type: Object, default: null },
    approving: { type: Boolean, default: false },
    refusing: { type: Boolean, default: false },
    // acting is the action running: snapshot, applied, resolve, again ('' for none).
    acting: { type: String, default: '' },
    updated: { type: Boolean, default: false },
  },
  emits: ['approve', 'refuse', 'snapshot', 'applied', 'handover', 'resolve', 'again'],
  data() {
    // showScripts opens the scripts in the simple mode.
    return { refuseOpen: false, reason: '', copied: '', showScripts: false, handOverOpen: false }
  },
  computed: {
    lang() {
      return this.$ui.lang
    },
    p() {
      return this.attempt.proposal || null
    },
    server() {
      return this.attempt.server || { target: { id: '', name: '' } }
    },
    flawView() {
      return this.flaw || {}
    },
    severity() {
      return severityOf(this.flawView.severity || this.attempt.finding?.severity)
    },
    flawTitle() {
      const f = this.flaw || { rule: this.attempt.finding?.osv_id, title: this.attempt.finding?.summary, package: this.attempt.finding?.package }
      return findingTitle(f, this.lang)
    },
    // handOver: 'ready' (Michel can run the validated script now), 'settings' (not yet), or ''.
    handOver() {
      return handOverOf(this.attempt)
    },
    serverHref() {
      return serversHash(this.server.target.id)
    },
    envText() {
      return envLabel(this.target?.env, this.lang)
    },
    needsSnap() {
      return needsSnapshot(this.server)
    },
    approvable() {
      return canApproveServer(this.attempt, this.p)
    },
    scripts() {
      return this.server.scripts || null
    },
    scriptList() {
      if (!this.scripts) return []
      return [{ key: 'apply', text: this.scripts.apply }, { key: 'undo', text: this.scripts.undo }].filter((s) => s.text)
    },
    shortHash() {
      return String(this.p?.hash || '').slice(0, 12)
    },
    steps() {
      return this.server.steps || []
    },
    // restoreNow: a package upgrade failed, or the site went down after it.
    restoreNow() {
      return restoreNeeded(this.attempt)
    },
    serverBackups() {
      return this.server.backup_list || []
    },
    backupLines() {
      return (this.server.backups || []).map((b) => backupLine(b, this.lang))
    },
    showBackupHint() {
      return ['failed', 'unknown'].includes(this.attempt.state) && this.serverBackups.length > 0
    },
    doneText() {
      const key = doneKey(this.attempt)
      return key ? this.$t(key) : ''
    },
    preparingLine() {
      return serverAttemptLine(this.attempt, this.lang)
    },
    // canAgain: once the server's sheet is there, the guide above holds this button with its plan.
    canAgain() {
      return !this.target && ['failed', 'refused', 'inconclusive'].includes(this.attempt.state) && canPrepareServer(this.attempt, isGone(this.attempt.finding, null))
    },
  },
  watch: {
    'attempt.id'() {
      this.refuseOpen = false
      this.handOverOpen = false
      this.reason = ''
      this.copied = ''
    },
  },
  methods: {
    dateText(iso) {
      return formatDate(iso, this.lang) || '?'
    },
    /** copy puts a script on the clipboard, exactly as validated. */
    async copy(text) {
      this.copied = ''
      try {
        await navigator.clipboard.writeText(text)
        this.copied = this.$t('srvfix.copied')
      } catch {
        this.copied = this.$t('srvfix.copy_failed')
      }
    },
    /** doHandOver is the click that lets Michel run the script the person validated: the hash is the one they approved. */
    doHandOver() {
      this.handOverOpen = false
      this.$emit('handover', this.p?.hash || '')
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
.m-sprop { display: grid; gap: 1.5rem; align-content: start; min-width: 0; }
.m-sprop__block { display: grid; gap: 0.6rem; }
.m-sprop__block p { margin: 0; line-height: 1.55; }
.m-sprop__title { font-family: var(--m-voice); font-size: 1.25rem; font-weight: 600; margin: 0; }
.m-sprop__id { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem 0.75rem; }
.m-sprop__label { font-size: 0.85rem; font-weight: 650; margin: 0.4rem 0 0.15rem; color: rgba(var(--v-theme-on-surface), 0.72); }
.m-sprop__sentence { font-size: 1.04rem; line-height: 1.55; }
.m-sprop__main { font-size: 1.12rem; }
.m-sprop__strong { font-weight: 650; }
.m-sprop__note { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgba(var(--v-theme-info), 0.12); }
.m-sprop__warn { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgba(var(--v-theme-warning), 0.12); }
.m-sprop__snap { display: grid; gap: 0.4rem; justify-items: start; padding: 0.6rem 0.75rem; border-radius: 8px; border: 1px solid rgba(var(--v-theme-warning), 0.5); }
.m-sprop__snap--done { border-color: rgba(var(--v-theme-success), 0.5); }
.m-sprop__user { display: grid; gap: 0.4rem; padding: 0.6rem 0.75rem; border-radius: 8px; background: rgba(var(--v-theme-primary), 0.08); }
.m-sprop__ok { color: rgb(var(--v-theme-success)); }
.m-sprop__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.25rem; }
.m-sprop__busy { display: flex; align-items: center; gap: 0.5rem; }
.m-sprop__alert p + p { margin-top: 0.25rem; }
.m-sprop__alert-btn { margin-top: 0.5rem; }
.m-sprop__done { font-size: 1.05rem; }
.m-sprop__sub { display: grid; gap: 0.25rem; }
.m-sprop__detail summary { cursor: pointer; font-size: 0.9rem; font-weight: 600; color: rgb(var(--v-theme-primary)); padding: 0.25rem 0; }
.m-sprop__script-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
.m-sprop__pre {
  margin: 0.25rem 0 0.5rem;
  padding: 0.6rem 0.75rem;
  border-radius: 8px;
  max-height: 22rem;
  overflow: auto;
  white-space: pre;
  font-size: 0.75rem;
  background: rgba(var(--v-theme-on-surface), 0.05);
}
.m-sprop__list { margin: 0; padding-left: 1.2rem; display: grid; gap: 0.2rem; }
.m-sprop__again { justify-self: start; }
.m-sprop__see { justify-self: start; margin-left: -0.6rem; }
.m-sprop__dialog-title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-sprop__dialog-body { margin: 0 0 0.75rem; }
.m-sprop__dialog-actions { justify-content: flex-end; }
.m-tag { padding: 0 0.45rem; border-radius: 999px; background: rgba(var(--v-theme-on-surface), 0.08); }
.m-tag--hot { background: rgba(var(--v-theme-error), 0.14); color: rgb(var(--v-theme-error)); font-weight: 600; }
</style>
