<template>
  <article class="m-sheet" :aria-labelledby="`srv-${id}-title`">
    <p v-if="loading" class="m-muted" role="status">
      <v-progress-circular indeterminate size="18" width="2" color="primary" />
      {{ $t('servers.sheet.loading') }}
    </p>

    <div v-else-if="failure" class="m-sheet__failure" role="alert">
      <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
      <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
      <v-btn size="small" variant="tonal" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
    </div>

    <template v-else-if="view">
      <header class="m-sheet__head">
        <h2 :id="`srv-${id}-title`" class="m-sheet__name">{{ view.name }}</h2>
        <p class="m-sheet__meta m-small">
          <span>{{ kindText }}</span>
          <span>{{ envText }}</span>
          <span v-if="$ui.advanced" class="m-code">{{ view.user }}@{{ view.host }}:{{ view.port }}</span>
        </p>
        <p class="m-voice m-sheet__state">{{ sentence }}</p>
        <div class="m-sheet__actions">
          <v-btn
            color="primary"
            variant="flat"
            size="small"
            :loading="view.checking || checking"
            :disabled="view.checking || checking || !view.active || !view.host_key_pinned"
            @click="check"
          >
            {{ $t('servers.sheet.check') }}
          </v-btn>
          <v-btn v-if="!view.host_key_pinned || keyChanged" variant="tonal" size="small" :color="keyChanged ? 'error' : 'primary'" @click="hostKeyOpen = true">
            {{ $t('servers.sheet.trust') }}
          </v-btn>
          <v-btn variant="text" size="small" @click="removeOpen = true">{{ $t('servers.sheet.remove') }}</v-btn>
        </div>
        <FieldHelp id="server.check" :field="$t('servers.sheet.check')" />
        <p v-if="view.checking || checking" class="m-muted m-small" role="status">{{ $t('servers.sheet.checking') }}</p>
        <v-alert v-if="lastFailure" type="warning" variant="tonal" density="comfortable" class="m-sheet__alert" role="alert">
          <p>{{ lastFailure.error || $t('servers.sheet.last_failed') }}</p>
          <p v-if="lastFailure.hint" class="m-small">{{ lastFailure.hint }}</p>
        </v-alert>
        <v-alert v-if="actionError && !errorFor" type="error" variant="tonal" density="comfortable" class="m-sheet__alert" role="alert" closable @click:close="clearError">
          <p>{{ actionError.offline ? $t('offline.hint') : actionError.error || $t('error.generic') }}</p>
          <p v-if="actionError.hint" class="m-small">{{ actionError.hint }}</p>
          <v-btn v-if="agentOffer" size="small" variant="tonal" color="primary" class="m-sheet__inline-btn" :loading="!!startingFor" @click="startAgent(agentOffer)">
            {{ $t('servers.sheet.ask_agent') }}
          </v-btn>
          <v-btn v-if="unknownAttempt && actionErrorIsUnknown" size="small" variant="text" color="primary" :href="fixHref(unknownAttempt.id)">
            {{ $t('servers.unknown.open') }}
          </v-btn>
        </v-alert>
        <p v-if="notice" class="m-sheet__notice m-small" role="status">{{ notice }}</p>
        <v-alert v-if="view.source_to_enable" type="info" variant="tonal" density="comfortable" class="m-sheet__alert">
          <p>{{ $t('servers.sheet.source', { key: view.source_to_enable }) }}</p>
          <v-btn size="small" variant="text" color="primary" href="#/sources" class="m-sheet__inline-btn">{{ $t('servers.sheet.source_open') }}</v-btn>
        </v-alert>
      </header>

      <section class="m-sheet__block" :aria-labelledby="`srv-${id}-flaws`">
        <h3 :id="`srv-${id}-flaws`" class="m-sheet__title" tabindex="-1">{{ $t('servers.sheet.flaws') }}</h3>
        <p v-if="!cards.length" class="m-muted">{{ view.last_check_at ? $t('servers.sheet.no_flaws') : $t('servers.sheet.no_flaws_unchecked') }}</p>
        <ul v-else class="m-sheet__flaws">
          <li v-for="c in cards" :id="`srv-flaw-${c.finding.id}`" :key="c.key" class="m-sheet__flaw" tabindex="-1">
            <div class="m-sheet__flaw-top">
              <span class="m-sev" :class="`m-sev--${sev(c.finding.severity)}`">{{ $t(`severity.${sev(c.finding.severity)}`) }}</span>
              <span v-if="c.finding.kev" class="m-tag m-tag--hot m-small">{{ $t('servers.sheet.kev') }}</span>
              <span v-if="c.finding.mitigation" class="m-tag m-small">{{ $t('servers.sheet.mitigation') }}</span>
              <span v-if="c.finding.kind === 'server_config'" class="m-code m-small m-muted">{{ c.finding.package }}</span>
            </div>
            <p class="m-voice m-sheet__flaw-title">{{ title(c.finding) }}</p>
            <p v-if="risk(c.finding)" class="m-small">{{ risk(c.finding) }}</p>
            <p v-if="c.runtimes.length" class="m-muted m-small">{{ runtimesText(c) }}</p>
            <p v-if="c.finding.location" class="m-muted m-small">{{ $t('servers.sheet.where', { where: c.finding.location }) }}</p>
            <FailureGuide
              class="m-sheet__guide"
              card
              server
              :attempt="lastAttempt(c)"
              :finding="c.finding"
              :sheet="c.finding"
              :target="view"
              :tried="tried(c)"
              :preprod-health="preprodHealth"
              :preprod-target="preprodView"
              :can-start="!startingFor"
              :starting="startingFor === c.finding.id"
              @start="fix(c.finding)"
            />
            <div v-if="lastAttempt(c)" class="m-sheet__flaw-actions">
              <v-btn size="small" variant="tonal" color="primary" :href="fixHref(lastAttempt(c).id)">{{ $t('servers.sheet.fix_open') }}</v-btn>
              <span v-if="cardText(c)" class="m-small m-voice">{{ cardText(c) }}</span>
            </div>
            <p v-if="provenNote(c)" class="m-small m-voice">{{ provenNote(c) }}</p>
            <!-- The answer of "Corriger" stays next to the card it was asked for. -->
            <v-alert v-if="actionError && errorFor === c.finding.id" type="error" variant="tonal" density="comfortable" class="m-sheet__alert" role="alert" closable @click:close="clearError">
              <p>{{ actionError.offline ? $t('offline.hint') : actionError.error || $t('error.generic') }}</p>
              <p v-if="actionError.hint" class="m-small">{{ actionError.hint }}</p>
              <v-btn v-if="agentOffer" size="small" variant="tonal" color="primary" class="m-sheet__inline-btn" :loading="!!startingFor" @click="startAgent(agentOffer)">
                {{ $t('servers.sheet.ask_agent') }}
              </v-btn>
              <v-btn v-if="unknownAttempt && actionErrorIsUnknown" size="small" variant="text" color="primary" :href="fixHref(unknownAttempt.id)">
                {{ $t('servers.unknown.open') }}
              </v-btn>
            </v-alert>
          </li>
        </ul>
        <p v-if="cards.length && view.fix_level === 0" class="m-muted m-small">{{ $t('servers.sheet.fix_report_only') }}</p>
        <p v-if="cards.length && view.fix_level === 3 && !cards.some(planOnCard)" class="m-muted m-small">{{ level3Warn }}</p>
      </section>

      <section class="m-sheet__block" :aria-labelledby="`srv-${id}-logs`">
        <h3 :id="`srv-${id}-logs`" class="m-sheet__title">{{ $t('logs.title') }}</h3>
        <ul v-if="logBadgeList.length" class="m-sheet__badges" :aria-label="$t('logs.title')">
          <li v-for="b in logBadgeList" :key="b.key" class="m-tag m-small" :class="{ 'm-tag--hot': b.key !== 'new' }">{{ b.text }}</li>
        </ul>
        <ServerLogs :id="id" :kind="view.kind" :env="view.env" @changed="refreshView" />
      </section>

      <section class="m-sheet__block" :aria-labelledby="$ui.advanced ? `srv-${id}-seen` : undefined">
        <h3 v-if="$ui.advanced" :id="`srv-${id}-seen`" class="m-sheet__title">{{ $t('servers.sheet.seen') }}</h3>
        <p v-if="$ui.advanced && !inv" class="m-muted">{{ $t('servers.sheet.seen_none') }}</p>
        <ul v-else-if="$ui.advanced" class="m-sheet__list m-small">
          <li v-if="inv.os.pretty || inv.os.id">
            {{ $t('servers.sheet.os', { os: inv.os.pretty || `${inv.os.id} ${inv.os.version_id}` }) }}<span v-if="inv.os.kernel">, {{ $t('servers.sheet.kernel', { kernel: inv.os.kernel }) }}</span>
          </li>
          <li v-for="p in inv.php" :key="`${p.sapi}|${p.binary}`">
            {{ $t('servers.sheet.php', { version: p.version || '?', sapi: p.sapi, binary: p.binary }) }} —
            {{ p.from_package ? $t('servers.sheet.php_package', { pkg: p.from_package }) : $t('servers.sheet.php_built') }}<span v-if="p.loaded_ini">, {{ $t('servers.sheet.php_ini', { ini: p.loaded_ini }) }}</span>
          </li>
          <li v-for="w in inv.web_servers" :key="w.name">{{ $t('servers.sheet.web', { name: w.name, version: w.version }) }}</li>
          <li v-if="inv.packages.length">{{ $t('servers.sheet.packages', { n: inv.packages.length }) }}</li>
        </ul>
        <details v-if="$ui.advanced && inv && inv.directives.length" class="m-sheet__details">
          <summary class="m-small">{{ $t('servers.sheet.directives') }}</summary>
          <ul class="m-sheet__list m-small">
            <li v-for="(d, i) in inv.directives" :key="`${d.sapi}|${d.name}|${i}`">
              <span class="m-code">{{ d.name }} = {{ d.secret ? d.value_text : d.value }}</span>
              <span class="m-muted"> ({{ d.sapi }}<template v-if="d.file">, {{ d.file }}<template v-if="d.line">:{{ d.line }}</template></template>)</span>
            </li>
          </ul>
        </details>
        <component :is="$ui.advanced ? 'h4' : 'h3'" :class="$ui.advanced ? 'm-sheet__sub' : 'm-sheet__title'">{{ $t('servers.sheet.projects') }}</component>
        <p v-if="!(view.projects || []).length" class="m-muted m-small">{{ $t('servers.sheet.no_projects') }}</p>
        <ul v-else class="m-sheet__list m-small">
          <li v-for="p in view.projects" :key="p.project">{{ $t('servers.sheet.project_dir', { project: p.project, dir: p.remote_dir }) }}</li>
        </ul>
      </section>

      <section class="m-sheet__block" :aria-labelledby="`srv-${id}-unseen`">
        <h3 :id="`srv-${id}-unseen`" class="m-sheet__title">{{ $t('servers.sheet.unseen') }}</h3>
        <p v-if="!(view.unseen || []).length" class="m-muted m-small">{{ inv ? $t('servers.sheet.unseen_none') : $t('servers.sheet.seen_none') }}</p>
        <template v-else>
          <ul class="m-sheet__list m-small">
            <li v-for="(u, i) in view.unseen" :key="`${u.what}|${i}`"><span class="m-code">{{ u.what }}</span> — {{ u.reason }}</li>
          </ul>
          <p class="m-muted m-small">{{ $t('servers.sheet.unseen_hint') }}</p>
        </template>
      </section>

      <section v-if="$ui.advanced" class="m-sheet__block" :aria-labelledby="`srv-${id}-history`">
        <h3 :id="`srv-${id}-history`" class="m-sheet__title">{{ $t('servers.sheet.history') }}</h3>
        <p v-if="!history.length" class="m-muted m-small">{{ $t('servers.sheet.history_none') }}</p>
        <ul v-else class="m-sheet__list m-small">
          <li v-for="h in history" :key="h.key">
            <a v-if="h.href" :href="h.href">{{ h.text }}</a>
            <template v-else>{{ h.text }}</template>
          </li>
        </ul>
        <template v-if="view.backup_files">
          <p class="m-small">{{ $t('servers.sheet.backups', { n: view.backup_files, size: sizeText }) }}</p>
        </template>
      </section>

      <p class="m-muted m-small">{{ $t('servers.sheet.backups_server') }}</p>

      <section class="m-sheet__block" :aria-labelledby="`srv-${id}-settings`">
        <h3 :id="`srv-${id}-settings`" class="m-sheet__title">{{ $t('servers.settings.title') }}</h3>

        <h4 :id="`srv-${id}-level`" class="m-sheet__sub">{{ $t('servers.settings.level') }}</h4>
        <v-radio-group :model-value="view.fix_level" :aria-labelledby="`srv-${id}-level`" hide-details density="comfortable" :disabled="saving" @update:model-value="(n) => set('fix_level', n)">
          <v-radio v-for="l in levelList" :key="l.n" :value="l.n" color="primary">
            <template #label><span class="m-sheet__radio"><strong>{{ l.title }}</strong> — {{ l.text }}</span></template>
          </v-radio>
        </v-radio-group>
        <FieldHelp id="server.level" :field="$t('servers.settings.level')" />
        <template v-if="view.fix_level === 3">
          <v-checkbox :model-value="view.auto_config" :label="$t('servers.settings.auto')" color="primary" density="comfortable" hide-details :disabled="saving" @update:model-value="(v) => set('auto_config', !!v)" />
          <p class="m-muted m-small m-sheet__indent">{{ $t('servers.settings.auto_hint') }}</p>
          <FieldHelp id="server.auto" :field="$t('servers.settings.auto')" />
        </template>

        <h4 :id="`srv-${id}-exec`" class="m-sheet__sub">{{ $t('servers.settings.executor') }}</h4>
        <v-radio-group :model-value="view.executor" :aria-labelledby="`srv-${id}-exec`" hide-details density="comfortable" :disabled="saving" @update:model-value="(v) => set('executor', v)">
          <v-radio value="user" color="primary" :label="$t('servers.settings.executor.user')" />
          <v-radio value="michel" color="primary" :label="$t('servers.settings.executor.michel')" />
        </v-radio-group>
        <FieldHelp id="server.executor" :field="$t('servers.settings.executor')" />

        <h4 :id="`srv-${id}-sudo`" class="m-sheet__sub">{{ $t('servers.settings.sudo') }}</h4>
        <v-radio-group :model-value="view.sudo" :aria-labelledby="`srv-${id}-sudo`" hide-details density="comfortable" :disabled="saving" @update:model-value="(v) => set('sudo', v)">
          <v-radio value="none" color="primary" :label="$t('servers.settings.sudo.none')" />
          <v-radio value="nopasswd" color="primary" :label="$t('servers.settings.sudo.nopasswd')" />
        </v-radio-group>
        <FieldHelp id="server.sudo" :field="$t('servers.settings.sudo')" />

        <h4 class="m-sheet__sub">{{ $t('servers.settings.site') }}</h4>
        <p class="m-small">{{ view.site_url ? $t('servers.settings.site_sentence', { url: view.site_url }) : $t('servers.settings.site_none') }}</p>
        <form class="m-sheet__inline" @submit.prevent="set('site_url', site)">
          <v-text-field v-model.trim="site" :label="$t('servers.settings.site')" placeholder="https://" autocomplete="off" spellcheck="false" hide-details="auto" density="compact" />
          <v-btn type="submit" size="small" variant="tonal" color="primary" :disabled="saving || site === (view.site_url || '')">{{ $t('servers.settings.site_save') }}</v-btn>
        </form>
        <FieldHelp id="server.site" :field="$t('servers.settings.site')" />

        <h4 class="m-sheet__sub">{{ $t('servers.settings.interval') }}</h4>
        <p class="m-small">{{ $t('servers.settings.interval_sentence', { when: intervalText }) }}</p>
        <v-select :model-value="intervalValue" :items="intervalItems" :label="$t('servers.settings.interval')" density="compact" variant="outlined" hide-details class="m-sheet__select" :disabled="saving" @update:model-value="(v) => set('check_interval', v)" />
        <FieldHelp id="server.interval" :field="$t('servers.settings.interval')" />

        <template v-if="view.env === 'prod'">
          <h4 class="m-sheet__sub">{{ $t('servers.settings.preprod') }}</h4>
          <p class="m-small">{{ view.preprod ? $t('servers.settings.preprod_sentence', { name: view.preprod.name }) : $t('servers.settings.preprod_empty') }}</p>
          <v-select :model-value="view.preprod ? view.preprod.id : ''" :items="preprodItems" :label="$t('servers.settings.preprod')" density="compact" variant="outlined" hide-details class="m-sheet__select" :disabled="saving" @update:model-value="(v) => set('preprod', v || '')" />
          <FieldHelp id="server.preprod" :field="$t('servers.settings.preprod')" />
        </template>

        <h4 class="m-sheet__sub">{{ $t('servers.settings.kind_env') }}</h4>
        <div class="m-sheet__pair">
          <div>
            <v-select :model-value="view.kind" :items="kindItems" :label="$t('servers.discover.kind')" density="compact" variant="outlined" hide-details :disabled="saving" @update:model-value="(v) => set('kind', v)" />
            <FieldHelp id="server.kind" :field="$t('servers.discover.kind')" />
          </div>
          <div>
            <v-select :model-value="view.env" :items="envItems" :label="$t('servers.discover.env')" density="compact" variant="outlined" hide-details :disabled="saving" @update:model-value="(v) => set('env', v)" />
            <FieldHelp id="server.env" :field="$t('servers.discover.env')" />
          </div>
        </div>
        <p v-if="view.kind === 'hds'" class="m-muted m-small">{{ $t('servers.settings.hds_note') }}</p>
        <v-switch :model-value="view.active" :label="$t('servers.settings.active')" color="primary" density="comfortable" hide-details inset :disabled="saving" @update:model-value="(v) => set('active', !!v)" />
        <FieldHelp id="server.active" :field="$t('servers.settings.active')" />

        <p v-if="saved" class="m-small m-sheet__saved" role="status">{{ $t('servers.settings.saved') }}</p>
        <p v-if="saveError" class="m-small m-sheet__error" role="alert">{{ saveError }}</p>
      </section>

      <section v-if="view.kind !== 'hds'" class="m-sheet__block" :aria-labelledby="`srv-${id}-ai`">
        <h3 :id="`srv-${id}-ai`" class="m-sheet__title">{{ $t('servers.ai.title') }}</h3>
        <p v-if="view.preprod" class="m-small">{{ $t('servers.ai.of_preprod', { name: view.preprod.name }) }}</p>
        <template v-if="consent">
          <p v-if="consent.refusal && !consent.switch_mode" class="m-small">{{ consent.refusal }}</p>
          <template v-else-if="consent.consented">
            <p class="m-small">{{ $t('servers.ai.given', { date: formatDate(consent.given_at), name: consent.target.name }) }}</p>
            <v-btn size="small" variant="text" color="error" class="m-sheet__inline-btn" :loading="consentBusy" @click="revokeConsent">{{ $t('servers.ai.revoke') }}</v-btn>
          </template>
          <template v-else>
            <p class="m-small">{{ $t('servers.ai.missing') }}</p>
            <v-btn size="small" variant="tonal" color="primary" class="m-sheet__inline-btn" @click="openConsent(null)">{{ $t('servers.ai.give') }}</v-btn>
          </template>
        </template>
        <p v-if="consentNotice" class="m-small" role="status">{{ consentNotice }}</p>
      </section>
    </template>

    <v-dialog v-model="hostKeyOpen" max-width="560" scrollable>
      <HostKeyDialog v-if="hostKeyOpen && view" :target="view" @close="hostKeyOpen = false" @confirmed="onConfirmed" />
    </v-dialog>

    <v-dialog v-model="unknownOpen" max-width="500">
      <v-card aria-labelledby="srv-unknown-title">
        <v-card-title id="srv-unknown-title" class="m-sheet__dialog-title">{{ $t('servers.unknown.title') }}</v-card-title>
        <v-card-text><p class="m-sheet__dialog-body">{{ unknownBody }}</p></v-card-text>
        <v-card-actions class="m-sheet__dialog-actions">
          <v-btn variant="text" @click="unknownOpen = false">{{ $t('app.close') }}</v-btn>
          <v-btn color="primary" variant="flat" :href="blockingUnknown ? fixHref(blockingUnknown.id) : undefined" @click="unknownOpen = false">{{ $t('servers.unknown.open') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog v-model="removeOpen" max-width="480">
      <v-card aria-labelledby="srv-remove-title">
        <v-card-title id="srv-remove-title" class="m-sheet__dialog-title">{{ $t('servers.remove.title', { name: view ? view.name : '' }) }}</v-card-title>
        <v-card-text>
          <p class="m-sheet__dialog-body">{{ $t('servers.remove.body') }}</p>
          <div v-if="removeError" class="m-sheet__error" role="alert">
            <p>{{ removeError.error }}</p>
            <p v-if="removeError.hint" class="m-small">{{ removeError.hint }}</p>
            <v-btn v-if="removeError.attempt" size="small" variant="text" color="primary" :href="fixHref(removeError.attempt)">{{ $t('servers.unknown.open') }}</v-btn>
          </div>
        </v-card-text>
        <v-card-actions class="m-sheet__dialog-actions">
          <v-btn variant="text" :disabled="removing" @click="removeOpen = false">{{ $t('servers.remove.keep') }}</v-btn>
          <v-btn color="error" variant="flat" :loading="removing" :disabled="removing" @click="remove">{{ $t('servers.remove.confirm') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog v-model="consentDialog.open" max-width="520" scrollable persistent>
      <AiConsentDialog
        :project="consent ? consent.target.name : ''"
        :lines="consentDialog.lines"
        :switch-mode="consentDialog.switchMode"
        :busy="consentBusy"
        :error="consentDialog.error"
        @accept="giveConsent"
        @cancel="consentDialog.open = false"
      />
    </v-dialog>
  </article>
</template>

<script>
import FieldHelp from './FieldHelp.vue'
import AiConsentDialog from './AiConsentDialog.vue'
import FailureGuide from './FailureGuide.vue'
import HostKeyDialog from './HostKeyDialog.vue'
import ServerLogs from './ServerLogs.vue'
import { api } from '../api.js'
import { formatDate, severityOf } from '../lib/digestView.js'
import { fixHash } from '../lib/fixView.js'
import { plainRisk, showsPlan } from '../lib/pathView.js'
import { logBadges } from '../lib/serverLogsView.js'
import {
  canOfferAgent, cardLine, cardOfFinding, envLabel, envs, findingTitle, healthServer, intervalLabel, intervals, kindLabel, kinds, lastAttemptOf, levelLabel, provenOnlyOnPreprod,
  mergeFindings, serverAttemptLine, serverLevels, sortFindings, stateSentence, triedOnPreprod,
} from '../lib/serversView.js'

// checkEvery is how often the sheet reads the server again while a check runs.
const checkEvery = 3000

// ServerSheet is a server's sheet: where it stands in one sentence, its
// flaws, each on its path, what Michel saw and could not see, the history of
// checks and fixes, the settings in sentences, the AI consent (of the
// preprod when one is linked: its inventory is what leaves) and "Retirer de
// Michel".
export default {
  name: 'ServerSheet',
  components: { AiConsentDialog, FailureGuide, FieldHelp, HostKeyDialog, ServerLogs },
  props: {
    id: { type: String, required: true },
    // finding is the flaw the address names: its card comes into view with the focus.
    finding: { type: String, default: '' },
  },
  emits: ['changed', 'removed'],
  data() {
    return {
      loading: true,
      failure: null,
      view: null,
      inv: null,
      fixes: [],
      // preprodFixes: a server with a preprod starts there first.
      preprodFixes: [],
      others: [],
      consent: null,
      consentBusy: false,
      consentNotice: '',
      consentDialog: { open: false, lines: [], switchMode: false, error: '', then: null },
      checking: false,
      timer: null,
      startingFor: '',
      actionError: null,
      // errorFor is the finding whose "Corriger" got actionError ('' for the header).
      errorFor: '',
      // pollErrors counts the failed reads while a check runs.
      pollErrors: 0,
      agentOffer: null,
      notice: '',
      site: '',
      saving: false,
      saved: false,
      saveError: '',
      hostKeyOpen: false,
      unknownOpen: false,
      removeOpen: false,
      removing: false,
      removeError: null,
      alive: true,
      // focusedFor: the address already served, so that a reload leaves the keyboard alone.
      focusedFor: '',
    }
  },
  computed: {
    lang() {
      return this.$ui.lang
    },
    kindText() {
      return kindLabel(this.view.kind, this.lang)
    },
    envText() {
      return envLabel(this.view.env, this.lang)
    },
    sentence() {
      return stateSentence(this.view, this.lang)
    },
    logBadgeList() {
      return logBadges(this.view, this.lang)
    },
    keyChanged() {
      return this.view?.last_check?.code === 'api.target.hostkey_changed'
    },
    lastFailure() {
      const lc = this.view?.last_check
      return lc && !lc.ok ? lc : null
    },
    flaws() {
      return (this.view?.findings || []).filter((f) => f.status === 'new' || f.status === 'pending' || f.status === 'decided')
    },
    // unknownAttempt is a fix of this server whose outcome Michel cannot tell.
    unknownAttempt() {
      return this.fixes.find((a) => a.state === 'unknown') || null
    },
    // blockingUnknown is what stops a new fix here: StartServer works on the preprod first.
    blockingUnknown() {
      return this.unknownAttempt || this.preprodFixes.find((a) => a.state === 'unknown') || null
    },
    unknownBody() {
      const a = this.blockingUnknown
      if (a && a !== this.unknownAttempt) return this.$t('servers.unknown.body_preprod', { name: a.server?.target?.name || '' })
      return this.$t('servers.unknown.body')
    },
    preprodView() {
      return this.others.find((o) => o.id === this.view?.preprod?.id) || null
    },
    preprodHealth() {
      return healthServer(this.preprodView)
    },
    // cards are the flaws, the most severe first, one card per flaw.
    cards() {
      return mergeFindings(sortFindings(this.flaws), this.inv)
    },
    level3Warn() {
      return levelLabel(3, this.lang).warn
    },
    actionErrorIsUnknown() {
      return this.actionError?.data?.code === 'api.target.busy_unknown'
    },
    history() {
      const out = []
      for (const h of this.view?.history || []) {
        out.push({ key: `c:${h.at}`, at: h.at, text: this.$t('servers.sheet.history_check', { date: this.formatDate(h.at), new: h.new, still: h.still, gone: h.gone }) })
      }
      for (const a of this.fixes) {
        const what = a.proposal?.summary || a.finding?.package || ''
        const state = serverAttemptLine(a, this.lang)
        out.push({ key: `f:${a.id}`, at: a.updated_at || a.created_at, href: this.fixHref(a.id), text: this.$t('servers.sheet.history_fix', { date: this.formatDate(a.updated_at || a.created_at), what, state }) })
      }
      return out.sort((x, y) => String(y.at).localeCompare(String(x.at))).slice(0, 30)
    },
    sizeText() {
      const kb = Math.max(1, Math.round((Number(this.view?.backup_bytes) || 0) / 1024))
      return this.$t('servers.sheet.size_kb', { n: kb })
    },
    levelList() {
      return serverLevels.map((n) => ({ n, ...levelLabel(n, this.lang) }))
    },
    intervalValue() {
      return this.view?.check_interval || '24h'
    },
    intervalText() {
      return intervalLabel(this.view?.check_interval, this.lang)
    },
    intervalItems() {
      const list = [...intervals]
      if (this.view && !list.includes(this.view.check_interval)) list.push(this.view.check_interval)
      return list.map((v) => ({ value: v, title: intervalLabel(v, this.lang) }))
    },
    preprodItems() {
      const items = [{ value: '', title: this.$t('servers.settings.preprod_none') }]
      for (const t of this.others) {
        if (t.id !== this.id && (t.env === 'preprod' || t.env === 'dev')) items.push({ value: t.id, title: t.name })
      }
      return items
    },
    kindItems() {
      return kinds.map((k) => ({ value: k, title: kindLabel(k, this.lang) }))
    },
    envItems() {
      return envs.map((e) => ({ value: e, title: envLabel(e, this.lang) }))
    },
    // consentTarget is the server whose inventory goes to the agent: the
    // preprod when one is linked (a fix is tried there first).
    consentTarget() {
      return this.view?.preprod?.id || this.id
    },
  },
  watch: {
    id() {
      // A check followed on the server shown before stops here.
      clearTimeout(this.timer)
      this.checking = false
      this.pollErrors = 0
      this.clearError()
      this.view = null
      this.load()
    },
    lang() {
      this.load()
    },
    finding() {
      this.focusFinding()
    },
  },
  created() {
    this.load()
  },
  beforeUnmount() {
    this.alive = false
    clearTimeout(this.timer)
  },
  methods: {
    q(path) {
      return `${path}${path.includes('?') ? '&' : '?'}lang=${encodeURIComponent(this.lang)}`
    },
    enc(s) {
      return encodeURIComponent(s)
    },
    sev(s) {
      return severityOf(s)
    },
    title(f) {
      return findingTitle(f, this.lang)
    },
    formatDate(iso) {
      return formatDate(iso, this.lang) || '?'
    },
    fixHref(attemptID) {
      return fixHash({ attempt: attemptID })
    },
    /** lastAttempt is the newest fix of a card's flaws, here or on the preprod, whatever its state: the path starts from it. */
    lastAttempt(c) {
      return lastAttemptOf(this.fixes, c, this.preprodFixes)
    },
    cardText(c) {
      return cardLine(this.lastAttempt(c), this.lang, this.id)
    },
    /** provenNote says a flaw proven on the preprod has no fix prepared here, and what can be done. */
    provenNote(c) {
      const name = provenOnlyOnPreprod(this.fixes, this.preprodFixes, c)
      if (!name) return ''
      return `${this.$t('servers.line.proven_preprod_only', { name })} ${this.$t('servers.line.proven_preprod_only_do')}`
    },
    tried(c) {
      return triedOnPreprod(this.preprodFixes, c)
    },
    /** risk says what a card's flaw means, and nothing when it would only repeat the title. */
    risk(f) {
      const text = plainRisk(f, null, this.lang, this.$ui.advanced)
      return text === this.title(f) ? '' : text
    },
    /** planOnCard: the card shows the plan, so the level 3 warning is next to it. */
    planOnCard(c) {
      return showsPlan(this.lastAttempt(c), false)
    },
    /** focusFinding takes the keyboard and the view to the flaw the address names, once. */
    focusFinding() {
      const want = `${this.id}|${this.finding}`
      if (!this.finding || this.focusedFor === want || !this.view) return
      const c = cardOfFinding(this.cards, this.finding)
      if (!c) return
      this.focusedFor = want
      this.$nextTick(() => {
        const el = document.getElementById(`srv-flaw-${c.finding.id}`)
        if (!el) return
        el.focus({ preventScroll: true })
        el.scrollIntoView({ block: 'start' })
      })
    },
    /**
     * keepFocus: the card about to change holds the keyboard. If what is read
     * takes its button or the card away, the keyboard goes to the flaws' title.
     */
    keepFocus() {
      const el = document.activeElement
      if (!el?.closest?.('.m-sheet__flaws')) return
      this.$nextTick(() => {
        if (!el.isConnected) document.getElementById(`srv-${this.id}-flaws`)?.focus()
      })
    },
    /** focusCard brings back to its card a keyboard lost while a button was disabled. */
    focusCard(id) {
      this.$nextTick(() => {
        const el = document.activeElement
        if (!el || el === document.body) document.getElementById(`srv-flaw-${id}`)?.focus()
      })
    },
    runtimesText(c) {
      const list = c.runtimes.map((r) => (r.binary ? this.$t('servers.sheet.runtime', r) : this.$t('servers.sheet.runtime_nobin', r)))
      return this.$t('servers.sheet.runtimes', { list: list.join(', ') })
    },
    clearError() {
      this.actionError = null
      this.errorFor = ''
      this.agentOffer = null
    },
    async load() {
      this.loading = !this.view
      this.failure = null
      try {
        const v = await api.get(this.q(`/targets/${this.enc(this.id)}`))
        if (!this.alive) return
        this.view = v
        this.site = v.site_url || ''
        await Promise.all([this.loadInventory(), this.loadFixes(), this.loadOthers(), this.loadConsent()])
        if (v.checking) this.follow()
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
        this.$nextTick(this.focusFinding)
      }
    },
    /** refreshView reads the server again: the log badges follow what the Journaux block changed. A failure is shown, not swallowed. */
    async refreshView() {
      try {
        const v = await api.get(this.q(`/targets/${this.enc(this.id)}`))
        if (this.alive) this.view = v
      } catch (err) {
        if (this.alive && err?.status !== 401) {
          this.errorFor = ''
          this.actionError = err
        }
      }
      this.$emit('changed')
    },
    async loadInventory() {
      try {
        this.inv = await api.get(this.q(`/targets/${this.enc(this.id)}/inventory`))
      } catch {
        // Never checked: the sheet says so.
        this.inv = null
      }
    },
    async loadFixes() {
      try {
        const list = (await api.get(this.q(`/fixes?target=${this.enc(this.id)}`))) || []
        const pre = this.view?.preprod?.id
        const onPreprod = pre ? (await api.get(this.q(`/fixes?target=${this.enc(pre)}`))) || [] : []
        this.keepFocus()
        this.fixes = list
        this.preprodFixes = onPreprod
      } catch {
        this.fixes = []
        this.preprodFixes = []
      }
    },
    async loadOthers() {
      try {
        this.others = (await api.get(this.q('/targets'))) || []
      } catch {
        this.others = []
      }
    },
    async loadConsent() {
      if (!this.view || this.view.kind === 'hds') {
        this.consent = null
        return
      }
      try {
        this.consent = await api.get(this.q(`/targets/${this.enc(this.consentTarget)}/ai-consent`))
      } catch {
        // Without the fix service (michel serve not running) there is no consent to show.
        this.consent = null
      }
    },
    /** follow reads the sheet again while a check runs. */
    follow() {
      clearTimeout(this.timer)
      this.timer = setTimeout(async () => {
        if (!this.alive) return
        try {
          const v = await api.get(this.q(`/targets/${this.enc(this.id)}`))
          if (!this.alive) return
          this.keepFocus()
          this.view = v
          if (v.checking) {
            this.follow()
            return
          }
          this.checking = false
          this.pollErrors = 0
          await Promise.all([this.loadInventory(), this.loadFixes()])
          this.$emit('changed')
        } catch (err) {
          this.pollErrors += 1
          // A server gone (removed elsewhere) or a page that keeps failing: stop.
          if (err?.status === 404 || err?.status === 401 || this.pollErrors >= 5) {
            this.checking = false
            if (err?.status !== 401) this.failure = err
            return
          }
          this.follow()
        }
      }, checkEvery)
    },
    async check() {
      this.checking = true
      this.clearError()
      this.notice = ''
      try {
        await api.post(this.q(`/targets/${this.enc(this.id)}/check`))
        this.follow()
      } catch (err) {
        this.checking = false
        if (err?.status !== 401) this.actionError = err
      }
    },
    onConfirmed(v) {
      this.hostKeyOpen = false
      this.view = { ...this.view, ...v }
      this.notice = this.$t('servers.hostkey.done')
      this.$emit('changed')
    },
    /** fix prepares Michel's fix of a finding; a fix of unknown outcome on the server warns first. */
    fix(f) {
      if (this.blockingUnknown) {
        this.unknownOpen = true
        return
      }
      this.startFix(f)
    },
    async startFix(f) {
      this.startingFor = f.id
      this.clearError()
      try {
        const r = await api.post(this.q(`/targets/${this.enc(this.id)}/fix/${this.enc(f.id)}`))
        if (!this.alive) return
        if (r?.attempt) {
          this.$emit('changed')
          window.location.hash = fixHash({ attempt: r.attempt.id })
        }
      } catch (err) {
        if (err?.status === 401) return
        this.actionError = err
        this.errorFor = f.id
        this.focusCard(f.id)
        // No ready-made fix: the agent may study it, where the API would not refuse it.
        if (err?.data?.code === 'fix.server.needs_agent' && canOfferAgent(this.view, this.preprodView)) this.agentOffer = f
      } finally {
        this.startingFor = ''
      }
    },
    async startAgent(f) {
      this.startingFor = f.id
      // The button is in the answer being cleared.
      this.keepFocus()
      this.clearError()
      try {
        const r = await api.post(this.q(`/targets/${this.enc(this.id)}/agent-fix/${this.enc(f.id)}`))
        if (!this.alive) return
        if (r?.attempt) {
          this.$emit('changed')
          window.location.hash = fixHash({ attempt: r.attempt.id })
        }
      } catch (err) {
        if (err?.status === 401) return
        const code = err?.data?.code
        if (err?.status === 409 && code === 'fix.err.consent_required') {
          this.openConsent(() => this.startAgent(f), err.data.consent || [])
          return
        }
        this.actionError = err
        this.errorFor = f.id
        this.focusCard(f.id)
      } finally {
        this.startingFor = ''
      }
    },
    openConsent(then, lines) {
      this.consentDialog = { open: true, lines: lines || this.consent?.lines || [], switchMode: !!this.consent?.switch_mode, error: '', then }
    },
    async giveConsent() {
      this.consentBusy = true
      this.consentDialog.error = ''
      try {
        const body = this.consentDialog.switchMode ? { switch_to_standard: true } : undefined
        this.consent = await api.post(this.q(`/targets/${this.enc(this.consentTarget)}/ai-consent`), body)
        const then = this.consentDialog.then
        this.consentDialog.open = false
        if (then) then()
      } catch (err) {
        this.consentDialog.error = err?.offline ? this.$t('offline.hint') : err?.error || this.$t('error.generic')
      } finally {
        this.consentBusy = false
      }
    },
    async revokeConsent() {
      this.consentBusy = true
      this.consentNotice = ''
      try {
        this.consent = await api.del(this.q(`/targets/${this.enc(this.consentTarget)}/ai-consent`))
        this.consentNotice = this.$t('servers.ai.revoked')
      } catch (err) {
        if (err?.status !== 401) this.consentNotice = err?.error || this.$t('error.generic')
      } finally {
        this.consentBusy = false
      }
    },
    /** set changes one setting (PATCH): the answer is the sheet again. */
    async set(field, value) {
      if (!this.view || this.view[field] === value) return
      this.saving = true
      this.saved = false
      this.saveError = ''
      try {
        const v = await api.patch(this.q(`/targets/${this.enc(this.id)}`), { [field]: value })
        this.view = v
        this.site = v.site_url || ''
        this.saved = true
        if (field === 'preprod' || field === 'kind') this.loadConsent()
        this.$emit('changed')
      } catch (err) {
        if (err?.status === 401) return
        this.saveError = err?.offline ? this.$t('offline.hint') : [err?.error || this.$t('error.generic'), err?.hint].filter(Boolean).join(' ')
      } finally {
        this.saving = false
      }
    },
    async remove() {
      this.removing = true
      this.removeError = null
      try {
        const r = await api.del(this.q(`/targets/${this.enc(this.id)}`))
        this.removeOpen = false
        this.$emit('removed', r?.rules_not_removed ? this.$t('servers.remove.rules_not_removed') : this.$t('servers.remove.done'))
      } catch (err) {
        if (err?.status === 401) return
        // busy, busy_unknown and busy_approved each name their way out.
        const code = err?.data?.code
        let attempt = ''
        if (code === 'api.target.busy_unknown') attempt = this.unknownAttempt?.id || ''
        if (code === 'api.target.busy_approved') attempt = this.fixes.find((a) => a.state === 'approved')?.id || ''
        this.removeError = { error: err?.offline ? this.$t('offline.hint') : err?.error || this.$t('error.generic'), hint: err?.hint || '', attempt }
      } finally {
        this.removing = false
      }
    },
  },
}
</script>

<style scoped>
.m-sheet { display: grid; grid-template-columns: minmax(0, 1fr); gap: 1.5rem; }
.m-sheet p { margin: 0; line-height: 1.55; }
.m-sheet__failure { display: grid; gap: 0.4rem; justify-items: start; }
.m-sheet__head { display: grid; gap: 0.5rem; }
.m-sheet__name { font-family: var(--m-voice); font-size: 1.75rem; font-weight: 600; margin: 0; overflow-wrap: anywhere; }
.m-sheet__meta { display: flex; flex-wrap: wrap; gap: 0.25rem 1rem; }
.m-sheet__state { font-size: 1.15rem; }
.m-sheet__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.m-sheet__alert p + p { margin-top: 0.25rem; }
.m-sheet__inline-btn { margin: 0.25rem 0 0 -0.6rem; }
.m-sheet__notice { color: rgb(var(--v-theme-success)); }
.m-sheet__block {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 0.6rem;
  padding: 1.1rem 1.25rem;
  border-radius: 12px;
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
}
.m-sheet__title { font-size: 1.1rem; font-weight: 650; margin: 0; }
.m-sheet__badges { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 0.4rem; }
.m-sheet__sub { font-size: 0.95rem; font-weight: 650; margin: 0.6rem 0 0; }
.m-sheet__flaws { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.9rem; }
.m-sheet__flaw { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0.3rem; padding-top: 0.75rem; border-top: 1px solid rgba(var(--v-theme-on-surface), 0.08); scroll-margin-top: 1rem; }
.m-sheet__flaw:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 4px; border-radius: 4px; }
.m-sheet__guide { margin-top: 0.4rem; }
.m-sheet__flaw:first-child { border-top: 0; padding-top: 0; }
.m-sheet__flaw-top { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem 0.75rem; }
.m-sheet__flaw-title { font-size: 1.05rem; }
.m-sheet__flaw-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.75rem; margin-top: 0.15rem; }
.m-sheet__list { margin: 0; padding-left: 1.2rem; display: grid; gap: 0.25rem; }
.m-sheet__details summary { cursor: pointer; color: rgb(var(--v-theme-primary)); font-weight: 600; }
.m-sheet__details ul { margin-top: 0.4rem; max-height: 18rem; overflow: auto; }
.m-sheet__radio { line-height: 1.45; padding: 0.2rem 0; }
.m-sheet__indent { margin-left: 2.5rem !important; }
.m-sheet__inline { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.m-sheet__inline .v-text-field { flex: 1 1 16rem; }
.m-sheet__select { max-width: 22rem; }
.m-sheet__pair { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.6rem; }
.m-sheet__saved { color: rgb(var(--v-theme-success)); }
.m-sheet__error { color: rgb(var(--v-theme-error)); }
.m-sheet__dialog-title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-sheet__dialog-body { margin: 0 0 0.75rem; }
.m-sheet__dialog-actions { justify-content: flex-end; flex-wrap: wrap; }
.m-tag { padding: 0 0.45rem; border-radius: 999px; background: rgba(var(--v-theme-on-surface), 0.08); }
.m-tag--hot { background: rgba(var(--v-theme-error), 0.14); color: rgb(var(--v-theme-error)); font-weight: 600; }
</style>
