<template>
  <div class="m-logs">
    <p class="m-small">{{ $t('logs.intro') }}</p>

    <p v-if="loading" class="m-muted m-small" role="status">
      <v-progress-circular indeterminate size="16" width="2" color="primary" />
      {{ $t('logs.loading') }}
    </p>
    <div v-else-if="failure" class="m-logs__error" role="alert">
      <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
      <p v-if="failure.hint" class="m-small">{{ failure.hint }}</p>
      <v-btn size="small" variant="tonal" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
    </div>

    <template v-else>
      <p v-if="notice" class="m-logs__ok m-small" role="status">{{ notice }}</p>
      <div v-if="actionError" class="m-logs__error" role="alert">
        <p>{{ actionError.offline ? $t('offline.hint') : actionError.error || $t('error.generic') }}</p>
        <p v-if="actionError.hint" class="m-small">{{ actionError.hint }}</p>
      </div>

      <!-- The logs Michel reads -->
      <h4 :id="`${uid}-sources`" class="m-sheet__sub">{{ $t('logs.sources.title') }}</h4>
      <p v-if="!sources.length" class="m-muted m-small">{{ $t('logs.sources.none') }}</p>
      <ul v-else class="m-logs__list" :aria-labelledby="`${uid}-sources`">
        <li v-for="s in sourceRows" :key="s.id" class="m-logs__item">
          <p>
            <span :id="`${uid}-src-${s.id}`" class="m-code">{{ s.path }}</span>
            <span v-if="$ui.advanced" class="m-muted m-small"> — {{ formatText(s.format) }}</span>
          </p>
          <v-switch
            :model-value="s.active"
            :label="$t('logs.sources.active')"
            color="primary"
            density="comfortable"
            hide-details
            inset
            :disabled="busy"
            :aria-describedby="`${uid}-src-${s.id}`"
            @update:model-value="(v) => setActive(s, !!v)"
          />
          <p class="m-muted m-small">{{ $t('logs.sources.active_hint') }}</p>
          <p class="m-small">{{ s.state.line }}</p>
          <ul v-if="s.state.unseen.length" class="m-sheet__list m-small">
            <li v-for="u in s.state.unseen" :key="u.what">{{ u.text }}</li>
          </ul>
          <p v-for="n in s.notes" :key="n.kind" class="m-muted m-small">{{ n.text }}</p>
          <p v-if="s.note" class="m-muted m-small">{{ s.note }}</p>
          <p v-for="w in s.channelNotes" :key="w" class="m-logs__warn m-small">{{ w }}</p>
          <div class="m-logs__actions">
            <v-btn size="small" variant="text" color="error" :disabled="busy" :aria-describedby="`${uid}-src-${s.id}`" @click="removing = s">
              {{ $t('logs.sources.remove') }}
            </v-btn>
          </div>
          <p class="m-muted m-small">{{ $t('logs.sources.remove_hint') }}</p>
        </li>
      </ul>

      <!-- Add a log: Michel proposes, the user chooses; "Essayer" shows what would come back -->
      <h4 :id="`${uid}-add`" class="m-sheet__sub">{{ $t('logs.add.title') }}</h4>
      <div class="m-logs__actions">
        <v-btn size="small" variant="tonal" color="primary" :loading="discovering" :disabled="discovering || busy" @click="discover">
          {{ $t('logs.add.find') }}
        </v-btn>
      </div>
      <p class="m-muted m-small">{{ $t('logs.add.find_hint') }}</p>
      <p v-if="discovering" class="m-muted m-small" role="status">{{ $t('logs.add.finding') }}</p>
      <p v-else-if="candidates && !candidates.length" class="m-small" role="status">{{ $t($ui.advanced ? 'logs.add.none' : 'logs.add.none_simple') }}</p>
      <ul v-if="candidates && candidates.length" class="m-logs__list" :aria-labelledby="`${uid}-add`">
        <li v-for="c in candidates" :key="candKey(c)" class="m-logs__item">
          <p>
            <span :id="`${uid}-cand-${domId(candKey(c))}`" class="m-code">{{ c.path }}</span>
            <span v-if="$ui.advanced" class="m-muted m-small"> — {{ formatText(c.format) }}</span>
          </p>
          <p class="m-small">{{ c.text }}</p>
          <p v-if="c.note && !tries[candKey(c)]" class="m-muted m-small">{{ c.note }}</p>
          <p v-if="c.known" class="m-tag m-small m-logs__tag">{{ $t('logs.add.known') }}</p>
          <template v-else>
            <div class="m-logs__actions">
              <v-btn size="small" variant="tonal" color="primary" :loading="trying === candKey(c)" :disabled="!!trying || busy" :aria-describedby="`${uid}-cand-${domId(candKey(c))}`" @click="tryDraft(candKey(c), candDraft(c))">
                {{ $t('logs.add.try') }}
              </v-btn>
              <v-btn size="small" variant="flat" color="primary" :disabled="!!trying || busy" :aria-describedby="`${uid}-cand-${domId(candKey(c))}`" @click="start(candDraft(c))">
                {{ $t('logs.add.start') }}
              </v-btn>
            </div>
            <p class="m-muted m-small">{{ $t('logs.add.try_hint') }} {{ $t('logs.add.start_hint') }}</p>
            <FieldHelp id="logs.try" :field="$t('logs.add.try')" />
          </template>
          <TryResult v-if="tries[candKey(c)]" :result="tries[candKey(c)]" :lang="lang" @close="delete tries[candKey(c)]" />
        </li>
      </ul>

      <p v-if="trying" class="m-muted m-small" role="status">{{ $t('logs.add.trying') }}</p>
      <h5 v-if="$ui.advanced" :id="`${uid}-manual`" class="m-logs__minor">{{ $t('logs.add.manual') }}</h5>
      <form v-if="$ui.advanced" class="m-logs__form" :aria-labelledby="`${uid}-manual`" @submit.prevent="tryDraft('manual', manualDraft)">
        <v-text-field v-model.trim="draft.path" :label="$t('logs.add.path')" :hint="$t('logs.add.path_hint')" persistent-hint autocomplete="off" spellcheck="false" density="compact" />
        <FieldHelp id="logs.path" :field="$t('logs.add.path')" />
        <v-select v-model="draft.format" :items="formatItems" :label="$t('logs.add.format')" :hint="$t('logs.add.format_hint')" persistent-hint density="compact" variant="outlined" class="m-logs__select" />
        <FieldHelp id="logs.format" :field="$t('logs.add.format')" />
        <template v-if="draft.format === 'json'">
          <v-text-field v-model.trim="draft.level_field" :label="$t('logs.add.level_field')" :hint="$t('logs.add.level_field_hint')" persistent-hint autocomplete="off" spellcheck="false" density="compact" />
          <v-text-field v-model.trim="draft.channel_field" :label="$t('logs.add.channel_field')" autocomplete="off" spellcheck="false" hide-details density="compact" />
        </template>
        <v-text-field v-if="draft.format === 'text'" v-model.trim="draft.pattern" :label="$t('logs.add.pattern')" :hint="$t('logs.add.pattern_hint')" persistent-hint autocomplete="off" spellcheck="false" density="compact" />
        <div class="m-logs__actions">
          <v-btn type="submit" size="small" variant="tonal" color="primary" :loading="trying === 'manual'" :disabled="!draft.path || !!trying || busy">{{ $t('logs.add.try') }}</v-btn>
          <v-btn size="small" variant="flat" color="primary" :disabled="!draft.path || !!trying || busy" @click="start(manualDraft)">{{ $t('logs.add.start') }}</v-btn>
        </div>
        <FieldHelp id="logs.try" :field="$t('logs.add.try')" />
        <p class="m-muted m-small">{{ $t('logs.add.try_hint') }} {{ $t('logs.add.start_hint') }}</p>
      </form>
      <TryResult v-if="$ui.advanced && tries.manual" :result="tries.manual" :lang="lang" @close="delete tries.manual" />

      <!-- The errors -->
      <h4 :id="`${uid}-errors`" class="m-sheet__sub">{{ $t('logs.errors.title') }}</h4>
      <p v-if="!sources.length" class="m-muted m-small">{{ $t('logs.errors.no_source') }}</p>
      <p v-else-if="!errors.length" class="m-muted m-small">{{ $t('logs.errors.none') }}</p>
      <ul v-if="errors.length" class="m-sheet__list m-muted m-small">
        <li><strong>{{ $t('logs.errors.seen') }}</strong> : {{ $t('logs.errors.seen_hint') }}</li>
        <li><strong>{{ $t('logs.errors.ignore') }}</strong> : {{ $t('logs.errors.ignore_hint') }}</li>
      </ul>
      <div v-for="g in groups" :key="g.level" class="m-logs__group">
        <h5 class="m-logs__minor"><span class="m-sev" :class="`m-sev--${levelSeverity(g.level)}`">{{ levelText(g.level) }}</span></h5>
        <ul class="m-logs__list" :aria-label="levelText(g.level)">
          <li v-for="e in g.errors" :key="e.id" class="m-logs__item">
            <p :id="`${uid}-err-${e.id}`" class="m-voice">{{ e.type || e.location || $t('logs.errors.unknown') }}</p>
            <p v-if="e.type && e.location" class="m-small m-muted">{{ $t('logs.errors.where', { where: e.location }) }}</p>
            <p class="m-small">
              <span class="m-tag">{{ statusText(e.status) }}</span>
              {{ $t('logs.errors.count', { n: e.total }) }}
            </p>
            <p class="m-muted m-small">{{ $t('logs.errors.when', { first: when(e.first_at), last: when(e.last_at) }) }}</p>
            <p v-if="e.text" class="m-small">{{ e.text }}</p>
            <div class="m-logs__actions">
              <v-btn v-if="$ui.advanced && e.detail" size="small" variant="text" color="primary" :aria-expanded="open === e.id ? 'true' : 'false'" :aria-describedby="`${uid}-err-${e.id}`" @click="toggleDetail(e)">
                {{ open === e.id ? $t('logs.errors.detail_hide') : $t('logs.errors.detail') }}
              </v-btn>
              <v-btn v-if="e.status !== 'seen' && e.status !== 'ignored'" size="small" variant="text" color="primary" :disabled="busy" :aria-describedby="`${uid}-err-${e.id}`" @click="mark(e, 'seen')">
                {{ $t('logs.errors.seen') }}
              </v-btn>
              <v-btn v-if="e.status !== 'ignored'" size="small" variant="text" :disabled="busy" :aria-describedby="`${uid}-err-${e.id}`" @click="mark(e, 'ignored')">
                {{ $t('logs.errors.ignore') }}
              </v-btn>
              <v-btn v-else size="small" variant="text" color="primary" :disabled="busy" :aria-describedby="`${uid}-err-${e.id}`" @click="mark(e, 'seen')">
                {{ $t('logs.errors.unignore') }}
              </v-btn>
            </div>
            <div v-if="$ui.advanced && open === e.id && e.detail" class="m-logs__detail">
              <p class="m-small">{{ $t('logs.errors.detail_help') }}</p>
              <pre class="m-logs__cmd m-code" tabindex="0">{{ e.detail }}</pre>
              <v-btn size="small" variant="tonal" color="primary" @click="copy(e.detail)">{{ $t('logs.copy') }}</v-btn>
              <span v-if="copyNote" class="m-small m-logs__ok" role="status">{{ copyNote }}</span>
            </div>
          </li>
        </ul>
      </div>
      <p v-if="truncated" class="m-muted m-small">{{ $t('logs.errors.truncated', { total }) }}</p>

      <template v-if="settings">
        <!-- When -->
        <h4 :id="`${uid}-interval`" class="m-sheet__sub">{{ $t('logs.interval.title') }}</h4>
        <p class="m-muted m-small">{{ $t('logs.interval.hint') }}</p>
        <v-select
          :model-value="settings.interval"
          :items="intervalItems"
          :aria-labelledby="`${uid}-interval`"
          density="compact"
          variant="outlined"
          hide-details
          class="m-logs__select"
          :disabled="busy"
          @update:model-value="(v) => change({ interval: v })"
        />
        <FieldHelp id="logs.interval" :field="$t('logs.interval.title')" />
        <p v-if="intervalWarn" class="m-logs__warn m-small">{{ intervalWarn }}</p>

        <!-- Who is told -->
        <h4 :id="`${uid}-alerts`" class="m-sheet__sub">{{ $t('logs.alerts.title') }}</h4>
        <p class="m-muted m-small">{{ $t('logs.alerts.hint') }}</p>
        <div class="m-logs__routes">
          <v-select
            v-for="l in levels"
            :key="l"
            :model-value="settings.routes[l]"
            :items="routeItems(l)"
            :label="$t('logs.alerts.level', { level: levelText(l) })"
            density="compact"
            variant="outlined"
            hide-details
            :disabled="busy"
            @update:model-value="(v) => change({ routes: { [l]: v } })"
          />
        </div>
        <v-switch :model-value="settings.sms" :label="$t('logs.alerts.sms')" color="primary" density="comfortable" hide-details inset :disabled="busy" @update:model-value="(v) => change({ sms: !!v })" />
        <p class="m-muted m-small">{{ $t('logs.alerts.sms_hint') }}</p>
        <FieldHelp id="logs.sms" :field="$t('logs.alerts.sms')" />
        <p v-for="w in settingNotes" :key="w" class="m-logs__warn m-small">{{ w }}</p>

        <!-- What Michel keeps -->
        <h4 :id="`${uid}-privacy`" class="m-sheet__sub">{{ $t('logs.privacy.title') }}</h4>
        <p class="m-small">{{ $t('logs.privacy.intro') }}</p>
        <div v-for="g in privacy" :key="g.key" class="m-logs__setting">
          <p :id="`${uid}-p-${g.key}`" class="m-logs__q">{{ $t(`logs.privacy.${g.key}`) }}</p>
          <p v-if="g.key === 'alert_text'" class="m-muted m-small">{{ $t('logs.privacy.alert_text_hint') }}</p>
          <p v-if="g.key === 'retention'" class="m-muted m-small">{{ $t('logs.privacy.retention_hint') }}</p>
          <FieldHelp v-if="g.key === 'store_text'" id="logs.store_text" :field="$t('logs.privacy.store_text')" />
          <FieldHelp v-else-if="g.key === 'alert_text'" id="logs.alert_text" :field="$t('logs.privacy.alert_text')" />
          <FieldHelp v-else-if="g.key === 'retention'" id="logs.retention" :field="$t('logs.privacy.retention')" />
          <v-radio-group
            :model-value="current(g)"
            :aria-labelledby="`${uid}-p-${g.key}`"
            hide-details
            density="comfortable"
            :disabled="busy"
            @update:model-value="(v) => change({ [settingField[g.key]]: v })"
          >
            <v-radio v-for="c in g.choices" :key="String(c.value)" :value="c.value" :label="c.label" :disabled="c.disabled" color="primary" />
          </v-radio-group>
        </div>
        <div v-if="settings.deviations.length" class="m-logs__away" role="status">
          <p class="m-small">{{ $t('logs.privacy.away') }}</p>
          <p v-for="d in settings.deviations" :key="d.code" class="m-small m-muted">{{ d.text }}</p>
          <p v-if="settings.health" class="m-small m-logs__warn">{{ settings.health }}</p>
          <v-btn size="small" variant="tonal" color="primary" :disabled="busy" @click="change({ store_text: false, alert_text: false, retention_days: 90 })">{{ $t('logs.privacy.back') }}</v-btn>
          <p class="m-muted m-small">{{ $t('logs.privacy.back_hint') }}</p>
        </div>
      </template>

      <!-- Erase -->
      <div class="m-logs__erase">
        <v-btn size="small" variant="tonal" color="error" :disabled="busy" @click="purging = true">{{ $t('logs.purge.button') }}</v-btn>
        <p class="m-muted m-small">{{ $t('logs.purge.hint') }}</p>
      </div>
    </template>

    <v-dialog :model-value="!!removing" max-width="480" @update:model-value="(v) => { if (!v) removing = null }">
      <v-card v-if="removing" :aria-labelledby="`${uid}-rm-title`">
        <v-card-title :id="`${uid}-rm-title`" class="m-logs__dialog-title">{{ $t('logs.sources.remove_title') }}</v-card-title>
        <v-card-text>
          <p class="m-code m-small">{{ removing.path }}</p>
          <p>{{ $t('logs.sources.remove_body') }}</p>
        </v-card-text>
        <v-card-actions class="m-logs__dialog-actions">
          <v-btn variant="text" @click="removing = null">{{ $t('logs.cancel') }}</v-btn>
          <v-btn color="error" variant="flat" :loading="busy" @click="removeSource">{{ $t('logs.sources.remove_confirm') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog v-model="purging" max-width="480">
      <v-card :aria-labelledby="`${uid}-purge-title`">
        <v-card-title :id="`${uid}-purge-title`" class="m-logs__dialog-title">{{ $t('logs.purge.title') }}</v-card-title>
        <v-card-text><p>{{ $t('logs.purge.body') }}</p></v-card-text>
        <v-card-actions class="m-logs__dialog-actions">
          <v-btn variant="text" @click="purging = false">{{ $t('logs.cancel') }}</v-btn>
          <v-btn color="error" variant="flat" :loading="busy" @click="purge">{{ $t('logs.purge.confirm') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog :model-value="!!confirm" max-width="540" scrollable @update:model-value="(v) => { if (!v) confirm = null }">
      <v-card v-if="confirm" :aria-labelledby="`${uid}-confirm-title`">
        <v-card-title :id="`${uid}-confirm-title`" class="m-logs__dialog-title">{{ confirm.titles.join(' ') }}</v-card-title>
        <v-card-text>
          <p class="m-logs__lead">{{ $t('logs.confirm.intro') }}</p>
          <p v-for="d in confirm.deviations" :key="d.code">{{ d.text }}</p>
          <p v-if="confirm.health" class="m-logs__warn"><strong>{{ confirm.health }}</strong></p>
        </v-card-text>
        <v-card-actions class="m-logs__dialog-actions">
          <v-btn variant="flat" color="primary" @click="confirm = null">{{ $t('logs.confirm.no') }}</v-btn>
          <v-btn variant="text" :loading="busy" @click="confirmChange">{{ $t('logs.confirm.yes') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
import FieldHelp from './FieldHelp.vue'
import TryResult from './LogTryResult.vue'
import { api } from '../api.js'
import { formatDate } from '../lib/digestView.js'
import {
  channelNotes, deviationWarning, domId, errorGroups, formatLabel, formats, intervalChoices, intervalNote, levelLabel, levelOrder, levelSeverity, settingsSaveOutcome,
  privacyChoices, readState, routeChoices, statusLabel,
} from '../lib/serverLogsView.js'

let counter = 0

// settingField maps a privacy group to the field the API takes.
const settingField = { store_text: 'store_text', alert_text: 'alert_text', retention: 'retention_days' }

// ServerLogs is the "Journaux" block of the server sheet: the logs Michel
// reads (ticked, last read, "non vu"), "Essayer" before reading one, the
// errors grouped by level with "Voir le détail" (a command to copy; Michel
// never runs it), the settings in sentences with the recommended choice first,
// the confirmation when a privacy setting moves away from it, and the erasing
// of the log data. It never shows a log line: text appears only when the API
// returns it.
export default {
  name: 'ServerLogs',
  components: { FieldHelp, TryResult },
  props: {
    id: { type: String, required: true },
    kind: { type: String, default: 'vps' },
    env: { type: String, default: 'prod' },
  },
  emits: ['changed'],
  data() {
    return {
      uid: `m-logs-${++counter}`,
      loading: true,
      failure: null,
      alive: true,
      sources: [],
      errors: [],
      total: 0,
      truncated: false,
      settings: null,
      busy: false,
      notice: '',
      actionError: null,
      candidates: null,
      discovering: false,
      trying: '',
      tries: {},
      draft: { path: '', format: 'php', level_field: 'level', channel_field: '', pattern: '' },
      open: '',
      copyNote: '',
      removing: null,
      purging: false,
      // confirm is a change waiting for the user's yes: {patch, deviations, health, titles}.
      confirm: null,
      now: new Date(),
      loadSeq: 0,
      clock: null,
      levels: levelOrder,
      settingField,
    }
  },
  computed: {
    lang() {
      return this.$ui.lang
    },
    formatItems() {
      return formats.map((f) => ({ value: f, title: formatLabel(f, this.lang) }))
    },
    manualDraft() {
      return { ...this.draft }
    },
    sourceRows() {
      return this.sources.map((s) => ({ ...s, state: readState(s, this.now, this.lang), channelNotes: channelNotes({ noChannel: s.active && s.no_channel }, this.lang), notes: s.notes || [] }))
    },
    groups() {
      return errorGroups(this.errors)
    },
    intervalItems() {
      return intervalChoices(this.settings?.interval, this.lang)
    },
    intervalWarn() {
      return intervalNote(this.settings, this.$ui.advanced, this.lang)
    },
    privacy() {
      return privacyChoices(this.settings, this.kind, this.lang)
    },
    settingNotes() {
      return channelNotes({ sms: !!this.settings?.sms }, this.lang)
    },
  },
  watch: {
    id() {
      this.reset()
      this.load()
    },
    lang() {
      this.load()
    },
  },
  created() {
    this.load()
  },
  mounted() {
    // "il y a X min" must not go stale on a sheet left open.
    this.clock = setInterval(() => {
      this.now = new Date()
    }, 60000)
  },
  beforeUnmount() {
    this.alive = false
    clearInterval(this.clock)
  },
  methods: {
    q(path) {
      return `/targets/${encodeURIComponent(this.id)}/logs${path}${path.includes('?') ? '&' : '?'}lang=${encodeURIComponent(this.lang)}`
    },
    reset() {
      Object.assign(this, { sources: [], errors: [], settings: null, candidates: null, tries: {}, open: '', notice: '', actionError: null, confirm: null })
    },
    levelText(l) {
      return levelLabel(l, this.lang)
    },
    levelSeverity,
    domId,
    formatText(f) {
      return formatLabel(f, this.lang)
    },
    statusText(s) {
      return statusLabel(s, this.lang)
    },
    when(iso) {
      return formatDate(iso, this.lang) || '?'
    },
    candKey(c) {
      return `${c.format}|${c.path}`
    },
    candDraft(c) {
      return { path: c.path, format: c.format }
    },
    routeItems(level) {
      return routeChoices(level, this.env, this.lang)
    },
    current(g) {
      return g.choices.find((c) => c.current)?.value
    },
    /** fail keeps the API's sentence (a busy read says so in plain words); a 401 is the page's business. */
    fail(err) {
      if (err?.status === 401) return
      this.actionError = err
    },
    async load() {
      // Only the newest call counts: a slower, older answer is dropped.
      const seq = ++this.loadSeq
      this.loading = !this.settings
      this.failure = null
      try {
        const [sources, errors, settings] = await Promise.all([
          api.get(this.q('/sources')),
          api.get(this.q('/errors')),
          api.get(this.q('/settings')),
        ])
        if (!this.alive || seq !== this.loadSeq) return
        this.sources = sources || []
        this.errors = errors?.errors || []
        this.total = errors?.total || 0
        this.truncated = !!errors?.truncated
        this.settings = settings
        this.now = new Date()
      } catch (err) {
        if (this.alive && seq === this.loadSeq && err?.status !== 401) this.failure = err
      } finally {
        if (seq === this.loadSeq) this.loading = false
      }
    },
    /** done reloads the block after a change and tells the sheet (its badge). */
    async done(notice = '') {
      this.notice = notice
      await this.load()
      this.$emit('changed')
    },
    begin() {
      this.busy = true
      this.notice = ''
      this.actionError = null
    },
    async setActive(s, active) {
      this.begin()
      try {
        await api.patch(this.q(`/sources/${encodeURIComponent(s.id)}`), { active })
        await this.done(this.$t('logs.sources.saved'))
      } catch (err) {
        this.fail(err)
        await this.load()
      } finally {
        this.busy = false
      }
    },
    async removeSource() {
      const s = this.removing
      this.begin()
      try {
        await api.del(this.q(`/sources/${encodeURIComponent(s.id)}`))
        this.removing = null
        await this.done(this.$t('logs.sources.saved'))
      } catch (err) {
        this.removing = null
        this.fail(err)
      } finally {
        this.busy = false
      }
    },
    async discover() {
      this.discovering = true
      this.actionError = null
      try {
        this.candidates = (await api.post(this.q('/sources/discover'))) || []
      } catch (err) {
        this.fail(err)
      } finally {
        this.discovering = false
      }
    },
    /** body is what the API takes for a log: the empty fields are left out. */
    body(d) {
      const b = { path: d.path, format: d.format }
      if (d.format === 'json') {
        b.level_field = d.level_field || ''
        if (d.channel_field) b.channel_field = d.channel_field
      }
      if (d.format === 'text') b.pattern = d.pattern || ''
      return b
    },
    async tryDraft(key, d) {
      this.trying = key
      this.actionError = null
      delete this.tries[key]
      try {
        this.tries[key] = await api.post(this.q('/sources/try'), this.body(d))
      } catch (err) {
        this.fail(err)
      } finally {
        this.trying = ''
      }
    },
    async start(d) {
      this.begin()
      try {
        await api.post(this.q('/sources'), this.body(d))
        this.tries = {}
        this.candidates = null
        this.draft = { path: '', format: 'php', level_field: 'level', channel_field: '', pattern: '' }
        await this.done(this.$t('logs.add.added'))
      } catch (err) {
        this.fail(err)
      } finally {
        this.busy = false
      }
    },
    async mark(e, status) {
      this.begin()
      try {
        await api.patch(this.q(`/errors/${encodeURIComponent(e.id)}`), { status })
        await this.done()
      } catch (err) {
        this.fail(err)
      } finally {
        this.busy = false
      }
    },
    toggleDetail(e) {
      this.copyNote = ''
      this.open = this.open === e.id ? '' : e.id
    },
    async copy(text) {
      try {
        await navigator.clipboard.writeText(text)
        this.copyNote = this.$t('logs.copied')
        return
      } catch {
        // Some browsers refuse the clipboard API here: the old way still works.
      }
      const box = document.createElement('textarea')
      box.value = text
      box.setAttribute('readonly', '')
      box.style.position = 'fixed'
      box.style.opacity = '0'
      document.body.appendChild(box)
      box.select()
      let ok = false
      try {
        ok = document.execCommand('copy')
      } catch {
        ok = false
      }
      document.body.removeChild(box)
      this.copyNote = ok ? this.$t('logs.copied') : this.$t('logs.copy_failed')
    },
    /**
     * change sends one or several settings. A step away from the recommended
     * choice comes back 409 with the risk: the user is asked, and only a yes
     * sends it again, confirmed.
     */
    async change(patch, confirmed = false) {
      this.begin()
      try {
        const body = confirmed ? { ...patch, confirmed: true } : patch
        this.settings = await api.patch(this.q('/settings'), body)
        this.confirm = null
        await this.done(this.$t('logs.sources.saved'))
      } catch (err) {
        const out = settingsSaveOutcome(err)
        if (out.kind === 'confirm') {
          const local = out.deviations.map((d) => deviationWarning(d.code, this.kind, this.lang))
          this.confirm = {
            patch,
            deviations: out.deviations,
            titles: local.map((w) => w.title),
            health: out.health || local.find((w) => w.health)?.health || '',
          }
        } else {
          this.fail(out.error)
        }
        // The page shows what is saved, not what was tried.
        await this.load()
      } finally {
        this.busy = false
      }
    },
    confirmChange() {
      return this.change(this.confirm.patch, true)
    },
    async purge() {
      this.begin()
      try {
        await api.post(this.q('/purge'), { scope: 'all' })
        this.purging = false
        await this.done(this.$t('logs.purge.done'))
      } catch (err) {
        this.purging = false
        this.fail(err)
      } finally {
        this.busy = false
      }
    },
  },
}
</script>

<style scoped>
.m-logs { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0.7rem; min-width: 0; }
.m-logs > * { min-width: 0; }
.m-logs__item { min-width: 0; }
.m-logs .m-code { overflow-wrap: anywhere; }
.m-logs p { margin: 0; line-height: 1.55; }
.m-sheet__sub { font-size: 0.95rem; font-weight: 650; margin: 0.8rem 0 0; }
.m-sheet__list { margin: 0; padding-left: 1.2rem; display: grid; gap: 0.25rem; }
.m-logs__minor { font-size: 0.9rem; font-weight: 650; margin: 0.4rem 0 0; }
.m-logs__list { grid-template-columns: minmax(0, 1fr); list-style: none; margin: 0; padding: 0; display: grid; gap: 0.9rem; }
.m-logs__item { display: grid; gap: 0.3rem; padding-top: 0.75rem; border-top: 1px solid rgba(var(--v-theme-on-surface), 0.08); }
.m-logs__item:first-child { border-top: 0; padding-top: 0; }
.m-logs__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.75rem; }
.m-logs__form { display: grid; gap: 0.9rem; }
.m-logs__select { max-width: 22rem; }
.m-logs__routes { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(19rem, 100%), 1fr)); gap: 0.6rem; }
.m-logs__setting { display: grid; gap: 0.2rem; }
.m-logs__q { font-weight: 600; }
.m-logs__group { display: grid; gap: 0.5rem; }
.m-logs__away { display: grid; gap: 0.3rem; justify-items: start; padding: 0.75rem 1rem; border-radius: 8px; background: rgba(var(--v-theme-warning), 0.12); }
.m-logs__detail { display: grid; gap: 0.4rem; justify-items: start; }
.m-logs__cmd { margin: 0; max-width: 100%; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; padding: 0.5rem 0.7rem; border-radius: 6px; background: rgba(var(--v-theme-on-surface), 0.06); }
.m-logs__erase { display: grid; gap: 0.3rem; justify-items: start; margin-top: 0.8rem; padding-top: 0.8rem; border-top: 1px solid rgba(var(--v-theme-on-surface), 0.1); }
.m-logs__ok { color: rgb(var(--v-theme-success)); }
.m-logs__warn { color: rgb(var(--v-theme-warning)); font-weight: 600; }
.m-logs__error { display: grid; gap: 0.3rem; justify-items: start; color: rgb(var(--v-theme-error)); }
.m-logs__lead { font-weight: 600; margin-bottom: 0.5rem; }
.m-logs__tag { justify-self: start; }
.m-logs__dialog-title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-logs__dialog-actions { justify-content: flex-end; flex-wrap: wrap; }
.m-tag { padding: 0 0.45rem; border-radius: 999px; background: rgba(var(--v-theme-on-surface), 0.08); }
</style>
