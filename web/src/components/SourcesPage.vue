<template>
  <div class="m-sources">
    <section class="m-hero" aria-labelledby="sources-title">
      <h1 id="sources-title" class="m-headline">{{ $t('sources.title') }}</h1>
      <p class="m-word">{{ sentence }}</p>
      <div class="m-sources__bar">
        <v-btn color="primary" variant="flat" :loading="updating" @click="updateAll">{{ $t('sources.update_all') }}</v-btn>
        <v-btn variant="tonal" color="primary" @click="adding = true">{{ $t('sources.add') }}</v-btn>
        <v-checkbox v-model="showHidden" :label="$t('sources.show_hidden')" density="compact" hide-details @update:model-value="load" />
      </div>
      <p v-if="updating" class="m-small m-muted" role="status">{{ $t('sources.updating') }}</p>
    </section>

    <v-alert v-if="notice" :type="notice.type" variant="tonal" density="comfortable" class="m-block" closable @click:close="notice = null">
      <p class="m-sources__notice">{{ notice.text }}</p>
      <p v-if="notice.hint" class="m-sources__notice m-small">{{ notice.hint }}</p>
    </v-alert>

    <div v-if="loading && !sources.length" class="m-small m-muted" role="status">{{ $t('sources.loading') }}</div>

    <section v-for="g in groups" :key="g.kind" class="m-kind" :aria-labelledby="`kind-${g.kind}`">
      <h2 :id="`kind-${g.kind}`" class="m-kind__title">{{ $t(`sources.kind.${g.kind}`) }}</h2>
      <p class="m-muted m-small m-kind__hint">{{ $t(`sources.kind_hint.${g.kind}`) }}</p>
      <ul class="m-kind__rows">
        <SourceRow
          v-for="s in g.sources"
          :key="s.key"
          :source="s"
          :now="now"
          :busy="busy === s.key"
          @toggle="toggle"
          @act="act"
        />
      </ul>
    </section>

    <DiscoverList ref="discover" @changed="load" />

    <v-dialog :model-value="!!consent" max-width="560" scrollable persistent @update:model-value="(v) => { if (!v) consent = null }">
      <ConsentDialog
        v-if="consent"
        :name="consent.source.name"
        :consent="consent.list"
        :busy="busy === consent.source.key"
        :error="consent.error"
        @accept="acceptConsent"
        @cancel="consent = null"
      />
    </v-dialog>

    <v-dialog :model-value="!!installing" max-width="680" scrollable persistent @update:model-value="(v) => { if (!v) installing = null }">
      <InstallDialog v-if="installing" :source="installing" @done="installed" @cancel="installing = null" />
    </v-dialog>

    <v-dialog v-model="adding" max-width="560" scrollable>
      <AddSourceForm v-if="adding" @added="added" @cancel="adding = false" />
    </v-dialog>

    <v-dialog :model-value="!!removing" max-width="480" @update:model-value="(v) => { if (!v) removing = null }">
      <v-card v-if="removing" role="alertdialog" aria-labelledby="remove-title">
        <v-card-title id="remove-title" class="m-sources__wrap">{{ $t('sources.remove_confirm.title', { name: removing.name }) }}</v-card-title>
        <v-card-text>{{ $t('sources.remove_confirm.body') }}</v-card-text>
        <v-card-actions class="m-sources__actions">
          <v-btn variant="text" @click="removing = null">{{ $t('common.cancel') }}</v-btn>
          <v-btn color="error" variant="flat" :loading="busy === removing.key" @click="remove(removing, true)">{{ $t('sources.remove_confirm.yes') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog :model-value="!!running" max-width="480" @update:model-value="(v) => { if (!v) stopRun() }">
      <v-card v-if="running" aria-labelledby="run-title">
        <v-card-title id="run-title" class="m-sources__wrap">{{ $t('run.title', { name: running.source.name }) }}</v-card-title>
        <v-card-text>
          <v-select v-model="running.project" :items="projects" :label="$t('run.project')" :disabled="!!running.runId" />
          <p v-if="running.status === 'running'" class="m-small" role="status">{{ $t('run.running', { name: running.source.name }) }}</p>
          <p v-else-if="running.status === 'ok'" class="m-small" role="status">{{ $t('run.ok', { n: running.findings }) }}</p>
          <p v-else-if="running.status === 'failed'" class="m-small m-sources__error" role="alert">{{ $t('run.failed', { error: running.error }) }}</p>
          <p v-if="running.failure" class="m-small m-sources__error" role="alert">{{ running.failure }}</p>
        </v-card-text>
        <v-card-actions class="m-sources__actions">
          <v-btn variant="text" @click="stopRun">{{ $t('app.close') }}</v-btn>
          <v-btn color="primary" variant="flat" :disabled="!running.project || !!running.runId" @click="startRun">{{ $t('run.start') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
import AddSourceForm from './AddSourceForm.vue'
import ConsentDialog from './ConsentDialog.vue'
import DiscoverList from './DiscoverList.vue'
import InstallDialog from './InstallDialog.vue'
import SourceRow from './SourceRow.vue'
import { api } from '../api.js'
import { agoText, groupByKind, summary } from '../lib/sourcesView.js'

export default {
  name: 'SourcesPage',
  components: { AddSourceForm, ConsentDialog, DiscoverList, InstallDialog, SourceRow },
  emits: ['changed'],
  data() {
    return {
      sources: [], loading: true, showHidden: false, now: new Date(), busy: '', notice: null, updating: false,
      consent: null, installing: null, adding: false, removing: null, running: null, projects: [], timer: null,
    }
  },
  computed: {
    groups() {
      return groupByKind(this.sources)
    },
    sentence() {
      const s = summary(this.sources)
      const parts = [this.$t('sources.summary.on', { n: s.on })]
      if (s.waiting > 0) parts.push(this.$t('sources.summary.waiting', { n: s.waiting }))
      parts.push(s.lastAt ? this.$t('sources.summary.updated', { when: agoText(s.lastAt, this.now, this.$t) }) : this.$t('sources.summary.never'))
      const text = parts.join(', ')
      return `${text.charAt(0).toUpperCase()}${text.slice(1)}.`
    },
  },
  watch: {
    '$ui.lang'() {
      this.load()
    },
  },
  created() {
    this.load()
  },
  beforeUnmount() {
    clearTimeout(this.timer)
  },
  methods: {
    q() {
      return `lang=${encodeURIComponent(this.$ui.lang)}`
    },
    path(s, action = '') {
      return `/sources/${encodeURIComponent(s.key)}${action ? `/${action}` : ''}?${this.q()}`
    },
    /** say shows the outcome of an action: a text, or the server's {error, hint}. */
    say(type, text, hint = '') {
      this.notice = { type, text, hint }
    },
    failed(err) {
      if (err?.status === 401) return
      this.say('error', err?.offline ? this.$t('offline.hint') : err?.error || this.$t('sources.failed'), err?.hint || '')
    },
    async load() {
      this.loading = true
      try {
        this.sources = await api.get(`/sources?${this.q()}${this.showHidden ? '&all=1' : ''}`)
        this.now = new Date()
      } catch (err) {
        this.failed(err)
      } finally {
        this.loading = false
      }
    },
    replace(view) {
      const i = this.sources.findIndex((s) => s.key === view.key)
      if (i >= 0) this.sources.splice(i, 1, view)
      this.$emit('changed')
    },
    async toggle(s, on) {
      this.busy = s.key
      try {
        if (on) this.replace(await api.post(this.path(s, 'enable'), {}))
        else this.replace(await api.post(this.path(s, 'disable'), {}))
      } catch (err) {
        if (err?.status === 409 && Array.isArray(err.data?.consent)) {
          this.consent = { source: s, list: err.data.consent, error: '' }
        } else {
          this.failed(err)
        }
      } finally {
        this.busy = ''
      }
    },
    async acceptConsent() {
      const { source } = this.consent
      this.busy = source.key
      try {
        this.replace(await api.post(this.path(source, 'enable'), { consent: true }))
        this.consent = null
      } catch (err) {
        if (this.consent) this.consent.error = [err?.error || this.$t('sources.failed'), err?.hint].filter(Boolean).join(' ')
      } finally {
        this.busy = ''
      }
    },
    act(action, s) {
      switch (action) {
        case 'disable':
          return this.toggle(s, false)
        case 'update':
          return this.updateOne(s)
        case 'remove':
          if (s.config?.installed) {
            this.removing = s
            return undefined
          }
          return this.remove(s, false)
        case 'reset':
          return this.reset(s)
        case 'install':
        case 'upgrade':
          this.installing = s
          return undefined
        case 'run':
          return this.openRun(s)
        default:
          return undefined
      }
    },
    async updateOne(s) {
      this.busy = s.key
      try {
        const rep = await api.post(this.path(s, 'update'), {})
        if (rep.source) this.replace(rep.source)
        if (rep.failed.length) this.say('warning', this.$t('sources.update_failed', { n: rep.failed.length }))
        else this.say('success', this.$t('sources.done.updated'))
      } catch (err) {
        this.failed(err)
      } finally {
        this.busy = ''
      }
    },
    async updateAll() {
      this.updating = true
      try {
        const rep = await api.post(`/sources/update?${this.q()}`, {})
        await this.load()
        if (rep.failed.length) this.say('warning', this.$t('sources.update_failed', { n: rep.failed.length }))
        else this.say('success', this.$t('sources.update_done'))
      } catch (err) {
        this.failed(err)
      } finally {
        this.updating = false
      }
    },
    async remove(s, confirm) {
      this.busy = s.key
      try {
        const res = await api.del(this.path(s), confirm ? { confirm: true } : undefined)
        this.removing = null
        await this.load()
        this.say('success', this.$t(res.mode === 'hidden' ? 'sources.done.hidden' : 'sources.done.removed'))
        this.$emit('changed')
      } catch (err) {
        // An installed skill or MCP server asks first.
        if (err?.status === 409 && !confirm) this.removing = s
        else this.failed(err)
      } finally {
        this.busy = ''
      }
    },
    async reset(s) {
      this.busy = s.key
      try {
        await api.post(`/sources/reset?${this.q()}`, { key: s.key })
        await this.load()
        this.say('success', this.$t('sources.done.reset'))
      } catch (err) {
        this.failed(err)
      } finally {
        this.busy = ''
      }
    },
    installed(res) {
      this.installing = null
      if (res?.source) this.replace(res.source)
      this.say(res?.warning ? 'warning' : 'success', res?.warning || this.$t('install.done'))
    },
    added(view) {
      this.adding = false
      this.sources.push(view)
      this.say('success', this.$t('add.done'))
    },
    async openRun(s) {
      this.running = { source: s, project: '', runId: '', status: '', findings: 0, error: '', failure: '' }
      try {
        const list = await api.get('/projects')
        this.projects = list.map((p) => p.name)
        if (this.running && this.projects.length === 1) this.running.project = this.projects[0]
      } catch (err) {
        if (this.running && err?.status !== 401) this.running.failure = err?.error || this.$t('sources.failed')
      }
    },
    async startRun() {
      const r = this.running
      r.failure = ''
      try {
        const res = await api.post(this.path(r.source, 'run'), { project: r.project })
        r.runId = res.run_id
        r.status = 'running'
        this.poll()
      } catch (err) {
        if (err?.status !== 401) r.failure = [err?.error || this.$t('sources.failed'), err?.hint].filter(Boolean).join(' ')
      }
    },
    poll() {
      clearTimeout(this.timer)
      this.timer = setTimeout(async () => {
        const r = this.running
        if (!r || !r.runId) return
        try {
          const v = await api.get(`/plugin-runs/${encodeURIComponent(r.runId)}`)
          Object.assign(r, { status: v.status, findings: v.findings, error: v.error })
          if (v.status === 'running') this.poll()
          else this.$emit('changed')
        } catch (err) {
          if (err?.status !== 401) r.failure = err?.error || this.$t('sources.failed')
        }
      }, 1500)
    },
    stopRun() {
      clearTimeout(this.timer)
      this.running = null
    },
  },
}
</script>

<style scoped>
.m-hero { padding-bottom: 1.5rem; }
.m-sources__bar { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.75rem; margin-top: 1rem; }
.m-sources__notice { margin: 0; }
.m-block { margin-bottom: 1.25rem; }
.m-kind {
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
  border-radius: 12px;
  padding: 1rem 1.25rem 0.5rem;
  margin-bottom: 1.25rem;
}
.m-kind__title { font-size: 1.15rem; font-weight: 650; margin: 0; }
.m-kind__hint { margin: 0.2rem 0 0.25rem; }
.m-kind__rows { list-style: none; padding: 0; margin: 0; }
.m-sources__wrap { white-space: normal; }
.m-sources__actions { justify-content: flex-end; }
.m-sources__error { color: rgb(var(--v-theme-error)); }
</style>
