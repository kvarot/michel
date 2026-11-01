<template>
  <v-card class="m-disc" aria-labelledby="discover-title">
    <v-card-title id="discover-title" class="m-disc__title">{{ manualOnly ? $t('servers.discover.manual') : $t('servers.discover.title') }}</v-card-title>
    <v-card-text class="m-disc__body">
      <!-- What adding means, said before anything is ticked. -->
      <v-alert type="info" variant="tonal" density="comfortable" class="m-disc__note">
        <p class="m-disc__strong">{{ $t('servers.discover.authorize') }}</p>
        <p class="m-small">{{ $t('servers.discover.authorize_more') }}</p>
      </v-alert>

      <template v-if="!manualOnly">
        <p v-if="loading" class="m-muted" role="status">
          <v-progress-circular indeterminate size="16" width="2" color="primary" />
          {{ $t('servers.discover.loading') }}
        </p>
        <div v-else-if="failure" role="alert" class="m-disc__failure">
          <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
          <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
          <v-btn size="small" variant="tonal" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
        </div>
        <template v-else>
          <template v-if="fresh.length">
            <p class="m-small">{{ $t('servers.discover.pick') }}</p>
            <ul class="m-disc__list">
              <li v-for="c in candidates" :key="keyOf(c)" class="m-disc__item">
                <v-checkbox
                  v-model="picked"
                  :value="keyOf(c)"
                  :disabled="c.known || busy"
                  color="primary"
                  density="compact"
                  hide-details
                >
                  <template #label>
                    <span class="m-disc__cand">
                      <strong>{{ c.alias || c.host }}</strong>
                      <span class="m-code m-small">{{ c.user }}@{{ c.host }}:{{ c.port }}</span>
                      <span class="m-muted m-small">{{ fromText(c) }}</span>
                      <span v-if="c.projects.length" class="m-muted m-small">{{ $t('servers.discover.projects', { list: c.projects.map((p) => p.project).join(', ') }) }}</span>
                      <span v-if="c.known" class="m-tag m-small">{{ $t('servers.discover.known') }}</span>
                    </span>
                  </template>
                </v-checkbox>
              </li>
            </ul>
          </template>
          <template v-else>
            <p class="m-voice">{{ $t('servers.discover.none') }}</p>
            <p class="m-muted m-small">{{ $t('servers.discover.none_hint') }}</p>
          </template>
        </template>
        <v-btn v-if="!showManual" variant="text" size="small" color="primary" class="m-disc__manual-btn" @click="showManual = true">
          {{ $t('servers.add_manual') }}
        </v-btn>
      </template>

      <section v-if="manualOnly || showManual" class="m-disc__manual" :aria-label="$t('servers.discover.manual')">
        <h3 v-if="!manualOnly" class="m-disc__label">{{ $t('servers.discover.manual') }}</h3>
        <div class="m-disc__grid">
          <v-text-field v-model.trim="manual.host" :label="$t('servers.discover.host')" autocomplete="off" spellcheck="false" hide-details="auto" />
          <v-text-field v-model.trim="manual.user" :label="$t('servers.discover.user')" autocomplete="off" spellcheck="false" hide-details="auto" />
          <v-text-field v-model.number="manual.port" :label="$t('servers.discover.port')" type="number" min="1" max="65535" hide-details="auto" />
          <v-text-field v-model.trim="manual.name" :label="$t('servers.discover.name')" autocomplete="off" hide-details="auto" />
        </div>
        <v-text-field v-model.trim="manual.site" :label="$t('servers.discover.site')" placeholder="https://" autocomplete="off" spellcheck="false" hide-details="auto" />
        <p class="m-muted m-small">{{ $t('servers.discover.key_only') }}</p>
      </section>

      <div class="m-disc__grid">
        <v-select v-model="kind" :items="kindItems" :label="$t('servers.discover.kind')" density="comfortable" variant="outlined" hide-details />
        <v-select v-model="env" :items="envItems" :label="$t('servers.discover.env')" density="comfortable" variant="outlined" hide-details />
      </div>
      <p v-if="kind === 'hds'" class="m-muted m-small">{{ $t('servers.settings.hds_note') }}</p>

      <div v-if="errors.length" class="m-disc__error" role="alert">
        <p>{{ $t('servers.discover.partial') }}</p>
        <ul>
          <li v-for="e in errors" :key="e.name"><strong>{{ e.name }}</strong> — {{ e.text }}<span v-if="e.hint" class="m-muted"> {{ e.hint }}</span></li>
        </ul>
      </div>
    </v-card-text>
    <v-card-actions class="m-disc__actions">
      <v-btn variant="text" :disabled="busy" @click="$emit('close')">{{ $t('servers.discover.cancel') }}</v-btn>
      <v-btn color="primary" variant="flat" :loading="busy" :disabled="busy || !count" @click="add">
        {{ $t('servers.discover.add_n', { n: count }) }}
      </v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
import { api } from '../api.js'
import { envLabel, envs, kindLabel, kinds } from '../lib/serversView.js'

// DiscoverServersDialog is "Trouver mes serveurs": Michel reads the SSH
// configuration and the PhpStorm settings of the projects (POST
// /targets/discover), the user ticks the servers to add; or a server added
// by hand. It says first that adding a server allows Michel to connect to
// it (Michel writes its network rule). The added servers are emitted, so
// the page can ask for their fingerprints.
export default {
  name: 'DiscoverServersDialog',
  props: {
    // manualOnly opens the form for a server added by hand.
    manualOnly: { type: Boolean, default: false },
  },
  emits: ['close', 'added'],
  data() {
    return {
      loading: !this.manualOnly,
      failure: null,
      candidates: [],
      picked: [],
      showManual: false,
      manual: { host: '', user: '', port: 22, name: '', site: '' },
      kind: 'vps',
      env: 'prod',
      busy: false,
      errors: [],
    }
  },
  computed: {
    fresh() {
      return this.candidates.filter((c) => !c.known)
    },
    manualReady() {
      return (this.manualOnly || this.showManual) && !!this.manual.host && !!this.manual.user
    },
    count() {
      return this.picked.length + (this.manualReady ? 1 : 0)
    },
    kindItems() {
      return kinds.map((k) => ({ value: k, title: kindLabel(k, this.$ui.lang) }))
    },
    envItems() {
      return envs.map((e) => ({ value: e, title: envLabel(e, this.$ui.lang) }))
    },
  },
  created() {
    if (!this.manualOnly) this.load()
  },
  methods: {
    q(path) {
      return `${path}?lang=${encodeURIComponent(this.$ui.lang)}`
    },
    keyOf(c) {
      return `${c.alias}|${c.user}@${c.host}:${c.port}`
    },
    fromText(c) {
      return (c.from || []).map((f) => this.$t(`servers.discover.from.${f === 'phpstorm' ? 'phpstorm' : 'ssh_config'}`)).join(', ')
    },
    async load() {
      this.loading = true
      this.failure = null
      try {
        this.candidates = (await api.post(this.q('/targets/discover'))) || []
        if (!this.fresh.length) this.showManual = true
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
      }
    },
    /** add sends POST /targets for each ticked server, then the one typed by hand. */
    async add() {
      if (!this.count || this.busy) return
      this.busy = true
      this.errors = []
      const bodies = []
      for (const c of this.candidates) {
        if (!this.picked.includes(this.keyOf(c))) continue
        bodies.push({
          name: c.alias || c.host, alias: c.alias, host: c.host, port: c.port, user: c.user, kind: this.kind, env: this.env,
          links: (c.projects || []).map((p) => ({ project: p.project, remote_dir: p.remote_dir })),
        })
      }
      if (this.manualReady) {
        const m = this.manual
        const b = { name: m.name || m.host, host: m.host, port: Number(m.port) || 22, user: m.user, kind: this.kind, env: this.env }
        if (m.site) b.site_url = m.site
        bodies.push(b)
      }
      const added = []
      for (const b of bodies) {
        try {
          added.push(await api.post(this.q('/targets'), b))
        } catch (err) {
          if (err?.status === 401) break
          this.errors.push({ name: b.name, text: err?.offline ? this.$t('offline.hint') : err?.error || this.$t('error.generic'), hint: err?.hint || '' })
        }
      }
      this.busy = false
      if (added.length) this.$emit('added', added, this.errors.length > 0)
    },
  },
}
</script>

<style scoped>
.m-disc__title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-disc__body { display: grid; gap: 0.8rem; }
.m-disc__body p { margin: 0; line-height: 1.5; }
.m-disc__note p + p { margin-top: 0.25rem; }
.m-disc__strong { font-weight: 650; }
.m-disc__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.15rem; }
.m-disc__cand { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.15rem 0.6rem; padding: 0.15rem 0; }
.m-disc__manual { display: grid; gap: 0.6rem; }
.m-disc__label { font-size: 0.95rem; font-weight: 650; margin: 0; }
.m-disc__grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.6rem; }
.m-disc__manual-btn { justify-self: start; margin-left: -0.6rem; }
.m-disc__failure { display: grid; gap: 0.4rem; justify-items: start; }
.m-disc__error { color: rgb(var(--v-theme-error)); }
.m-disc__error ul { margin: 0.25rem 0 0; padding-left: 1.2rem; }
.m-disc__actions { justify-content: flex-end; }
.m-tag {
  padding: 0 0.45rem;
  border-radius: 999px;
  background: rgba(var(--v-theme-on-surface), 0.08);
}
</style>
