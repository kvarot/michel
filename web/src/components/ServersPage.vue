<template>
  <div class="m-srv">
    <header class="m-srv__head">
      <h1 class="m-srv__title">{{ $t('servers.title') }}</h1>
      <p class="m-muted m-srv__intro">{{ $t('servers.intro') }}</p>
      <div class="m-srv__actions">
        <v-btn color="primary" variant="flat" @click="openDiscover(false)">{{ $t('servers.find') }}</v-btn>
        <v-btn variant="outlined" @click="openDiscover(true)">{{ $t('servers.add_manual') }}</v-btn>
      </div>
    </header>

    <p v-if="notice" class="m-srv__notice" role="status">{{ notice }}</p>

    <template v-if="route.id">
      <a href="#/servers" class="m-srv__back m-small">← {{ $t('servers.back') }}</a>
      <ServerSheet :id="route.id" :finding="route.finding" @changed="onChanged" @removed="onRemoved" />
    </template>

    <template v-else>
      <p v-if="loading" class="m-muted" role="status">
        <v-progress-circular indeterminate size="18" width="2" color="primary" />
        {{ $t('servers.loading') }}
      </p>
      <div v-else-if="failure" class="m-srv__failure" role="alert">
        <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
        <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
        <v-btn size="small" variant="tonal" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
      </div>
      <section v-else-if="!list.length" class="m-srv__empty">
        <p class="m-voice">{{ $t('servers.empty') }}</p>
        <p class="m-muted">{{ $t('servers.empty_hint') }}</p>
      </section>
      <ul v-else class="m-srv__list" :aria-label="$t('servers.list_label')">
        <li v-for="t in list" :key="t.id">
          <a :href="hrefOf(t)" class="m-srv__item">
            <span class="m-srv__item-top">
              <span class="m-srv__name">{{ t.name }}</span>
              <span class="m-small m-muted">{{ kindText(t) }} · {{ envText(t) }}</span>
            </span>
            <span class="m-voice m-small" :class="{ 'm-srv__hot': t.open_findings > 0 }">{{ sentence(t) }}</span>
            <span v-if="badgesOf(t).length" class="m-srv__badges">
              <span v-for="b in badgesOf(t)" :key="b.key" class="m-tag m-small" :class="{ 'm-tag--hot': b.key !== 'new' }">{{ b.text }}</span>
            </span>
          </a>
        </li>
      </ul>
    </template>

    <v-dialog v-model="discover.open" max-width="640" scrollable>
      <DiscoverServersDialog v-if="discover.open" :manual-only="discover.manual" @close="discover.open = false" @added="onAdded" />
    </v-dialog>

    <v-dialog v-model="hostKey.open" max-width="560" scrollable>
      <HostKeyDialog v-if="hostKey.open && hostKey.target" :target="hostKey.target" @close="nextHostKey" @confirmed="onConfirmed" />
    </v-dialog>
  </div>
</template>

<script>
import DiscoverServersDialog from './DiscoverServersDialog.vue'
import HostKeyDialog from './HostKeyDialog.vue'
import ServerSheet from './ServerSheet.vue'
import { api } from '../api.js'
import { logBadges } from '../lib/serverLogsView.js'
import { envLabel, kindLabel, serversHash, stateSentence } from '../lib/serversView.js'

// ServersPage is the "Serveurs" page: the list of servers (name, kind,
// environment, where it stands in one sentence), "Trouver mes serveurs" and
// "Ajouter à la main", and the sheet of the server the address names
// (#/servers/<id>). After an add, it asks for the fingerprint of each new
// server, one after the other.
export default {
  name: 'ServersPage',
  components: { DiscoverServersDialog, HostKeyDialog, ServerSheet },
  props: {
    route: { type: Object, default: () => ({ id: '' }) },
  },
  emits: ['changed'],
  data() {
    return {
      loading: true,
      failure: null,
      list: [],
      notice: '',
      discover: { open: false, manual: false },
      hostKey: { open: false, target: null, queue: [] },
    }
  },
  computed: {
    lang() {
      return this.$ui.lang
    },
  },
  watch: {
    lang() {
      this.load()
    },
    'route.id'() {
      this.notice = ''
      if (!this.route.id) this.load()
    },
  },
  created() {
    this.load()
  },
  methods: {
    hrefOf(t) {
      return serversHash(t.id)
    },
    kindText(t) {
      return kindLabel(t.kind, this.lang)
    },
    envText(t) {
      return envLabel(t.env, this.lang)
    },
    sentence(t) {
      return stateSentence(t, this.lang)
    },
    badgesOf(t) {
      return logBadges(t, this.lang)
    },
    async load() {
      this.loading = !this.list.length
      this.failure = null
      try {
        this.list = (await api.get(`/targets?lang=${encodeURIComponent(this.lang)}`)) || []
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
      }
    },
    openDiscover(manual) {
      this.notice = ''
      this.discover = { open: true, manual }
    },
    onAdded(added) {
      this.discover.open = false
      this.$emit('changed')
      this.load()
      // Each new server's fingerprint, one after the other.
      this.hostKey.queue = [...added]
      this.nextHostKey()
    },
    nextHostKey() {
      const next = this.hostKey.queue.shift()
      this.hostKey.target = next || null
      this.hostKey.open = !!next
      if (!next && !this.route.id) this.load()
    },
    onConfirmed(v) {
      this.notice = this.$t('servers.hostkey.done')
      if (this.hostKey.queue.length) {
        this.nextHostKey()
        return
      }
      this.hostKey.open = false
      window.location.hash = serversHash(v?.id || this.hostKey.target?.id || '')
    },
    onChanged() {
      this.$emit('changed')
    },
    onRemoved(text) {
      this.notice = text
      this.$emit('changed')
      window.location.hash = '#/servers'
      this.load()
    },
  },
}
</script>

<style scoped>
.m-srv { display: grid; gap: 1.25rem; }
.m-srv p { margin: 0; }
.m-srv__head { display: grid; gap: 0.5rem; }
.m-srv__title { font-family: var(--m-voice); font-size: 2rem; font-weight: 600; margin: 0; }
.m-srv__intro { max-width: 70ch; line-height: 1.5; }
.m-srv__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.25rem; }
.m-srv__notice { padding: 0.5rem 0.75rem; border-radius: 8px; background: rgba(var(--v-theme-success), 0.12); }
.m-srv__back { color: rgb(var(--v-theme-primary)); text-decoration: none; justify-self: start; }
.m-srv__failure { display: grid; gap: 0.4rem; justify-items: start; }
.m-srv__empty { display: grid; gap: 0.4rem; padding: 1rem 0; }
.m-srv__empty .m-voice { font-size: 1.2rem; }
.m-srv__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.6rem; }
.m-srv__item {
  display: grid;
  gap: 0.25rem;
  padding: 0.9rem 1.1rem;
  border-radius: 12px;
  color: inherit;
  text-decoration: none;
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
}
.m-srv__item:hover { border-color: rgba(var(--v-theme-primary), 0.45); }
.m-srv__item-top { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 0.25rem 1rem; }
.m-srv__name { font-weight: 650; font-size: 1.05rem; overflow-wrap: anywhere; }
.m-srv__badges { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.m-tag { padding: 0 0.45rem; border-radius: 999px; background: rgba(var(--v-theme-on-surface), 0.08); }
.m-tag--hot { background: rgba(var(--v-theme-error), 0.14); color: rgb(var(--v-theme-error)); font-weight: 600; }
.m-srv__hot { color: rgb(var(--v-theme-error)); }
</style>
