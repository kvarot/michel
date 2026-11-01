<template>
  <v-app>
    <a class="m-skip" href="#main">{{ $t('app.skip') }}</a>
    <header class="m-top">
      <div class="m-top__row" :class="page === 'fix' ? 'm-wide' : 'm-column'">
        <span class="m-brand">
          <img src="/icons/icon-192.png" alt="" width="28" height="28">
          <span>{{ assistant }}</span>
        </span>
        <v-tabs
          v-if="state === 'ready'"
          :model-value="page"
          density="compact"
          color="primary"
          class="m-top__tabs"
          :aria-label="$t('nav.label')"
          @update:model-value="go"
        >
          <v-tab value="today">{{ $t('nav.today') }}</v-tab>
          <v-tab value="fix">{{ $t('nav.fix') }}</v-tab>
          <v-tab value="servers">{{ $t('nav.servers') }}</v-tab>
          <v-tab value="sources">{{ $t('nav.sources') }}</v-tab>
        </v-tabs>
        <nav class="m-top__actions">
          <v-btn v-if="state === 'ready' && page === 'today'" variant="text" :loading="refreshing" @click="loadToday(true)">{{ $t('app.refresh') }}</v-btn>
          <v-btn variant="text" @click="settingsOpen = true">{{ $t('app.settings') }}</v-btn>
        </nav>
      </div>
    </header>

    <v-main>
      <div id="main" class="m-main" :class="page === 'fix' && state === 'ready' ? 'm-wide' : 'm-column'" tabindex="-1">
        <div v-if="state === 'loading'" class="m-state" role="status">
          <v-progress-circular indeterminate color="primary" size="28" width="3" />
          <p class="m-muted">{{ $t('app.loading') }}</p>
        </div>

        <section v-else-if="state === 'unauthorized'" class="m-state" aria-labelledby="auth-title">
          <h1 id="auth-title" class="m-state__title">{{ $t('auth.title') }}</h1>
          <p>{{ $t('auth.body') }}</p>
          <p class="m-muted m-small">{{ $t('auth.why') }}</p>
          <p v-if="rejected" class="m-auth__rejected" role="alert">{{ $t('auth.rejected') }}</p>
          <form class="m-auth" @submit.prevent="useToken">
            <v-text-field
              v-model="pasted"
              :label="$t('auth.paste')"
              type="password"
              autocomplete="off"
              spellcheck="false"
              hide-details
            />
            <v-btn type="submit" color="primary" variant="flat" :disabled="!pasted.trim()">{{ $t('auth.save') }}</v-btn>
          </form>
        </section>

        <section v-else-if="state === 'offline'" class="m-state" aria-labelledby="offline-title">
          <h1 id="offline-title" class="m-state__title">{{ $t('offline.title') }}</h1>
          <p>{{ $t('offline.hint') }}</p>
          <v-btn color="primary" variant="tonal" @click="load">{{ $t('app.retry') }}</v-btn>
        </section>

        <section v-else-if="state === 'error'" class="m-state" aria-labelledby="error-title">
          <h1 id="error-title" class="m-state__title">{{ $t('error.title') }}</h1>
          <p>{{ failure.error || $t('error.generic') }}</p>
          <p v-if="failure.hint" class="m-muted">{{ failure.hint }}</p>
          <v-btn color="primary" variant="tonal" @click="load">{{ $t('app.retry') }}</v-btn>
        </section>

        <SourcesPage v-else-if="page === 'sources'" @changed="stale = true" />
        <FixPage v-else-if="page === 'fix'" :route="fixRoute" @changed="stale = true" />
        <ServersPage v-else-if="page === 'servers'" :route="serversRoute" @changed="stale = true" />
        <TodayPage v-else :digest="digest" :meta="meta" @decided="loadToday(false)" />
      </div>
    </v-main>

    <v-dialog v-model="settingsOpen" max-width="480" scrollable>
      <SettingsPanel
        :meta="meta"
        :theme="themeName"
        @lang="setLang"
        @theme="setTheme"
        @token-forgotten="onUnauthorized"
        @token-saved="load"
        @close="settingsOpen = false"
      />
    </v-dialog>
  </v-app>
</template>

<script>
import TodayPage from './components/TodayPage.vue'
import SourcesPage from './components/SourcesPage.vue'
import FixPage from './components/FixPage.vue'
import ServersPage from './components/ServersPage.vue'
import SettingsPanel from './components/SettingsPanel.vue'
import { api } from './api.js'
import { keys, save } from './lib/storage.js'
import { fixRoute } from './lib/fixView.js'
import { serversRoute } from './lib/serversView.js'

/** pageOf reads the page from the address hash: #/sources, #/fix…, #/servers…, else today. */
function pageOf(hash) {
  if (hash === '#/sources') return 'sources'
  if (serversRoute(hash)) return 'servers'
  return fixRoute(hash) ? 'fix' : 'today'
}

/** serversOf is the Servers page's {id} in the address ('' for the list). */
function serversOf(hash) {
  return serversRoute(hash) || { id: '' }
}

/** routeOf is the Fix page's {attempt, finding} in the address (empty elsewhere). */
function routeOf(hash) {
  return fixRoute(hash) || { attempt: '', finding: '' }
}

export default {
  name: 'App',
  components: { TodayPage, SourcesPage, FixPage, ServersPage, SettingsPanel },
  data() {
    return {
      state: 'loading', // loading | unauthorized | offline | error | ready
      meta: null,
      digest: null,
      failure: { error: '', hint: '' },
      refreshing: false,
      settingsOpen: false,
      pasted: '',
      // rejected is true when the server refused the token this page holds.
      rejected: false,
      stopListening: null,
      // page follows the address: #/sources, else today (no router).
      page: pageOf(window.location.hash),
      // fixRoute is the attempt or the finding the Fix page shows.
      fixRoute: routeOf(window.location.hash),
      // serversRoute is the server whose sheet the Servers page shows.
      serversRoute: serversOf(window.location.hash),
      // stale is set when the Sources page changed something the Today page shows.
      stale: false,
    }
  },
  computed: {
    assistant() {
      return this.digest?.assistant || this.meta?.assistant || 'Michel'
    },
    themeName() {
      return this.$vuetify.theme.global.name
    },
  },
  watch: {
    '$ui.lang'(lang) {
      document.documentElement.lang = lang
      if (this.state === 'ready') this.loadToday(false)
    },
  },
  created() {
    document.documentElement.lang = this.$ui.lang
    this.stopListening = api.on('unauthorized', this.onUnauthorized)
    window.addEventListener('hashchange', this.onHash)
    this.load()
  },
  beforeUnmount() {
    if (this.stopListening) this.stopListening()
    window.removeEventListener('hashchange', this.onHash)
  },
  methods: {
    onHash() {
      this.page = pageOf(window.location.hash)
      this.fixRoute = routeOf(window.location.hash)
      this.serversRoute = serversOf(window.location.hash)
      if (this.page === 'today' && this.stale && this.state === 'ready') {
        this.stale = false
        this.loadToday(false)
      }
    },
    /** go shows a page by changing the address, so the back button works. */
    go(page) {
      const hashes = { sources: '#/sources', fix: '#/fix', servers: '#/servers' }
      window.location.hash = hashes[page] || '#/'
    },
    onUnauthorized() {
      this.rejected = !!api.token
      this.state = 'unauthorized'
      this.digest = null
    },
    /** fail shows what went wrong: offline, the token, or the server's {error, hint}. */
    fail(err) {
      if (err?.status === 401) return this.onUnauthorized()
      if (err?.offline) {
        this.state = 'offline'
        return
      }
      this.failure = { error: err?.error || '', hint: err?.hint || '' }
      this.state = 'error'
    },
    async load() {
      this.state = 'loading'
      if (!api.token) {
        this.rejected = false
        this.state = 'unauthorized'
        return
      }
      try {
        this.meta = await api.get('/meta')
        if (!this.$ui.langChosen && this.meta?.lang) this.$ui.lang = this.meta.lang === 'fr' ? 'fr' : 'en'
        this.digest = await api.get(`/today?lang=${encodeURIComponent(this.$ui.lang)}`)
        this.state = 'ready'
      } catch (err) {
        this.fail(err)
      }
    },
    /** loadToday computes the digest again; shown says whether the button spins. */
    async loadToday(shown) {
      if (shown) this.refreshing = true
      try {
        this.digest = await api.get(`/today?lang=${encodeURIComponent(this.$ui.lang)}`)
        this.state = 'ready'
      } catch (err) {
        this.fail(err)
      } finally {
        this.refreshing = false
      }
    },
    useToken() {
      api.setToken(this.pasted)
      this.pasted = ''
      this.load()
    },
    setLang(lang) {
      this.$ui.lang = lang
      this.$ui.langChosen = true
      save(keys.lang, lang)
    },
    setTheme(name) {
      const theme = this.$vuetify.theme
      if (typeof theme.change === 'function') theme.change(name)
      else theme.global.name = name
      save(keys.theme, name)
    },
  },
}
</script>

<style scoped>
.m-top {
  border-bottom: 1px solid rgba(var(--v-theme-on-background), 0.1);
  background: rgb(var(--v-theme-background));
}
.m-top__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  min-height: 56px;
}
.m-brand {
  display: inline-flex;
  align-items: center;
  gap: 0.6rem;
  font-family: var(--m-voice);
  font-weight: 600;
  font-size: 1.2rem;
}
.m-brand img { border-radius: 7px; }
.m-top__actions { display: flex; gap: 0.25rem; margin-right: -0.5rem; }
.m-top__tabs { flex: 1 1 auto; min-width: 0; }
.m-main { padding-top: 2.5rem; padding-bottom: 4rem; outline: none; }
.m-state { max-width: 34rem; display: grid; gap: 0.9rem; justify-items: start; padding-top: 1rem; }
.m-state p { margin: 0; line-height: 1.55; }
.m-state__title {
  font-family: var(--m-voice);
  font-size: 1.75rem;
  line-height: 1.2;
  font-weight: 600;
  margin: 0;
}
.m-auth__rejected { color: rgb(var(--v-theme-error)); font-weight: 600; }
.m-auth { display: grid; gap: 0.75rem; width: 100%; max-width: 26rem; }
.m-auth .v-btn { justify-self: start; }
</style>
