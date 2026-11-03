<template>
  <v-app>
    <a class="m-skip" href="#main">{{ $t('app.skip') }}</a>
    <AppNav v-if="state === 'ready'" :page="page" :assistant="assistant" />

    <v-main>
      <header v-if="showHeader" class="m-top">
        <div class="m-top__row" :class="page === 'fix' ? 'm-wide' : 'm-column'">
          <span v-if="showBrand" class="m-brand">
            <img src="/icons/icon-192.png" alt="" width="28" height="28">
            <span>{{ assistant }}</span>
          </span>
          <span v-else />
          <div class="m-top__actions">
            <v-btn v-if="state === 'ready' && refreshable" variant="text" :loading="refreshing" @click="loadToday(true)">{{ $t('app.refresh') }}</v-btn>
          </div>
        </div>
      </header>

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
        <ProjectsPage v-else-if="page === 'projects'" :digest="digest" @decided="loadToday(false)" />
        <ResolvedPage v-else-if="page === 'resolved'" />
        <SettingsPanel
          v-else-if="page === 'settings'"
          :meta="meta"
          :theme="themeName"
          @lang="setLang"
          @theme="setTheme"
          @token-forgotten="onUnauthorized"
          @token-saved="load"
        />
        <FixPage v-else-if="page === 'fix'" :route="fixRoute" @changed="stale = true" />
        <ServersPage v-else-if="page === 'servers'" :route="serversRoute" @changed="stale = true" />
        <TodayPage v-else :digest="digest" :meta="meta" @decided="loadToday(false)" />
      </div>
    </v-main>

  </v-app>
</template>

<script>
import AppNav from './components/AppNav.vue'
import TodayPage from './components/TodayPage.vue'
import ProjectsPage from './components/ProjectsPage.vue'
import ResolvedPage from './components/ResolvedPage.vue'
import SourcesPage from './components/SourcesPage.vue'
import FixPage from './components/FixPage.vue'
import ServersPage from './components/ServersPage.vue'
import SettingsPanel from './components/SettingsPanel.vue'
import { api } from './api.js'
import { keys, save } from './lib/storage.js'
import { fixRoute } from './lib/fixView.js'
import { pageOf, navMode } from './lib/navView.js'
import { serversRoute } from './lib/serversView.js'

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
  components: { AppNav, TodayPage, ProjectsPage, ResolvedPage, SourcesPage, FixPage, ServersPage, SettingsPanel },
  data() {
    return {
      state: 'loading', // loading | unauthorized | offline | error | ready
      meta: null,
      digest: null,
      failure: { error: '', hint: '' },
      refreshing: false,
      pasted: '',
      // rejected is true when the server refused the token this page holds.
      rejected: false,
      stopListening: null,
      // page follows the address (see navView.pageOf); there is no router.
      page: pageOf(window.location.hash),
      // fixRoute is the attempt or the finding the Fix page shows.
      fixRoute: routeOf(window.location.hash),
      // serversRoute is the server whose sheet the Servers page shows.
      serversRoute: serversOf(window.location.hash),
      // stale is set when another page changed something the digest shows.
      stale: false,
    }
  },
  computed: {
    assistant() {
      return this.digest?.assistant || this.meta?.assistant || 'Michel'
    },
    // The menu stands at the bottom below 960 px; the brand then sits in the header.
    showBrand() {
      return this.state !== 'ready' || navMode(this.$vuetify.display.width) === 'bottom'
    },
    refreshable() {
      return this.page === 'todo' || this.page === 'projects'
    },
    showHeader() {
      return this.showBrand || (this.state === 'ready' && this.refreshable)
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
      if ((this.page === 'todo' || this.page === 'projects') && this.stale && this.state === 'ready') {
        this.stale = false
        this.loadToday(false)
      }
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
