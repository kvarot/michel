<template>
  <v-navigation-drawer v-if="mode === 'side'" permanent :width="200" color="nav" tag="nav" :aria-label="$t('nav.label')" class="m-nav">
    <p class="m-nav__brand">{{ assistant }}</p>
    <ul class="m-nav__list">
      <li v-for="e in entries" :key="e.page">
        <a :href="e.hash" class="m-nav__link" :class="{ 'm-nav__link--on': e.page === active }" :aria-current="e.page === active ? 'page' : undefined">
          <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path :d="e.icon" fill="currentColor" /></svg>
          <span>{{ $t(e.key) }}</span>
        </a>
      </li>
    </ul>
    <a href="#/settings" class="m-nav__help">{{ $t('nav.help') }}</a>
  </v-navigation-drawer>

  <v-bottom-navigation v-else tag="nav" :aria-label="$t('nav.label')" :model-value="active" grow class="m-bottom">
    <v-btn
      v-for="e in entries"
      :key="e.page"
      :value="e.page"
      :href="e.hash"
      :aria-current="e.page === active ? 'page' : undefined"
      class="m-bottom__btn"
      :class="{ 'm-bottom__btn--on': e.page === active }"
    >
      <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path :d="e.icon" fill="currentColor" /></svg>
      <span>{{ $t(e.shortKey) }}</span>
    </v-btn>
  </v-bottom-navigation>
</template>

<script>
import { activeEntry, navEntries, navMode } from '../lib/navView.js'

export default {
  name: 'AppNav',
  props: {
    page: { type: String, required: true },
    assistant: { type: String, default: 'Michel' },
  },
  data() {
    return { entries: navEntries }
  },
  computed: {
    mode() {
      return navMode(this.$vuetify.display.width)
    },
    active() {
      return activeEntry(this.page)
    },
  },
}
</script>

<style scoped>
.m-nav { padding: 16px 10px; }
.m-nav__brand { font-family: var(--m-voice); font-weight: 600; font-size: 1.2rem; margin: 0; padding: 0 8px 16px; color: rgb(var(--v-theme-on-nav)); }
.m-nav__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }
.m-nav__link {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 8px;
  border-radius: 6px;
  color: rgb(var(--v-theme-on-nav));
  text-decoration: none;
  font-size: 0.95rem;
}
.m-nav__link:hover { background: rgba(var(--v-theme-on-nav), 0.1); }
.m-nav__link--on { background: rgb(var(--v-theme-nav-active)); font-weight: 700; }
.m-nav__link:focus-visible, .m-nav__help:focus-visible { outline: 2px solid rgb(var(--v-theme-on-nav)); outline-offset: 2px; }
.m-nav__help {
  display: block;
  margin-top: 26px;
  padding: 8px;
  border-top: 1px solid rgba(var(--v-theme-on-nav), 0.3);
  color: rgb(var(--v-theme-on-nav));
  font-size: 0.85rem;
  line-height: 1.4;
}

.m-bottom { border-top: 1px solid var(--m-line); background: rgb(var(--v-theme-surface)); }
.m-bottom__btn { min-width: 0; font-size: 0.75rem; letter-spacing: 0; text-transform: none; color: rgb(var(--v-theme-on-surface)); }
.m-bottom__btn--on { font-weight: 700; color: rgb(var(--v-theme-primary)); }
.m-bottom__btn :deep(.v-btn__content) { flex-direction: column; gap: 2px; }
</style>
