<template>
  <v-navigation-drawer v-if="mode === 'side'" permanent :width="248" color="nav" tag="nav" :aria-label="$t('nav.label')" class="m-nav">
    <p class="m-nav__brand">
      <img src="/icons/icon-192.png" alt="" width="26" height="26">
      <span>{{ assistant }}</span>
    </p>
    <div v-for="g in groups" :key="g.group" class="m-nav__group">
      <p v-if="g.group !== 'other'" :id="`nav-group-${g.group}`" class="m-nav__group-name">{{ $t(`nav.group.${g.group}`) }}</p>
      <ul class="m-nav__list" :aria-labelledby="g.group !== 'other' ? `nav-group-${g.group}` : undefined">
        <li v-for="e in g.entries" :key="e.page">
          <a :href="e.hash" class="m-nav__link" :class="{ 'm-nav__link--on': e.page === active }" :aria-current="e.page === active ? 'page' : undefined">
            <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path :d="e.icon" fill="currentColor" /></svg>
            <span class="m-nav__text">{{ $t(e.key) }}</span>
            <span v-if="e.page === 'findings' && open !== null" class="m-nav__count">
              <span aria-hidden="true">{{ open }}</span>
              <span class="m-sr">{{ $t('nav.badge', { n: open }) }}</span>
            </span>
          </a>
        </li>
      </ul>
    </div>
    <a href="#/" class="m-nav__help" @click="showGuide">{{ $t('nav.help') }}</a>
  </v-navigation-drawer>

  <v-bottom-navigation v-else tag="nav" :aria-label="$t('nav.label')" :model-value="active" grow class="m-bottom">
    <v-btn
      v-for="e in groups[0].entries"
      :key="e.page"
      :value="e.page"
      :href="e.hash"
      :aria-current="e.page === active ? 'page' : undefined"
      class="m-bottom__btn"
      :class="{ 'm-bottom__btn--on': e.page === active }"
    >
      <span class="m-bottom__icon">
        <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path :d="e.icon" fill="currentColor" /></svg>
        <span v-if="e.page === 'findings' && open !== null && open > 0" class="m-bottom__count" aria-hidden="true">{{ open > 99 ? '99+' : open }}</span>
      </span>
      <span>{{ $t(e.shortKey) }}</span>
      <span v-if="e.page === 'findings' && open !== null" class="m-sr">{{ $t('nav.badge', { n: open }) }}</span>
    </v-btn>
  </v-bottom-navigation>
</template>

<script>
import { showGuideAgain } from '../lib/guideView.js'
import { activeEntry, entriesFor, navMode } from '../lib/navView.js'
import { save } from '../lib/storage.js'

export default {
  name: 'AppNav',
  props: {
    page: { type: String, required: true },
    assistant: { type: String, default: 'Michel' },
    // open is the number of open flaws, null when it is not known: no badge then.
    open: { type: Number, default: null },
  },
  computed: {
    mode() {
      return navMode(this.$vuetify.display.width)
    },
    groups() {
      return entriesFor(this.mode)
    },
    active() {
      return activeEntry(this.page, this.mode)
    },
  },
  methods: {
    showGuide() {
      showGuideAgain(this.$ui.guide, save)
    },
  },
}
</script>

<style scoped>
.m-nav { padding: 14px 12px; border-right: 1px solid var(--m-line) !important; }
.m-nav__brand {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  font-weight: 700;
  font-size: 1.1rem;
  margin: 0;
  padding: 2px 8px 14px;
  color: rgb(var(--v-theme-on-nav));
}
.m-nav__brand img { border-radius: 7px; }
.m-nav__group + .m-nav__group { margin-top: 14px; }
.m-nav__group-name {
  margin: 0 0 4px;
  padding: 0 8px;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: rgb(var(--v-theme-secondary));
}
.m-nav__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }
.m-nav__link {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 7px 8px;
  border-radius: 8px;
  color: rgb(var(--v-theme-on-nav));
  text-decoration: none;
  font-size: 0.92rem;
}
.m-nav__text { flex: 1 1 auto; min-width: 0; }
.m-nav__link:hover { background: rgb(var(--v-theme-nav-active)); }
.m-nav__link--on { background: rgb(var(--v-theme-nav-active)); color: rgb(var(--v-theme-primary)); font-weight: 700; }
.m-nav__count {
  flex: none;
  min-width: 1.6rem;
  padding: 0 0.4rem;
  border-radius: 999px;
  text-align: center;
  font-size: 0.75rem;
  font-weight: 700;
  line-height: 1.35rem;
  color: rgb(var(--v-theme-on-primary));
  background: rgb(var(--v-theme-primary));
}
.m-nav__link:focus-visible, .m-nav__help:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 1px; }
.m-nav__help {
  display: block;
  margin-top: 18px;
  padding: 10px 8px 0;
  border-top: 1px solid var(--m-line);
  color: rgb(var(--v-theme-primary));
  font-size: 0.85rem;
  line-height: 1.4;
}

.m-bottom { border-top: 1px solid var(--m-line); background: rgb(var(--v-theme-surface)); }
.m-bottom__btn { min-width: 0; font-size: 0.75rem; letter-spacing: 0; text-transform: none; color: rgb(var(--v-theme-on-surface)); }
.m-bottom__btn--on { font-weight: 700; color: rgb(var(--v-theme-primary)); }
.m-bottom__btn :deep(.v-btn__content) { flex-direction: column; gap: 2px; }
.m-bottom__icon { position: relative; display: inline-flex; }
.m-bottom__count {
  position: absolute;
  top: -4px;
  left: 14px;
  min-width: 1.1rem;
  padding: 0 0.25rem;
  border-radius: 999px;
  font-size: 0.65rem;
  font-weight: 700;
  line-height: 1.1rem;
  text-align: center;
  color: rgb(var(--v-theme-on-primary));
  background: rgb(var(--v-theme-primary));
}
</style>
