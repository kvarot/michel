<template>
  <section class="m-findings" aria-labelledby="findings-title">
    <header class="m-findings__head">
      <h1 id="findings-title" class="m-verdict">{{ $t('findings.title') }}</h1>
      <p class="m-muted m-small m-findings__sub">{{ $t('findings.sub') }}</p>
    </header>

    <form class="m-card m-findings__filters" role="search" :aria-label="$t('findings.filters')" @submit.prevent>
      <div class="m-field m-field--search">
        <label for="findings-q">{{ $t('findings.search') }}</label>
        <input id="findings-q" v-model="filters.q" type="search" autocomplete="off" spellcheck="false">
      </div>
      <div class="m-field">
        <label for="findings-project">{{ $t('findings.filter.project') }}</label>
        <select id="findings-project" v-model="filters.project">
          <option value="">{{ $t('findings.any.project') }}</option>
          <option v-for="p in projectNames" :key="p" :value="p">{{ p }}</option>
        </select>
      </div>
      <div class="m-field">
        <label for="findings-severity">{{ $t('findings.filter.severity') }}</label>
        <select id="findings-severity" v-model="filters.severity">
          <option value="">{{ $t('findings.any.severity') }}</option>
          <option v-for="s in severities" :key="s" :value="s">{{ $t(`severity.${s}`) }}</option>
        </select>
      </div>
      <div class="m-field">
        <label for="findings-status">{{ $t('findings.filter.status') }}</label>
        <select id="findings-status" v-model="filters.status">
          <option value="">{{ $t('findings.any.status') }}</option>
          <option v-for="s in states" :key="s" :value="s">{{ $t(`findings.state.${s}`) }}</option>
        </select>
      </div>
      <div class="m-field">
        <label for="findings-signal">{{ $t('findings.filter.signal') }}</label>
        <select id="findings-signal" v-model="filters.signal">
          <option value="">{{ $t('findings.any.signal') }}</option>
          <option v-for="s in signals" :key="s" :value="s">{{ $t(`signal.${s}`) }}</option>
        </select>
      </div>
      <v-btn v-if="anyFilter" class="m-findings__clear" variant="text" color="primary" @click="clear">{{ $t('findings.clear') }}</v-btn>
    </form>

    <div v-if="!loaded" class="m-findings__loading" role="status">
      <v-progress-circular indeterminate color="primary" size="28" width="3" />
      <p class="m-muted">{{ $t('app.loading') }}</p>
    </div>

    <div v-else-if="!projects" class="m-card m-findings__error" role="alert">
      <p>{{ $t('findings.unread') }}</p>
      <v-btn variant="outlined" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
    </div>

    <template v-else>
      <p v-if="unread.length" class="m-small m-findings__partial" role="status">{{ $t('findings.partial', { n: unread.length, names: unread.join(', ') }) }}</p>
      <p class="m-small m-muted m-findings__count" role="status">{{ $t('findings.count', { n: shown.length }) }}</p>

      <div v-if="!shown.length" class="m-card m-findings__empty">
        <p>{{ anyFilter ? $t('findings.empty_filtered') : $t('findings.empty') }}</p>
        <v-btn v-if="anyFilter" variant="outlined" color="primary" @click="clear">{{ $t('findings.clear') }}</v-btn>
      </div>

      <div v-else class="m-card m-findings__box" role="region" aria-labelledby="findings-caption" tabindex="0">
        <table class="m-table">
          <caption id="findings-caption" class="m-sr">{{ $t('findings.caption') }}. {{ $t('findings.scroll') }}</caption>
          <thead>
            <tr>
              <th scope="col">{{ $t('findings.col.severity') }}</th>
              <th scope="col">{{ $t('findings.col.flaw') }}</th>
              <th scope="col">{{ $t('findings.col.project') }}</th>
              <th scope="col">{{ $t('findings.col.version') }}</th>
              <th scope="col">{{ $t('findings.col.seen') }}</th>
              <th scope="col">{{ $t('findings.col.state') }}</th>
              <th scope="col">{{ $t('findings.col.signals') }}</th>
              <th v-if="$ui.advanced" scope="col">{{ $t('findings.col.id') }}</th>
              <th v-if="$ui.advanced" scope="col" class="m-table__num">{{ $t('findings.col.score') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in shown" :key="r.id">
              <td><span class="m-sev" :class="`m-sev--${r.severity}`">{{ $t(`severity.${r.severity}`) }}</span></td>
              <td class="m-table__flaw"><a :href="r.href">{{ r.title }}</a></td>
              <td>{{ r.project }}</td>
              <td class="m-table__version">
                <template v-if="r.installed || r.fixed || r.signals.includes('nofix')">
                  <span class="m-code">{{ r.installed }}</span>
                  <span aria-hidden="true"> → </span>
                  <span v-if="r.fixed" class="m-code">{{ r.fixed }}</span>
                  <span v-else class="m-muted">{{ $t('findings.fixed_none') }}</span>
                </template>
              </td>
              <td class="m-table__nowrap">{{ r.seen }}</td>
              <td class="m-table__nowrap">{{ $t(`findings.state.${r.state}`) }}</td>
              <td>
                <span class="m-findings__signals">
                  <span v-for="s in r.signals" :key="s" :class="hotSignal(s) ? 'm-flag m-small' : 'm-tag m-small'">{{ $t(`signal.${s}`) }}</span>
                </span>
              </td>
              <td v-if="$ui.advanced" class="m-code">{{ r.osvId }}</td>
              <td v-if="$ui.advanced" class="m-table__num">{{ score(r.cvss) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>
</template>

<script>
import { api } from '../api.js'
import { severities } from '../lib/digestView.js'
import {
  emptyFilters, filterRows, findingRows, findingStates, findingsHash, projectChoices, readAllFindings, signals, unreadProjects,
} from '../lib/findingsView.js'

export default {
  name: 'FindingsPage',
  props: {
    // route is the filters of the address (findingsRoute).
    route: { type: Object, default: () => emptyFilters() },
  },
  data() {
    return {
      loaded: false,
      projects: null,
      lists: {},
      filters: { ...emptyFilters(), ...this.route },
      severities,
      states: findingStates,
      signals,
      seq: 0,
    }
  },
  computed: {
    rows() {
      return findingRows(this.lists, this.$ui.lang)
    },
    shown() {
      return filterRows(this.rows, this.filters)
    },
    unread() {
      return unreadProjects(this.lists)
    },
    projectNames() {
      return projectChoices(this.projects)
    },
    anyFilter() {
      return Object.values(this.filters).some((v) => String(v || '').trim() !== '')
    },
  },
  watch: {
    // A link (a signal of the overview) chose other filters.
    route(next) {
      this.filters = { ...emptyFilters(), ...next }
    },
    // The filters live in the address, so that a link keeps them; replaceState
    // keeps one history entry for a whole search.
    filters: {
      deep: true,
      handler(f) {
        const hash = findingsHash(f)
        if (window.location.hash !== hash) window.history.replaceState(window.history.state, '', hash)
      },
    },
    '$ui.lang'() {
      this.load()
    },
  },
  created() {
    this.load()
  },
  methods: {
    async load() {
      const seq = ++this.seq
      this.loaded = false
      const read = (path) => api.get(path).then((r) => r || []).catch(() => null)
      const got = await readAllFindings(read, this.$ui.lang)
      if (seq !== this.seq) return
      this.projects = got.projects
      this.lists = got.lists
      this.loaded = true
    },
    clear() {
      this.filters = emptyFilters()
    },
    hotSignal(s) {
      return s === 'exploited' || s === 'malicious'
    },
    /** score writes a 0 to 10 score with one decimal, a comma in French; '' when there is none. */
    score(n) {
      if (typeof n !== 'number') return ''
      const s = n.toFixed(1)
      return this.$ui.lang === 'fr' ? s.replace('.', ',') : s
    },
  },
}
</script>

<style scoped>
.m-findings__head { padding-bottom: 1rem; }
.m-findings__head h1 { margin: 0; }
.m-findings__sub { margin: 0.4rem 0 0; }
.m-findings__filters {
  display: grid;
  grid-template-columns: minmax(12rem, 2fr) repeat(4, minmax(9rem, 1fr));
  gap: 0.75rem;
  align-items: end;
  margin-bottom: 1rem;
}
.m-findings__clear { justify-self: start; }
.m-field { display: grid; gap: 0.25rem; min-width: 0; }
.m-field label { font-size: 0.8125rem; font-weight: 700; }
.m-field input, .m-field select {
  width: 100%;
  min-height: 40px;
  padding: 0.4rem 0.6rem;
  border: 1px solid rgba(var(--v-theme-on-surface), 0.45);
  border-radius: 8px;
  background: rgb(var(--v-theme-surface));
  color: rgb(var(--v-theme-on-surface));
  font: inherit;
  font-size: 0.9rem;
}
.m-field select { appearance: auto; }
.m-field input:focus-visible, .m-field select:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 1px; }
.m-findings__loading { display: grid; gap: 0.9rem; justify-items: start; }
.m-findings__loading p, .m-findings__error p, .m-findings__empty p { margin: 0 0 0.75rem; }
.m-findings__partial { margin: 0 0 0.5rem; font-weight: 600; }
.m-findings__count { margin: 0 0 0.5rem; }
.m-findings__box { padding: 0; overflow-x: auto; }
.m-findings__box:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 2px; }
.m-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
.m-table th {
  text-align: left;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.02em;
  color: rgb(var(--v-theme-on-surface));
  background: rgb(var(--v-theme-surface-variant));
  padding: 0.55rem 0.75rem;
  white-space: nowrap;
}
.m-table th:first-child { border-top-left-radius: var(--m-radius); }
.m-table th:last-child { border-top-right-radius: var(--m-radius); }
.m-table td { padding: 0.6rem 0.75rem; border-top: 1px solid var(--m-line); vertical-align: top; }
.m-table tbody tr:hover { background: rgba(var(--v-theme-surface-variant), 0.5); }
.m-table__flaw { min-width: 14rem; font-weight: 600; }
.m-table__flaw a { color: rgb(var(--v-theme-primary)); }
.m-table__version { min-width: 9rem; }
.m-table__nowrap { white-space: nowrap; }
.m-table__num { text-align: right; white-space: nowrap; }
.m-findings__signals { display: flex; flex-wrap: wrap; gap: 0.25rem; }

@media (max-width: 959px) {
  .m-findings__filters { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .m-field--search { grid-column: 1 / -1; }
}
@media (max-width: 599px) {
  .m-findings__filters { grid-template-columns: minmax(0, 1fr); }
}
</style>
