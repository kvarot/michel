<template>
  <section aria-labelledby="reports-title" class="m-rep">
    <header class="m-rep__head">
      <h1 id="reports-title" class="m-verdict">{{ $t('reports.title') }}</h1>
      <p class="m-muted m-rep__sub m-rep__screen">{{ $t('reports.sub') }}</p>
      <p class="m-rep__print-head">{{ $t('reports.print_title', { period: p.label }) }} · {{ $t('reports.printed', { date: printedAt }) }}</p>
    </header>

    <div class="m-rep__bar m-no-print">
      <v-btn-toggle :model-value="p.kind" mandatory divided density="comfortable" variant="outlined" color="primary" :aria-label="$t('reports.kind.label')" @update:model-value="setKind">
        <v-btn v-for="k in kinds" :key="k" :value="k">{{ $t(`reports.kind.${k}`) }}</v-btn>
      </v-btn-toggle>
      <div class="m-rep__nav">
        <v-btn variant="text" icon :href="prevHref" :aria-label="$t('reports.prev')" :title="$t('reports.prev')">
          <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M15.4 7.4 14 6l-6 6 6 6 1.4-1.4-4.6-4.6z" fill="currentColor" /></svg>
        </v-btn>
        <v-btn variant="text" icon :href="nextHref || undefined" :disabled="!nextHref" :aria-label="$t('reports.next')" :title="$t('reports.next')">
          <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M8.6 16.6 10 18l6-6-6-6-1.4 1.4 4.6 4.6z" fill="currentColor" /></svg>
        </v-btn>
      </div>
      <v-btn class="m-rep__print" variant="outlined" color="primary" @click="print">{{ $t('reports.print') }}</v-btn>
    </div>

    <div class="m-rep__period">
      <h2 class="m-rep__label" aria-live="polite">{{ p.label }}</h2>
      <span v-if="p.current" class="m-tag">{{ $t('reports.current') }}</span>
    </div>
    <p v-if="p.current" class="m-small m-muted">{{ $t('reports.current_hint') }}</p>

    <div v-if="state === 'reading'" class="m-rep__state m-no-print" role="status">
      <v-progress-circular indeterminate color="primary" size="28" width="3" />
      <p class="m-muted">{{ $t('reports.reading') }}</p>
    </div>

    <div v-else-if="state === 'error'" class="m-panel m-rep__state m-rep__error" role="alert">
      <p>{{ $t('reports.error') }}</p>
      <p v-if="failure" class="m-small m-muted">{{ failure }}</p>
      <v-btn class="m-no-print" variant="outlined" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
    </div>

    <template v-else-if="report">
      <p class="m-word m-rep__lead">{{ lead }}</p>
      <p v-if="report.reconstructed" class="m-small m-rep__rec">{{ $t('reports.reconstructed') }}</p>

      <section class="m-rep__block" aria-labelledby="rep-sev">
        <h2 id="rep-sev" class="m-rep__title">{{ $t('reports.sev.title') }}</h2>
        <div class="m-rep__scroll" tabindex="0" role="region" aria-labelledby="rep-sev">
          <table class="m-rep__table">
            <thead>
              <tr>
                <th scope="col">{{ $t('reports.col.severity') }}</th>
                <th v-for="c in sevCols" :key="c.key" scope="col" class="m-rep__num">{{ $t(c.label) }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in sevRows" :key="r.severity" :class="{ 'm-rep__total': r.severity === 'total' }">
                <th scope="row">
                  <template v-if="r.severity === 'total'">{{ $t('reports.total') }}</template>
                  <span v-else class="m-sev" :class="`m-sev--${r.severity}`">{{ $t(`severity.${r.severity}`) }}</span>
                </th>
                <td v-for="c in sevCols" :key="c.key" class="m-rep__num" :class="{ 'm-unread': r[c.key] === null }">{{ shown(r[c.key]) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="m-small m-muted">{{ $t('reports.sev.hint') }}</p>
        <p class="m-small m-muted">{{ $t('curve.severity_today') }}</p>
      </section>

      <div class="m-rep__pair">
        <section class="m-rep__block" aria-labelledby="rep-decisions">
          <h2 id="rep-decisions" class="m-rep__title">{{ $t('reports.decisions.title') }}</h2>
          <table class="m-rep__table">
            <tbody>
              <tr v-for="d in decisions" :key="d.action">
                <th scope="row">{{ $t(`decision.action.${d.action}`) }}</th>
                <td class="m-rep__num" :class="{ 'm-unread': d.n === null }">{{ shown(d.n) }}</td>
              </tr>
            </tbody>
          </table>
        </section>
        <section class="m-rep__block" aria-labelledby="rep-fixes">
          <h2 id="rep-fixes" class="m-rep__title">{{ $t('reports.fixes.title') }}</h2>
          <table class="m-rep__table">
            <tbody>
              <tr v-for="f in fixes" :key="f.key">
                <th scope="row">{{ $t(`reports.fixes.${f.key}`) }}</th>
                <td class="m-rep__num" :class="{ 'm-unread': f.n === null }">{{ shown(f.n) }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </div>

      <section class="m-rep__block" aria-labelledby="rep-oldest">
        <h2 id="rep-oldest" class="m-rep__title">{{ $t('reports.oldest.title') }}</h2>
        <p v-if="!oldest">{{ $t('reports.oldest.none') }}</p>
        <p v-else class="m-rep__oldest">
          <span class="m-rep__oldest-name">{{ oldest.name }}</span>
          <span v-if="oldest.since" class="m-small m-muted">{{ $t('reports.oldest.since', { date: oldest.since }) }}</span>
          <a class="m-small m-no-print" :href="oldest.href">{{ $t('reports.oldest.open') }}</a>
        </p>
      </section>

      <section class="m-rep__block" aria-labelledby="rep-checks">
        <h2 id="rep-checks" class="m-rep__title">{{ $t('reports.checks.title') }}</h2>
        <table class="m-rep__table">
          <thead>
            <tr>
              <th scope="col">{{ $t('reports.checks.what') }}</th>
              <th scope="col" class="m-rep__num">{{ $t('reports.checks.done') }}</th>
              <th scope="col" class="m-rep__num">{{ $t('reports.checks.failed') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in checks" :key="c.key">
              <th scope="row">{{ $t(`reports.checks.${c.key}`) }}</th>
              <td class="m-rep__num" :class="{ 'm-unread': c.done === null }">{{ shown(c.done) }}</td>
              <td class="m-rep__num" :class="{ 'm-unread': c.failed === null }">{{ shown(c.failed) }}</td>
            </tr>
          </tbody>
        </table>
        <p v-if="checks[1].failed === null" class="m-small m-muted">{{ $t('reports.checks.servers_hint') }}</p>
      </section>

      <section class="m-rep__block" aria-labelledby="rep-servers">
        <h2 id="rep-servers" class="m-rep__title">{{ $t('reports.servers.title') }}</h2>
        <p class="m-small m-muted">{{ $t('reports.servers.hint') }}</p>
        <table class="m-rep__table">
          <tbody>
            <tr>
              <th scope="row">{{ $t('reports.col.found') }}</th>
              <td class="m-rep__num" :class="{ 'm-unread': servers.found === null }">{{ shown(servers.found) }}</td>
            </tr>
            <tr>
              <th scope="row">{{ $t('reports.servers.closed') }}</th>
              <td class="m-rep__num" :class="{ 'm-unread': servers.closed === null }">{{ shown(servers.closed) }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section class="m-rep__block" aria-labelledby="rep-projects">
        <h2 id="rep-projects" class="m-rep__title">{{ $t('reports.projects.title') }}</h2>
        <p v-if="projects === null" class="m-unread"><span aria-hidden="true">— </span>{{ $t('reports.projects.unread') }}</p>
        <p v-else-if="!projects.length" class="m-muted">{{ $t('reports.projects.none') }}</p>
        <div v-else class="m-rep__scroll" tabindex="0" role="region" aria-labelledby="rep-projects">
          <table class="m-rep__table">
            <thead>
              <tr>
                <th scope="col">{{ $t('reports.col.project') }}</th>
                <th v-for="c in projectCols" :key="c.key" scope="col" class="m-rep__num">{{ $t(c.label) }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(r, i) in projects" :key="`${r.name}-${i}`">
                <th scope="row" class="m-rep__name">{{ r.name }}</th>
                <td v-for="c in projectCols" :key="c.key" class="m-rep__num" :class="{ 'm-unread': r[c.key] === null }">{{ shown(r[c.key]) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </section>
</template>

<script>
import { api } from '../api.js'
import { longDay } from '../lib/overviewView.js'
import {
  checkRows, decisionRows, fixRows, oldestLine, period, periodKinds, projectRows, reportsHash, serverCounts, severityRows, summary,
} from '../lib/reportsView.js'

// ReportsPage is the week or the month of the whole park: the lead
// sentence, the tables by severity and by project, the checks and the
// server flaws counted apart, with a print button. The period lives in the
// address (#/reports?period=…&at=…); the counts come from GET /reports.
export default {
  name: 'ReportsPage',
  props: {
    // route is {period, at} read from the address.
    route: { type: Object, default: () => ({ period: 'week', at: '' }) },
  },
  data() {
    return {
      kinds: periodKinds,
      report: null,
      state: 'reading', // reading | read | error
      failure: '',
      printedAt: '',
      // seq drops the answer of a reading that a newer one replaced.
      seq: 0,
      sevCols: [
        { key: 'found', label: 'reports.col.found' },
        { key: 'goneByMichel', label: 'reports.col.gone_by_michel' },
        { key: 'goneElsewhere', label: 'reports.col.gone_elsewhere' },
        { key: 'openStart', label: 'reports.col.open_start' },
        { key: 'openEnd', label: 'reports.col.open_end' },
      ],
      projectCols: [
        { key: 'found', label: 'reports.col.found' },
        { key: 'gone', label: 'reports.col.gone' },
        { key: 'openEnd', label: 'reports.col.open_end' },
        { key: 'decisions', label: 'reports.col.decisions' },
      ],
    }
  },
  computed: {
    p() {
      return period(this.route?.period, this.route?.at, new Date(), this.$ui.lang)
    },
    prevHref() {
      return reportsHash(this.p.kind, this.p.prev)
    },
    nextHref() {
      return this.p.next ? reportsHash(this.p.kind, this.p.next) : ''
    },
    lead() {
      return summary(this.report, this.$ui.lang)
    },
    sevRows() {
      return severityRows(this.report)
    },
    decisions() {
      return decisionRows(this.report)
    },
    fixes() {
      return fixRows(this.report)
    },
    checks() {
      return checkRows(this.report)
    },
    servers() {
      return serverCounts(this.report)
    },
    projects() {
      return projectRows(this.report)
    },
    oldest() {
      return oldestLine(this.report, this.$ui.lang)
    },
    // key changes when another period must be read.
    key() {
      return `${this.p.from}/${this.p.to}`
    },
  },
  watch: {
    key() {
      this.load()
    },
    '$ui.lang'() {
      this.stamp()
    },
  },
  created() {
    this.stamp()
    window.addEventListener('beforeprint', this.stamp)
    this.load()
  },
  beforeUnmount() {
    window.removeEventListener('beforeprint', this.stamp)
  },
  methods: {
    /** shown is a count, or « non lu » when it cannot be read: never 0. */
    shown(v) {
      return v === null ? this.$t('reports.unread') : String(v)
    },
    /** stamp dates the printed sheet. */
    stamp() {
      this.printedAt = longDay(new Date(), this.$ui.lang)
    },
    /** keepAddress writes the period shown in the address, so that a link or a reload keeps it. */
    keepAddress() {
      const hash = reportsHash(this.p.kind, this.p.from)
      if (window.location.hash !== hash) window.history.replaceState(window.history.state, '', hash)
    },
    setKind(kind) {
      if (!kind || kind === this.p.kind) return
      window.location.hash = reportsHash(kind, this.p.from)
    },
    print() {
      this.stamp()
      window.print()
    },
    async load() {
      const seq = ++this.seq
      this.keepAddress()
      this.state = 'reading'
      this.failure = ''
      try {
        const report = await api.report(this.p.from, this.p.to)
        if (seq !== this.seq) return
        this.report = report
        this.state = 'read'
      } catch (err) {
        if (seq !== this.seq) return
        this.report = null
        this.failure = err?.error || ''
        this.state = 'error'
      }
    },
  },
}
</script>

<style scoped>
.m-rep { display: grid; gap: 1rem; }
.m-rep p { margin: 0; }
.m-rep__sub { margin-top: 0.5rem; }
.m-rep__print-head { display: none; }
.m-rep__bar { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem; }
.m-rep__nav { display: flex; gap: 0.25rem; }
.m-rep__print { margin-left: auto; }
.m-rep__period { display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; }
.m-rep__label { font-size: 1.15rem; font-weight: 700; margin: 0; }
.m-rep__state { display: grid; gap: 0.9rem; justify-items: start; }
.m-rep__error { padding: 1rem 0.9rem; }
.m-rep__lead { margin: 0; }
.m-rep__rec { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgb(var(--v-theme-tag-look)); }
.m-rep__block { display: grid; gap: 0.5rem; }
.m-rep__title { font-size: 1.05rem; font-weight: 600; margin: 0.5rem 0 0; }
.m-rep__pair { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
.m-rep__scroll { overflow-x: auto; }
.m-rep__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
  background: rgb(var(--v-theme-surface));
  border: 1px solid var(--m-line);
}
.m-rep__table th, .m-rep__table td { padding: 0.45rem 0.7rem; text-align: left; vertical-align: top; }
.m-rep__table thead th { font-weight: 700; border-bottom: 1px solid var(--m-line); }
.m-rep__table tbody th { font-weight: 600; }
.m-rep__table tbody tr + tr { border-top: 1px solid var(--m-line); }
.m-rep__num { text-align: right !important; font-variant-numeric: tabular-nums; }
td.m-rep__num { white-space: nowrap; }
.m-rep__total { border-top: 2px solid rgba(var(--v-theme-on-surface), 0.4) !important; font-weight: 700; }
.m-rep__name { overflow-wrap: anywhere; }
.m-rep__oldest { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.3rem 0.8rem; }
.m-rep__oldest-name { font-weight: 600; overflow-wrap: anywhere; }

@media print {
  .m-rep__screen { display: none; }
  .m-rep__print-head { display: block; font-size: 0.9rem; }
  .m-rep__scroll { overflow: visible; }
  .m-rep__table { background: #fff; border-color: #000; }
  .m-rep__table thead th, .m-rep__table tbody tr + tr { border-color: #000; }
  .m-rep__rec { background: #fff; border: 1px solid #000; }
}
</style>
