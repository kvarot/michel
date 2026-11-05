<template>
  <section class="m-ov" aria-labelledby="ov-numbers">
    <h2 id="ov-numbers" class="m-sr">{{ $t('overview.numbers') }}</h2>

    <div class="m-ov__tiles">
      <article class="m-card m-ov__tile" aria-labelledby="ov-open">
        <h3 id="ov-open" class="m-card__title">{{ $t('overview.open.title') }}</h3>
        <template v-if="open">
          <p class="m-ov__kpi">{{ open.total }}</p>
          <template v-if="open.total > 0">
            <div class="m-ov__stack" aria-hidden="true">
              <span v-for="p in shares" :key="p.severity" class="m-ov__stack-part" :class="`m-ov__stack-part--${p.severity}`" :style="{ width: `${p.share * 100}%` }" />
            </div>
            <ul class="m-ov__sevs">
              <li v-for="p in shares" :key="p.severity">
                <span class="m-sev" :class="`m-sev--${p.severity}`">{{ $t(`severity.${p.severity}`) }}</span>
                <span class="m-ov__sev-n">{{ p.n }}</span>
              </li>
            </ul>
          </template>
          <p v-else class="m-small m-muted m-ov__line">{{ $t('overview.open.none') }}</p>
        </template>
        <Unread v-else />
        <a class="m-ov__link m-small" href="#/findings">{{ $t('overview.open.link') }}</a>
      </article>

      <article class="m-card m-ov__tile" aria-labelledby="ov-proposed">
        <h3 id="ov-proposed" class="m-card__title">{{ $t('overview.proposed.title') }}</h3>
        <template v-if="proposed !== null">
          <p class="m-ov__kpi">{{ proposed }}</p>
          <p class="m-small m-muted m-ov__line">{{ $t('overview.proposed.hint') }}</p>
        </template>
        <Unread v-else />
        <a v-if="proposed" class="m-ov__link m-small" href="#/fix">{{ $t('overview.proposed.link') }}</a>
      </article>

      <article class="m-card m-ov__tile" aria-labelledby="ov-proven">
        <h3 id="ov-proven" class="m-card__title">{{ $t('overview.proven.title') }}</h3>
        <template v-if="proven !== null">
          <p class="m-ov__kpi">{{ proven }}</p>
          <p class="m-small m-muted m-ov__line">{{ $t('overview.proven.hint') }}</p>
        </template>
        <Unread v-else />
        <a class="m-ov__link m-small" href="#/resolved">{{ $t('overview.proven.link') }}</a>
      </article>

      <article class="m-card m-ov__tile" aria-labelledby="ov-park">
        <h3 id="ov-park" class="m-card__title">{{ $t('overview.park.title') }}</h3>
        <ul class="m-ov__park">
          <li>
            <a v-if="park.projects !== null" href="#/projects">{{ $t('overview.park.projects', { n: park.projects }) }}</a>
            <span v-else class="m-unread"><span aria-hidden="true">— </span>{{ $t('overview.park.unread_projects') }}</span>
          </li>
          <li>
            <a v-if="park.servers !== null" href="#/servers">{{ $t('overview.park.servers', { n: park.servers }) }}</a>
            <span v-else class="m-unread"><span aria-hidden="true">— </span>{{ $t('overview.park.unread_servers') }}</span>
          </li>
        </ul>
        <p v-if="park.failedProjects > 0" class="m-small m-ov__line m-ov__failed">{{ $t('overview.park.failed_projects', { n: park.failedProjects }) }}</p>
        <p v-if="park.failedServers > 0" class="m-small m-ov__line m-ov__failed">{{ $t('overview.park.failed_servers', { n: park.failedServers }) }}</p>
        <p v-if="park.failedProjects === null || park.failedServers === null" class="m-small m-unread m-ov__line"><span aria-hidden="true">— </span>{{ $t('overview.park.unread_failed') }}</p>
        <p v-else-if="park.failedProjects === 0 && park.failedServers === 0" class="m-small m-muted m-ov__line">{{ $t('overview.park.failed_none') }}</p>
      </article>
    </div>

    <div class="m-ov__cards">
      <article class="m-card" aria-labelledby="ov-weeks">
        <h3 id="ov-weeks" class="m-card__title">{{ $t('overview.weeks.title') }}</h3>
        <p class="m-small m-muted m-ov__line">{{ $t('overview.weeks.hint') }}</p>
        <p v-if="!weeks" class="m-small m-unread m-ov__line"><span aria-hidden="true">— </span>{{ $t('overview.weeks.unread') }}</p>
        <p v-else-if="!weeks.some((w) => w.sent)" class="m-small m-muted m-ov__line">{{ $t('overview.weeks.empty') }}</p>
        <template v-else>
          <ul class="m-ov__legend m-small" aria-hidden="true">
            <li><span class="m-ov__key m-ov__key--new" />{{ $t('overview.weeks.new') }}</li>
            <li><span class="m-ov__key m-ov__key--gone" />{{ $t('overview.weeks.gone') }}</li>
          </ul>
          <svg class="m-ov__chart" :viewBox="`0 0 ${chart.width} ${chart.height + 22}`" aria-hidden="true" focusable="false">
            <line :x1="0" :x2="chart.width" :y1="chart.height" :y2="chart.height" class="m-ov__axis" />
            <g v-for="(w, i) in weeks" :key="w.key">
              <template v-if="w.fresh !== null">
                <rect :x="i * chart.step + 6" :y="chart.height - bar(w.fresh)" width="12" :height="bar(w.fresh)" class="m-ov__bar--new" />
                <rect :x="i * chart.step + 20" :y="chart.height - bar(w.gone)" width="12" :height="bar(w.gone)" class="m-ov__bar--gone" />
              </template>
              <text v-else :x="i * chart.step + chart.step / 2" :y="chart.height - 4" text-anchor="middle" class="m-ov__none">–</text>
              <text :x="i * chart.step + chart.step / 2" :y="chart.height + 16" text-anchor="middle" class="m-ov__tick">{{ short(w.start) }}</text>
            </g>
          </svg>
          <p class="m-small m-muted m-ov__line">{{ $t('overview.weeks.gaps') }}</p>
          <div class="m-sr">
          <table>
            <caption>{{ $t('overview.weeks.caption') }}</caption>
            <thead>
              <tr>
                <th scope="col">{{ $t('overview.weeks.col_week') }}</th>
                <th scope="col">{{ $t('overview.weeks.new') }}</th>
                <th scope="col">{{ $t('overview.weeks.gone') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="w in weeks" :key="w.key">
                <th scope="row">{{ $t('overview.weeks.week', { date: long(w.start) }) }}</th>
                <td>{{ cell(w, w.fresh) }}</td>
                <td>{{ cell(w, w.gone) }}</td>
              </tr>
            </tbody>
          </table>
          </div>
        </template>
      </article>

      <article class="m-card" aria-labelledby="ov-ages">
        <h3 id="ov-ages" class="m-card__title">{{ $t('overview.ages.title') }}</h3>
        <p v-if="listsShown === 'reading'" class="m-small m-muted m-ov__line" role="status">{{ $t('overview.reading') }}</p>
        <p v-else-if="listsShown === 'unread'" class="m-small m-unread m-ov__line"><span aria-hidden="true">— </span>{{ $t('overview.lists_unread') }}</p>
        <template v-else>
          <p v-if="unreadCount" class="m-small m-ov__line m-ov__partial">{{ $t('overview.partial', { n: unreadCount }) }}</p>
          <p v-if="!ages.total" class="m-small m-muted m-ov__line">{{ $t('overview.ages.none') }}</p>
          <ul v-else class="m-ov__ages">
            <li v-for="b in ages.buckets" :key="b.key">
              <span class="m-ov__age-label m-small">{{ $t(`overview.ages.${b.key}`) }}</span>
              <span class="m-ov__age-track" aria-hidden="true"><span class="m-ov__age-bar" :style="{ width: `${ageShare(b.n)}%` }" /></span>
              <span class="m-ov__age-n">{{ b.n }}</span>
            </li>
          </ul>
          <p v-if="ages.unknown" class="m-small m-muted m-ov__line">{{ $t('overview.ages.unknown', { n: ages.unknown }) }}</p>
        </template>
      </article>
    </div>

    <article class="m-card m-ov__signals" aria-labelledby="ov-signals">
      <h3 id="ov-signals" class="m-card__title">{{ $t('overview.signals.title') }}</h3>
      <p v-if="listsShown === 'reading'" class="m-small m-muted m-ov__line">{{ $t('overview.reading') }}</p>
      <p v-else-if="listsShown === 'unread'" class="m-small m-unread m-ov__line"><span aria-hidden="true">— </span>{{ $t('overview.lists_unread') }}</p>
      <template v-else>
        <p class="m-small m-muted m-ov__line">{{ $t('overview.signals.hint') }}</p>
        <p v-if="unreadCount" class="m-small m-ov__line m-ov__partial">{{ $t('overview.partial', { n: unreadCount }) }}</p>
        <ul class="m-ov__chips">
          <li v-for="s in signalList" :key="s.signal">
            <a class="m-ov__chip" :class="{ 'm-ov__chip--hot': hot(s.signal) && s.n > 0 }" :href="signalHref(s.signal)">
              {{ $t('overview.signals.count', { label: $t(`signal.${s.signal}`), n: s.n }) }}
            </a>
          </li>
        </ul>
      </template>
    </article>
  </section>
</template>

<script>
import Unread from './UnreadValue.vue'
import { findingsHash } from '../lib/findingsView.js'
import {
  ageCounts, allListed, barHeight, listsStatus, longDay, openBySeverity, parkSummary, proposedCount, provenFixedCount, severityShares, shortDay,
  signalCounts, weeklyChanges, weeklyMax,
} from '../lib/overviewView.js'

export default {
  name: 'OverviewPanel',
  components: { Unread },
  props: {
    digest: { type: Object, default: null },
    // attempts, projects, servers and runs are null when they could not be read.
    attempts: { type: Array, default: null },
    projects: { type: Array, default: null },
    servers: { type: Array, default: null },
    runs: { type: Array, default: null },
    // lists is {project: findings | null}; listsState is reading, read, or unread
    // when the projects could not be read.
    lists: { type: Object, default: () => ({}) },
    listsState: { type: String, default: 'reading' },
    now: { type: Date, required: true },
  },
  data() {
    return { chart: { width: 320, height: 96, step: 40 } }
  },
  computed: {
    open() {
      return openBySeverity(this.digest)
    },
    shares() {
      return severityShares(this.open)
    },
    proposed() {
      return proposedCount(this.attempts)
    },
    proven() {
      return provenFixedCount(this.attempts, this.now)
    },
    park() {
      return parkSummary(this.projects, this.servers, this.digest)
    },
    weeks() {
      return weeklyChanges(this.runs, this.now)
    },
    max() {
      return weeklyMax(this.weeks)
    },
    // lists: reading, unread (no list could be read), or read.
    listsShown() {
      return listsStatus(this.listsState, this.lists)
    },
    listed() {
      return allListed(this.lists)
    },
    unreadCount() {
      return Object.values(this.lists || {}).filter((l) => !Array.isArray(l)).length
    },
    ages() {
      return ageCounts(this.listed, this.now)
    },
    signalList() {
      return signalCounts(this.listed)
    },
  },
  methods: {
    bar(n) {
      return barHeight(n, this.max, this.chart.height - 8)
    },
    short(d) {
      return shortDay(d, this.$ui.lang)
    },
    long(d) {
      return longDay(d, this.$ui.lang)
    },
    cell(w, n) {
      if (!w.sent) return this.$t('overview.weeks.none_sent')
      return n === null ? this.$t('overview.weeks.week_unread') : String(n)
    },
    ageShare(n) {
      const top = Math.max(...this.ages.buckets.map((b) => b.n))
      return top ? Math.max(n ? 3 : 0, Math.round((n / top) * 100)) : 0
    },
    hot(s) {
      return s === 'exploited' || s === 'malicious'
    },
    signalHref(signal) {
      return findingsHash({ signal })
    },
  },
}
</script>

<style scoped>
.m-ov { margin-bottom: 1.5rem; }
.m-ov__tiles { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.75rem; }
.m-ov__tile { display: flex; flex-direction: column; gap: 0.35rem; }
.m-ov__kpi { margin: 0.15rem 0 0; font-size: 2rem; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.m-ov__line { margin: 0; }
.m-ov__link { margin-top: auto; padding-top: 0.4rem; color: rgb(var(--v-theme-primary)); font-weight: 600; }
.m-ov__stack { display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: var(--m-line); gap: 2px; }
.m-ov__stack-part { display: block; height: 100%; min-width: 4px; }
.m-ov__stack-part--critical { background: rgb(var(--v-theme-critical)); }
.m-ov__stack-part--high { background: rgb(var(--v-theme-high)); }
.m-ov__stack-part--medium { background: rgb(var(--v-theme-medium)); }
.m-ov__stack-part--low { background: rgb(var(--v-theme-low)); }
.m-ov__stack-part--unknown { background: rgb(var(--v-theme-unknown)); }
.m-ov__sevs { list-style: none; margin: 0.2rem 0 0; padding: 0; display: grid; gap: 0.15rem; }
.m-ov__sevs li { display: flex; justify-content: space-between; gap: 0.5rem; }
.m-ov__sev-n { font-weight: 700; font-variant-numeric: tabular-nums; font-size: 0.875rem; }
.m-ov__park { list-style: none; margin: 0.2rem 0 0; padding: 0; display: grid; gap: 0.2rem; font-weight: 600; }
.m-ov__park a { color: rgb(var(--v-theme-primary)); }
.m-ov__failed { color: rgb(var(--v-theme-warning)); font-weight: 700; }
.m-ov__partial { font-weight: 600; }
.m-ov__cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.75rem; margin-top: 0.75rem; }
.m-ov__cards .m-card { display: grid; gap: 0.5rem; align-content: start; }
.m-ov__legend { list-style: none; margin: 0; padding: 0; display: flex; gap: 1rem; }
.m-ov__legend li { display: inline-flex; align-items: center; gap: 0.35rem; }
.m-ov__key { display: inline-block; width: 12px; height: 12px; border-radius: 3px; }
.m-ov__key--new { background: rgb(var(--v-theme-primary)); }
.m-ov__key--gone { background: rgb(var(--v-theme-tag-done)); border: 2px solid rgb(var(--v-theme-success)); }
.m-ov__chart { width: 100%; height: auto; max-height: 160px; display: block; }
.m-ov__axis { stroke: rgb(var(--v-theme-line)); stroke-width: 1; }
.m-ov__bar--new { fill: rgb(var(--v-theme-primary)); }
.m-ov__bar--gone { fill: rgb(var(--v-theme-tag-done)); stroke: rgb(var(--v-theme-success)); stroke-width: 2; }
.m-ov__none { fill: rgb(var(--v-theme-secondary)); font-size: 16px; }
.m-ov__tick { fill: rgb(var(--v-theme-secondary)); font-size: 12px; }
.m-ov__ages { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.45rem; }
.m-ov__ages li { display: grid; grid-template-columns: 9.5rem minmax(0, 1fr) 2.5rem; align-items: center; gap: 0.6rem; }
.m-ov__age-track { height: 10px; border-radius: 999px; background: rgb(var(--v-theme-surface-variant)); overflow: hidden; }
.m-ov__age-bar { display: block; height: 100%; border-radius: 999px; background: rgb(var(--v-theme-primary)); }
.m-ov__age-n { text-align: right; font-weight: 700; font-variant-numeric: tabular-nums; }
.m-ov__signals { margin-top: 0.75rem; display: grid; gap: 0.5rem; }
.m-ov__chips { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); gap: 0.4rem; }
.m-ov__chip {
  display: flex;
  align-items: center;
  min-height: 40px;
  padding: 0.35rem 0.8rem;
  border: 1px solid var(--m-line);
  border-radius: 8px;
  color: rgb(var(--v-theme-primary));
  background: rgb(var(--v-theme-surface-variant));
  font-size: 0.875rem;
  font-weight: 600;
  text-decoration: none;
}
.m-ov__chip:hover { text-decoration: underline; }
.m-ov__chip--hot { color: rgb(var(--v-theme-surface)); background: rgb(var(--v-theme-critical)); border-color: rgb(var(--v-theme-critical)); }

@media (max-width: 1199px) {
  .m-ov__tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 799px) {
  .m-ov__cards { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 599px) {
  .m-ov__tiles { grid-template-columns: minmax(0, 1fr); }
  .m-ov__ages li { grid-template-columns: 7.5rem minmax(0, 1fr) 2rem; }
}
</style>
