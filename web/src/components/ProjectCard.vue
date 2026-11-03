<template>
  <article class="m-card" :aria-labelledby="titleId">
    <header class="m-card__head">
      <h2 :id="titleId" class="m-card__name">{{ project.name }}</h2>
      <div class="m-card__state">
        <span v-if="project.critical_open > 0" class="m-sev m-sev--critical">{{ $t('project.critical_open', { n: project.critical_open }) }}</span>
        <span v-else-if="seen" class="m-keep">
          <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path :d="checkPath" fill="currentColor" /></svg>
          {{ $t('project.zero_critical') }}
        </span>
        <span v-if="seen && project.days_without_critical > 0" class="m-muted">
          {{ $t('project.days_without_critical', { n: project.days_without_critical }) }}
        </span>
      </div>
      <p v-if="seen && project.critical_open === 0" class="m-card__keep m-muted m-small">{{ $t('project.zero_critical_hint') }}</p>
      <p class="m-card__counts m-small">
        <span v-if="seen || openTotal > 0">{{ $t('project.open', { n: openTotal }) }}</span>
        <template v-if="$ui.advanced"><span v-for="d in decided" :key="d.action" class="m-muted">{{ $t(`project.decided.${d.action}`, { n: d.n }) }}</span></template>
      </p>
      <!-- Where the checks stand, and the button that starts one. -->
      <v-alert
        v-if="failed"
        type="warning"
        variant="tonal"
        density="compact"
        class="m-card__scan"
        role="alert"
      >
        <p class="m-card__scan-text">{{ sentence }}</p>
        <p v-if="project.last_failure.hint" class="m-card__scan-text m-small">{{ project.last_failure.hint }}</p>
        <a v-if="noDatabase" href="#/sources" class="m-card__scan-link">{{ $t('project.open_sources') }}</a>
      </v-alert>
      <v-alert
        v-else-if="scanProblem"
        type="warning"
        variant="tonal"
        density="compact"
        class="m-card__scan"
      >
        {{ sentence }}
        <span>{{ $t('project.scan_hint') }}</span>
      </v-alert>
      <div class="m-card__check">
        <p v-if="!failed && !scanProblem" class="m-card__scan-text m-small" :class="{ 'm-muted': !running }" role="status">
          <v-progress-circular v-if="running" indeterminate size="14" width="2" color="primary" />
          {{ sentence }}
        </p>
        <v-btn size="small" variant="tonal" color="primary" :disabled="running || starting" :loading="starting" @click="check">
          {{ running ? $t('project.check_running') : $t('project.check') }}
        </v-btn>
      </div>
      <div v-if="refusal" class="m-card__refusal m-small" role="alert">
        <p>{{ refusal.offline ? $t('offline.hint') : refusal.error || $t('error.generic') }}</p>
        <p v-if="refusal.hint" class="m-muted">{{ refusal.hint }}</p>
      </div>
    </header>

    <section v-for="s in sections" :key="s.kind" class="m-section" :aria-label="$t(s.title)">
      <h3 class="m-section__title">{{ $t(s.title) }}</h3>
      <p v-if="s.hint" class="m-muted m-small m-section__hint">{{ $t(s.hint) }}</p>
      <ul class="m-rows">
        <PackageRow
          v-for="item in s.items"
          :key="rowKey(item)"
          :item="item"
          @decided="$emit('decided')"
        />
      </ul>
    </section>

    <p v-if="seen && !sections.length" class="m-card__quiet m-muted">{{ $t('project.nothing_new') }}</p>

    <FixSettings :name="project.name" />
  </article>
</template>

<script>
import FixSettings from './FixSettings.vue'
import PackageRow from './PackageRow.vue'
import { api } from '../api.js'
import { severityOf } from '../lib/digestView.js'
import { checkedWell, scanPath, scanSentence, showsFailure } from '../lib/projectsView.js'

const checkPath = 'M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z'

export default {
  name: 'ProjectCard',
  components: { FixSettings, PackageRow },
  props: {
    project: { type: Object, required: true },
    items: { type: Array, default: () => [] },
  },
  emits: ['decided', 'scan-changed'],
  data() {
    return { checkPath, starting: false, refusal: null }
  },
  computed: {
    titleId() {
      return `project-${String(this.project.name).replace(/[^a-zA-Z0-9_-]/g, '-')}`
    },
    openTotal() {
      return Object.values(this.project.open || {}).reduce((a, b) => a + b, 0)
    },
    decided() {
      const d = this.project.decided || {}
      return ['fix', 'defer', 'ignore'].filter((a) => d[a] > 0).map((a) => ({ action: a, n: d[a] }))
    },
    // No reassuring word unless the last check read the whole project.
    seen() {
      return checkedWell(this.project)
    },
    running() {
      return !!this.project.scanning || this.project.last_scan_status === 'running'
    },
    failed() {
      return showsFailure(this.project)
    },
    noDatabase() {
      return this.project.last_failure?.code === 'api.project.no_database'
    },
    scanProblem() {
      return !this.running && ['failed', 'interrupted', 'partial'].includes(this.project.last_scan_status)
    },
    sentence() {
      return scanSentence(this.project, this.$ui.lang)
    },
    gone() {
      return (this.project.gone || []).map((pkg) => ({
        kind: 'gone', package: pkg.name, severity: severityOf(pkg.worst_severity), text: '',
        findingIds: pkg.finding_ids || [], osvIds: pkg.osv_ids || [], installed: pkg.installed || '', target: pkg.target || '',
      }))
    },
    sections() {
      const of = (kind) => this.items.filter((i) => i.kind === kind)
      return [
        { kind: 'new', title: 'section.new', items: of('new') },
        { kind: 'superseded', title: 'section.superseded', items: of('superseded') },
        { kind: 'due', title: 'section.due', items: of('due') },
        { kind: 'gone', title: 'section.gone', hint: 'section.gone_hint', items: this.gone },
      ].filter((s) => s.items.length)
    },
  },
  watch: {
    running(now) {
      // "Already running" is over once the check ends.
      if (!now) this.refusal = null
    },
  },
  methods: {
    async check() {
      this.starting = true
      this.refusal = null
      try {
        await api.post(scanPath(this.project.name, this.$ui.lang))
      } catch (err) {
        // A check already running is told as Michel tells it; the state follows.
        if (err?.status !== 401) this.refusal = err
      } finally {
        this.starting = false
      }
      this.$emit('scan-changed')
    },
    rowKey(item) {
      return `${item.kind}:${item.package}:${item.findingIds.join(',')}`
    },
  },
}
</script>

<style scoped>
.m-card {
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
  border-radius: 12px;
  padding: 1.25rem 1.25rem 0.5rem;
}
.m-card__head { padding-bottom: 0.75rem; }
.m-card__name {
  font-size: 1.25rem;
  font-weight: 650;
  margin: 0 0 0.5rem;
  overflow-wrap: anywhere;
}
.m-card__state {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.4rem 1rem;
  font-size: 0.95rem;
}
.m-keep {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.15rem 0.6rem 0.15rem 0.45rem;
  border-radius: 999px;
  font-weight: 650;
  color: rgb(var(--v-theme-success));
  background: rgba(var(--v-theme-success), 0.12);
}
.m-card__keep { margin: 0.4rem 0 0; }
.m-card__counts {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem 1rem;
  margin: 0.6rem 0 0;
}
.m-card__scan { margin-top: 0.75rem; }
.m-card__scan-text { margin: 0; }
.m-card__scan-link { display: inline-block; margin-top: 0.25rem; color: inherit; font-weight: 600; }
.m-card__check {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem 1rem;
  margin-top: 0.75rem;
}
.m-card__refusal { margin-top: 0.5rem; }
.m-card__refusal p { margin: 0; }
.m-card__quiet { margin: 0 0 0.75rem; }
.m-section { border-top: 1px solid rgba(var(--v-theme-on-surface), 0.08); padding: 0.9rem 0 0.4rem; }
.m-section__title { font-size: 1rem; font-weight: 650; margin: 0 0 0.25rem; }
.m-section__hint { margin: 0 0 0.25rem; }
.m-rows { list-style: none; padding: 0; margin: 0; }
</style>
