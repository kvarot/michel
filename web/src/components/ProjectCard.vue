<template>
  <article class="m-card" :aria-labelledby="titleId">
    <header class="m-card__head">
      <h2 :id="titleId" class="m-card__name">{{ project.name }}</h2>
      <div class="m-card__state">
        <span v-if="project.critical_open === 0" class="m-keep">
          <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path :d="checkPath" fill="currentColor" /></svg>
          {{ $t('project.zero_critical') }}
        </span>
        <span v-else class="m-sev m-sev--critical">{{ $t('project.critical_open', { n: project.critical_open }) }}</span>
        <span v-if="project.days_without_critical > 0" class="m-muted">
          {{ $t('project.days_without_critical', { n: project.days_without_critical }) }}
        </span>
      </div>
      <p v-if="project.critical_open === 0" class="m-card__keep m-muted m-small">{{ $t('project.zero_critical_hint') }}</p>
      <p class="m-card__counts m-small">
        <span>{{ $t('project.open', { n: openTotal }) }}</span>
        <span v-for="d in decided" :key="d.action" class="m-muted">{{ $t(`project.decided.${d.action}`, { n: d.n }) }}</span>
      </p>
      <v-alert
        v-if="scanProblem"
        :type="project.last_scan_status === 'running' ? 'info' : 'warning'"
        variant="tonal"
        density="compact"
        class="m-card__scan"
      >
        {{ $t(`project.scan.${project.last_scan_status}`) }}
        <span v-if="project.last_scan_status !== 'running'">{{ $t('project.scan_hint', { name: project.name }) }}</span>
      </v-alert>
    </header>

    <section v-for="s in sections" :key="s.kind" class="m-section" :aria-label="$t(s.title)">
      <h3 class="m-section__title">{{ $t(s.title) }}</h3>
      <p v-if="s.hint" class="m-muted m-small m-section__hint">{{ $t(s.hint) }}</p>
      <ul class="m-rows">
        <PackageRow
          v-for="item in s.items"
          :key="rowKey(item)"
          :item="item"
          :project="project.name"
          @decided="$emit('decided')"
        />
      </ul>
    </section>

    <p v-if="!sections.length" class="m-card__quiet m-muted">{{ $t('project.nothing_new') }}</p>
  </article>
</template>

<script>
import PackageRow from './PackageRow.vue'
import { severityOf } from '../lib/digestView.js'

const checkPath = 'M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z'

export default {
  name: 'ProjectCard',
  components: { PackageRow },
  props: {
    project: { type: Object, required: true },
    items: { type: Array, default: () => [] },
  },
  emits: ['decided'],
  data() {
    return { checkPath }
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
    scanProblem() {
      return ['failed', 'interrupted', 'partial', 'running', 'never'].includes(this.project.last_scan_status)
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
  methods: {
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
.m-card__quiet { margin: 0 0 0.75rem; }
.m-section { border-top: 1px solid rgba(var(--v-theme-on-surface), 0.08); padding: 0.9rem 0 0.4rem; }
.m-section__title { font-size: 1rem; font-weight: 650; margin: 0 0 0.25rem; }
.m-section__hint { margin: 0 0 0.25rem; }
.m-rows { list-style: none; padding: 0; margin: 0; }
</style>
