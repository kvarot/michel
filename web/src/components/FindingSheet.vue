<template>
  <div class="m-sheet" :aria-busy="String(loading)">
    <div v-if="loading" class="m-sheet__loading m-muted m-small" role="status">
      <v-progress-circular indeterminate size="18" width="2" color="primary" />
      {{ $t('sheet.loading') }}
    </div>

    <div v-else-if="failure" class="m-sheet__failure" role="alert">
      <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
      <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
      <v-btn size="small" variant="tonal" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
    </div>

    <template v-else-if="f">
      <div class="m-sheet__head">
        <span class="m-code m-sheet__id">{{ f.osv_id }}</span>
        <span class="m-sheet__chips">
          <span v-if="f.malicious" class="m-flag m-small">{{ $t('chip.malicious') }}</span>
          <span v-else-if="f.kev" class="m-flag m-small">{{ $t('chip.kev') }}</span>
          <span v-if="kind !== 'dependency'" class="m-tag m-small">{{ $t(`kind.${kind}`) }}</span>
          <span class="m-sev" :class="`m-sev--${severity}`">{{ $t(`severity.${severity}`) }}</span>
        </span>
      </div>

      <div class="m-sheet__sentences">
        <section v-for="s in sentences" :key="s.key" class="m-sentence">
          <h4 class="m-sentence__label">{{ $t(s.label) }}</h4>
          <p class="m-sentence__text m-voice">{{ s.text }}</p>
        </section>
      </div>

      <h4 class="m-sheet__sub">{{ $t('sheet.facts') }}</h4>
      <dl class="m-facts">
        <div v-if="f.kev"><dt>{{ $t('fact.kev') }}</dt><dd>{{ $t('fact.kev_value', { date: kevDate }) }}</dd></div>
        <div v-if="f.epss > 0"><dt>{{ $t('fact.epss') }}</dt><dd>{{ $t('fact.epss_value', epss) }}</dd></div>
        <div v-if="f.rule_id"><dt>{{ $t('fact.rule') }}</dt><dd class="m-code">{{ f.rule_id }}</dd></div>
        <div v-if="f.location"><dt>{{ $t('fact.location') }}</dt><dd class="m-code">{{ f.location }}</dd></div>
        <div v-if="f.source_key"><dt>{{ $t('fact.source') }}</dt><dd class="m-code">{{ f.source_key }}</dd></div>
        <div v-if="f.manifest_rel_path"><dt>{{ $t('fact.manifest') }}</dt><dd class="m-code">{{ f.manifest_rel_path }}</dd></div>
        <div><dt>{{ $t('fact.installed') }}</dt><dd class="m-code">{{ f.installed_version }}</dd></div>
        <div>
          <dt>{{ $t('fact.fixed') }}</dt>
          <dd :class="{ 'm-code': f.fixed_versions.length }">{{ f.fixed_versions.length ? f.fixed_versions.join(', ') : $t('fact.fixed_none') }}</dd>
        </div>
        <template v-if="a">
          <div>
            <dt>{{ $t('fact.path') }}</dt>
            <dd>
              <span v-if="a.path.directness === 'direct'">{{ $t('fact.direct') }}</span>
              <span v-else-if="a.path.directness === 'transitive'">
                <span v-if="glossary.transitive" class="m-term" tabindex="0">
                  {{ $t('fact.transitive', { via: (a.path.via || []).join(', ') }) }}
                  <v-tooltip activator="parent" location="top" max-width="320">{{ glossary.transitive }}</v-tooltip>
                </span>
                <span v-else>{{ $t('fact.transitive', { via: (a.path.via || []).join(', ') }) }}</span>
              </span>
              <span v-else>{{ $t('fact.path_unknown') }}</span>
            </dd>
          </div>
          <div>
            <dt>{{ $t('fact.calls') }}</dt>
            <dd>
              <span v-if="!a.calls.count">{{ $t('fact.calls_none') }}</span>
              <ul v-else class="m-files">
                <li v-for="s in calls" :key="`${s.file}:${s.line}`" class="m-code">{{ s.file }}:{{ s.line }}</li>
                <li v-if="a.calls.count > calls.length" class="m-muted">{{ $t('sheet.more', { n: a.calls.count - calls.length }) }}</li>
              </ul>
            </dd>
          </div>
          <div>
            <dt>{{ $t('fact.tests') }}</dt>
            <dd>
              <span v-if="!a.coverage.count">{{ $t('fact.tests_none') }}</span>
              <ul v-else class="m-files">
                <li v-for="t in tests" :key="t" class="m-code">{{ t }}</li>
                <li v-if="a.coverage.count > tests.length" class="m-muted">{{ $t('sheet.more', { n: a.coverage.count - tests.length }) }}</li>
              </ul>
            </dd>
          </div>
          <div>
            <dt>
              <span v-if="glossary.breaking" class="m-term" tabindex="0">
                {{ $t('fact.changelog') }}
                <v-tooltip activator="parent" location="top" max-width="320">{{ glossary.breaking }}</v-tooltip>
              </span>
              <span v-else>{{ $t('fact.changelog') }}</span>
            </dt>
            <dd>
              <span v-if="!a.changelog.available">{{ $t('fact.changelog_unavailable') }}</span>
              <span v-else-if="!breaking.length">{{ $t('fact.changelog_none') }}</span>
              <ul v-else class="m-files">
                <li v-for="(l, i) in breaking" :key="i">{{ l }}</li>
              </ul>
            </dd>
          </div>
        </template>
      </dl>
      <p v-if="!a" class="m-muted m-small">{{ $t('sheet.no_analysis', { name: f.project }) }}</p>

      <details class="m-tech">
        <summary>{{ $t('sheet.technical') }}</summary>
        <dl class="m-facts">
          <div>
            <dt>
              <span v-if="glossary.cve" class="m-term" tabindex="0">
                {{ $t('fact.ids') }}
                <v-tooltip activator="parent" location="top" max-width="320">{{ glossary.cve }}</v-tooltip>
              </span>
              <span v-else>{{ $t('fact.ids') }}</span>
            </dt>
            <dd class="m-code">{{ [f.osv_id, ...f.aliases].join(', ') }}</dd>
          </div>
          <div v-if="f.cvss > 0">
            <dt>
              <span v-if="glossary.cvss" class="m-term" tabindex="0">
                {{ $t('fact.cvss') }}
                <v-tooltip activator="parent" location="top" max-width="320">{{ glossary.cvss }}</v-tooltip>
              </span>
              <span v-else>{{ $t('fact.cvss') }}</span>
            </dt>
            <dd>{{ f.cvss }}</dd>
          </div>
          <template v-if="a">
            <div><dt>{{ $t('fact.score') }}</dt><dd>{{ a.risk.score }}</dd></div>
            <div v-if="terms.length">
              <dt>{{ $t('fact.score_terms') }}</dt>
              <dd>
                <ul class="m-files">
                  <li v-for="t in terms" :key="t.name"><span class="m-code">{{ t.name }}</span> +{{ t.points }}</li>
                </ul>
              </dd>
            </div>
          </template>
        </dl>
      </details>

      <section v-if="glossaryList.length" class="m-glossary">
        <h4 class="m-sheet__sub">{{ $t('sheet.glossary') }}</h4>
        <dl>
          <div v-for="g in glossaryList" :key="g.term">
            <dt>{{ $t(`term.${g.term}`) }}</dt>
            <dd>{{ g.definition }}</dd>
          </div>
        </dl>
      </section>

      <div v-if="fixable" class="m-sheet__fix">
        <v-btn color="primary" variant="flat" :href="fixHref">{{ $t('item.fix') }}</v-btn>
      </div>

      <DecisionPanel :finding="f" @decided="onDecided" />
    </template>
  </div>
</template>

<script>
import DecisionPanel from './DecisionPanel.vue'
import { api } from '../api.js'
import { formatDate, formatPercent, severityOf } from '../lib/digestView.js'
import { fixHash } from '../lib/fixView.js'

const kinds = ['dependency', 'code', 'misconfig', 'web', 'vulnerability']

export default {
  name: 'FindingSheet',
  components: { DecisionPanel },
  props: {
    findingId: { type: String, required: true },
  },
  emits: ['decided'],
  data() {
    return { f: null, loading: true, failure: null }
  },
  computed: {
    // fixable: an open finding can go to the Fix page ("Corriger").
    fixable() {
      if (!this.f || this.f.status === 'gone') return false
      return this.f.decision?.action !== 'ignore'
    },
    fixHref() {
      return fixHash({ finding: this.f?.id })
    },
    a() {
      return this.f?.analysis || null
    },
    severity() {
      return severityOf(this.f?.severity)
    },
    kind() {
      return kinds.includes(this.f?.kind) ? this.f.kind : 'dependency'
    },
    kevDate() {
      return formatDate(this.f?.kev_added, this.$ui.lang) || '?'
    },
    epss() {
      const lang = this.$ui.lang
      return { p: formatPercent(this.f?.epss, lang), pct: formatPercent(this.f?.epss_percentile, lang, true) }
    },
    glossary() {
      return this.f?.glossary || {}
    },
    glossaryList() {
      return Object.keys(this.glossary).sort().map((term) => ({ term, definition: this.glossary[term] }))
    },
    sentences() {
      const ex = this.f?.explanation || {}
      return [
        { key: 'what', label: 'sheet.what', text: ex.what },
        { key: 'impact', label: 'sheet.impact', text: ex.impact },
        { key: 'cost', label: 'sheet.cost', text: ex.cost },
      ].filter((s) => s.text)
    },
    calls() {
      return (this.a?.calls?.sites || []).slice(0, 5)
    },
    tests() {
      return (this.a?.coverage?.test_files || []).slice(0, 5)
    },
    breaking() {
      return (this.a?.changelog?.breaking_lines || []).slice(0, 5)
    },
    terms() {
      const t = this.a?.risk?.terms || {}
      return Object.keys(t).filter((k) => t[k] > 0).sort().map((name) => ({ name, points: t[name] }))
    },
  },
  watch: {
    '$ui.lang'() {
      this.load()
    },
  },
  created() {
    this.load()
  },
  methods: {
    async load() {
      this.loading = !this.f
      this.failure = null
      try {
        this.f = await api.get(`/findings/${encodeURIComponent(this.findingId)}?lang=${encodeURIComponent(this.$ui.lang)}`)
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
      }
    },
    onDecided(view) {
      this.f = view
      this.$emit('decided')
    },
  },
}
</script>

<style scoped>
.m-sheet {
  background: rgba(var(--v-theme-on-surface), 0.035);
  border-radius: 10px;
  padding: 1rem;
}
.m-sheet__loading { display: flex; align-items: center; gap: 0.6rem; }
.m-sheet__failure p { margin: 0 0 0.5rem; }
.m-sheet__head { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 0.5rem; }
.m-sheet__id { font-weight: 600; }
.m-sheet__chips { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: 0.5rem; }
.m-sheet__sentences { display: grid; gap: 0.9rem; margin: 1rem 0 1.25rem; }
.m-sentence__label { font-size: 0.85rem; font-weight: 650; margin: 0 0 0.15rem; color: rgba(var(--v-theme-on-surface), 0.72); }
.m-sentence__text { margin: 0; font-size: 1.08rem; line-height: 1.6; max-width: 62ch; }
.m-sheet__sub { font-size: 0.95rem; font-weight: 650; margin: 0 0 0.5rem; }
.m-facts { margin: 0 0 0.75rem; display: grid; gap: 0.55rem; }
.m-facts > div { display: grid; grid-template-columns: minmax(9rem, 13rem) 1fr; gap: 0.15rem 1rem; }
.m-facts dt { font-size: 0.875rem; color: rgba(var(--v-theme-on-surface), 0.72); }
.m-facts dd { margin: 0; font-size: 0.925rem; min-width: 0; }
.m-files { list-style: none; padding: 0; margin: 0; display: grid; gap: 0.15rem; }
.m-tech { margin: 0.25rem 0 1rem; }
.m-tech summary { cursor: pointer; font-size: 0.9rem; font-weight: 600; color: rgb(var(--v-theme-primary)); padding: 0.25rem 0; }
.m-tech[open] summary { margin-bottom: 0.6rem; }
.m-sheet__fix { margin: 0 0 1rem; }
.m-glossary { margin-bottom: 1rem; }
.m-glossary dl { margin: 0; display: grid; gap: 0.4rem; }
.m-glossary dt { font-weight: 600; font-size: 0.9rem; }
.m-glossary dd { margin: 0; font-size: 0.9rem; line-height: 1.5; }
@media (max-width: 560px) {
  .m-facts > div { grid-template-columns: 1fr; }
}
</style>
