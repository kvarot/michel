<template>
  <article class="m-card m-curve" aria-labelledby="ov-curve">
    <h3 id="ov-curve" class="m-card__title">{{ $t('curve.title') }}</h3>
    <p class="m-small m-muted m-curve__line">{{ $t('curve.hint') }}</p>
    <p v-if="state === 'reading'" class="m-small m-muted m-curve__line" role="status">{{ $t('curve.reading') }}</p>
    <p v-else-if="state === 'unread' || !s" class="m-small m-unread m-curve__line"><span aria-hidden="true">— </span>{{ $t('curve.unread') }}</p>
    <p v-else-if="!s.summary || !s.max" class="m-small m-muted m-curve__line">{{ summary }}</p>
    <template v-else>
      <ul class="m-curve__legend m-small">
        <li v-for="p in s.paths" :key="p.severity">
          <span class="m-curve__key" :class="`m-curve__key--${p.severity}`" aria-hidden="true" />
          <span class="m-sev" :class="`m-sev--${p.severity}`">{{ $t(`severity.${p.severity}`) }}</span>
        </li>
        <li v-if="s.since">
          <span class="m-curve__key m-curve__key--dashed" aria-hidden="true" />
          {{ $t('curve.legend_dashed') }}
        </li>
      </ul>
      <svg
        class="m-curve__chart"
        :viewBox="`0 0 ${s.width} ${s.height + 22}`"
        role="img"
        :aria-label="$t('curve.title')"
        aria-describedby="ov-curve-summary"
        focusable="false"
      >
        <g v-for="p in s.paths" :key="p.severity" :class="`m-curve__band--${p.severity}`">
          <path v-if="p.areaReconstructed" :d="p.areaReconstructed" class="m-curve__area m-curve__area--rec" />
          <path v-if="p.area" :d="p.area" class="m-curve__area" />
          <path v-if="p.lineReconstructed" :d="p.lineReconstructed" class="m-curve__edge m-curve__edge--rec" />
          <path v-if="p.line" :d="p.line" class="m-curve__edge" />
        </g>
        <line v-if="s.since && s.reconstructedX < s.width" :x1="s.reconstructedX" :x2="s.reconstructedX" y1="0" :y2="s.height" class="m-curve__cut" />
        <line x1="0" :x2="s.width" :y1="s.height" :y2="s.height" class="m-curve__axis" />
        <text v-for="tk in ticks" :key="tk.date" :x="tk.x" :y="s.height + 16" :text-anchor="tk.anchor" class="m-curve__tick">{{ tk.label }}</text>
      </svg>
      <p id="ov-curve-summary" class="m-small m-curve__line">{{ summary }}</p>
      <p v-if="recNote" class="m-small m-muted m-curve__line">{{ recNote }}</p>
      <p class="m-small m-muted m-curve__line">{{ sevNote }}</p>
    </template>
  </article>
</template>

<script>
import { localDay, reconstructedNote, series, severityNote, summaryText } from '../lib/openCurveView.js'
import { shortDay } from '../lib/overviewView.js'

// OpenCurve is the card of the open flaws over 90 days on the overview: the
// stacked curve by severity, its equivalent text, and the sentences on the
// reconstructed part and on the severity used.
export default {
  name: 'OpenCurve',
  props: {
    // stats is GET /stats/open, null when it could not be read; state is reading, read or unread.
    stats: { type: Object, default: null },
    state: { type: String, default: 'reading' },
  },
  computed: {
    s() {
      return series(this.stats?.days ?? null)
    },
    summary() {
      return summaryText(this.s, this.$ui.lang)
    },
    recNote() {
      return reconstructedNote(this.s, this.$ui.lang)
    },
    sevNote() {
      return severityNote(this.$ui.lang)
    },
    // ticks: the first, the middle and the last day under the axis.
    ticks() {
      const st = this.s?.stack || []
      if (!st.length) return []
      const n = st.length
      const idx = n === 1 ? [0] : [...new Set([0, Math.floor((n - 1) / 2), n - 1])]
      return idx.map((i) => {
        const x = n === 1 ? this.s.width / 2 : (i * this.s.width) / (n - 1)
        const anchor = n === 1 ? 'middle' : i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'
        return { date: st[i].date, x, anchor, label: shortDay(localDay(st[i].date), this.$ui.lang) }
      })
    },
  },
}
</script>

<style scoped>
.m-curve { display: grid; gap: 0.5rem; margin-top: 0.75rem; align-content: start; }
.m-curve__line { margin: 0; }
.m-curve__legend { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 0.4rem 1rem; }
.m-curve__legend li { display: inline-flex; align-items: center; gap: 0.35rem; }
.m-curve__key { display: inline-block; width: 14px; height: 10px; border-radius: 2px; }
.m-curve__key--critical { background: rgb(var(--v-theme-critical)); }
.m-curve__key--high { background: rgb(var(--v-theme-high)); }
.m-curve__key--medium { background: rgb(var(--v-theme-medium)); }
.m-curve__key--low { background: rgb(var(--v-theme-low)); }
.m-curve__key--unknown { background: rgb(var(--v-theme-unknown)); }
.m-curve__key--dashed { height: 0; border-top: 2px dashed rgb(var(--v-theme-on-surface)); border-radius: 0; }
.m-curve__chart { width: 100%; height: auto; max-height: 220px; display: block; }
.m-curve__area { fill-opacity: 0.8; stroke: none; }
.m-curve__area--rec { fill-opacity: 0.35; }
.m-curve__edge { fill: none; stroke-width: 1.5; vector-effect: non-scaling-stroke; }
.m-curve__edge--rec { stroke-dasharray: 4 3; }
.m-curve__band--critical { fill: rgb(var(--v-theme-critical)); stroke: rgb(var(--v-theme-critical)); }
.m-curve__band--high { fill: rgb(var(--v-theme-high)); stroke: rgb(var(--v-theme-high)); }
.m-curve__band--medium { fill: rgb(var(--v-theme-medium)); stroke: rgb(var(--v-theme-medium)); }
.m-curve__band--low { fill: rgb(var(--v-theme-low)); stroke: rgb(var(--v-theme-low)); }
.m-curve__band--unknown { fill: rgb(var(--v-theme-unknown)); stroke: rgb(var(--v-theme-unknown)); }
.m-curve__cut { stroke: rgb(var(--v-theme-on-surface)); stroke-width: 1; stroke-dasharray: 3 3; vector-effect: non-scaling-stroke; }
.m-curve__axis { stroke: rgb(var(--v-theme-line)); stroke-width: 1; }
.m-curve__tick { fill: rgb(var(--v-theme-secondary)); font-size: 12px; }
</style>
