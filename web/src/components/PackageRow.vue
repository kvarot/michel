<template>
  <li class="m-row" :class="`m-row--${item.severity}`">
    <div class="m-row__line">
      <span class="m-row__name m-code">{{ item.package }}</span>
      <span class="m-row__tags">
        <span v-if="item.decided" class="m-row__decided m-small">{{ $t('item.decided') }}</span>
        <span class="m-sev" :class="`m-sev--${item.severity}`">{{ $t(`severity.${item.severity}`) }}</span>
      </span>
    </div>
    <p class="m-row__meta m-small m-muted">
      <span v-if="item.osvIds.length">{{ $t('item.advisories', { n: item.osvIds.length }) }}</span>
      <span v-if="item.kind === 'new' || item.kind === 'gone'">{{ upgrade }}</span>
    </p>
    <p v-if="item.kind === 'new' && item.text" class="m-row__what m-voice">{{ item.text }}</p>
    <p v-else-if="item.kind === 'superseded'" class="m-row__what">
      <span class="m-row__reason">{{ reason }}</span>
      <span v-if="item.previousAction" class="m-muted m-small m-row__previous">
        {{ $t('item.previous', { label: $t(`decision.action.${item.previousAction}`) }) }}
      </span>
    </p>
    <p v-else-if="item.kind === 'due'" class="m-row__what" :class="{ 'm-row__overdue': item.overdue }">
      {{ $t(item.overdue ? 'item.overdue' : 'item.due', { date: dueDate }) }}
    </p>
    <v-btn
      v-if="item.findingIds.length"
      variant="text"
      size="small"
      class="m-row__toggle"
      :aria-expanded="String(open)"
      :aria-controls="sheetId"
      @click="open = !open"
    >
      {{ $t(open ? 'item.hide' : 'item.open') }}
    </v-btn>
    <div v-if="open" :id="sheetId" class="m-row__sheets">
      <FindingSheet v-for="id in item.findingIds" :key="id" :finding-id="id" @decided="$emit('decided')" />
    </div>
  </li>
</template>

<script>
import FindingSheet from './FindingSheet.vue'
import { formatDate } from '../lib/digestView.js'

let seq = 0

export default {
  name: 'PackageRow',
  components: { FindingSheet },
  props: {
    item: { type: Object, required: true },
  },
  emits: ['decided'],
  data() {
    seq += 1
    return { open: false, sheetId: `sheet-${seq}` }
  },
  computed: {
    upgrade() {
      if (!this.item.target) return this.$t('item.no_target')
      return this.$t('item.upgrade', { installed: this.item.installed || '?', target: this.item.target })
    },
    reason() {
      const known = ['severity_changed', 'fixed_version_changed', 'due_reached', 'reappeared_changed']
      return this.$t(`reason.${known.includes(this.item.text) ? this.item.text : 'unknown'}`)
    },
    dueDate() {
      return formatDate(this.item.text, this.$ui.lang)
    },
  },
}
</script>

<style scoped>
.m-row {
  position: relative;
  padding: 0.85rem 0 0.85rem 1rem;
}
.m-row + .m-row { border-top: 1px dashed rgba(var(--v-theme-on-surface), 0.1); }
.m-row::before {
  content: "";
  position: absolute;
  left: 0;
  top: 0.95rem;
  bottom: 0.95rem;
  width: 3px;
  border-radius: 2px;
  background: rgb(var(--m-sev));
}
.m-row--critical { --m-sev: var(--v-theme-critical); }
.m-row--high { --m-sev: var(--v-theme-high); }
.m-row--medium { --m-sev: var(--v-theme-medium); }
.m-row--low { --m-sev: var(--v-theme-low); }
.m-row--unknown { --m-sev: var(--v-theme-unknown); }
.m-row__line {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.25rem 0.75rem;
}
.m-row__name { font-size: 0.95rem; font-weight: 600; }
.m-row__tags { display: inline-flex; align-items: baseline; gap: 0.5rem; }
.m-row__decided {
  padding: 0 0.45rem;
  border: 1px solid rgba(var(--v-theme-on-surface), 0.25);
  border-radius: 999px;
  color: rgba(var(--v-theme-on-surface), 0.7);
}
.m-row__meta { display: flex; flex-wrap: wrap; gap: 0.1rem 0.9rem; margin: 0.2rem 0 0; }
.m-row__what { margin: 0.45rem 0 0; line-height: 1.55; max-width: 62ch; }
.m-voice.m-row__what { font-size: 1.05rem; }
.m-row__previous { display: block; margin-top: 0.15rem; }
.m-row__overdue { color: rgb(var(--v-theme-warning)); font-weight: 600; }
.m-row__toggle { margin: 0.35rem 0 0 -0.75rem; }
.m-row__sheets { display: grid; gap: 0.75rem; margin-top: 0.5rem; }
</style>
