<template>
  <li class="m-src" :class="`m-src--${source.state}`">
    <div class="m-src__line">
      <div class="m-src__main">
        <span class="m-src__name">{{ source.name }}</span>
        <span class="m-src__chips">
          <span class="m-src__state m-small" :class="`m-src__state--${source.state}`">{{ $t(stateKey) }}</span>
          <span v-for="b in badges" :key="b" class="m-tag m-small">{{ $t(b) }}</span>
          <span v-if="source.origin === 'user'" class="m-small m-muted">{{ $t('sources.origin_user') }}</span>
        </span>
      </div>
      <div class="m-src__controls">
        <v-switch
          :model-value="on"
          color="primary"
          density="compact"
          hide-details
          inset
          :disabled="busy"
          :aria-label="$t('sources.switch', { name: source.name })"
          @update:model-value="(on) => $emit('toggle', source, on)"
        />
        <v-menu location="bottom end">
          <template #activator="{ props }">
            <v-btn v-bind="props" variant="text" size="small" :icon="dots" :aria-label="$t('sources.menu', { name: source.name })" />
          </template>
          <v-list density="compact">
            <v-list-item v-for="a in actions" :key="a" :title="$t(`sources.action.${a}`)" @click="onAction(a)" />
          </v-list>
        </v-menu>
      </div>
    </div>
    <p v-if="source.hosts.length" class="m-small m-muted m-src__hosts m-code">{{ source.hosts.join(', ') }}</p>
    <p class="m-small m-src__last" :class="{ 'm-src__last--error': source.last_read.result === 'error' }">{{ lastRead }}</p>

    <div v-if="open" class="m-src__detail">
      <div v-if="loading" class="m-small m-muted" role="status">{{ $t('sources.loading') }}</div>
      <template v-else-if="detail">
        <p v-if="detail.note" class="m-src__note">{{ detail.note }}</p>
        <p v-if="safeURL(detail.url)" class="m-small">
          <a :href="detail.url" target="_blank" rel="noopener noreferrer">{{ $t('sources.detail.page') }}</a>
        </p>
        <h4 class="m-src__sub">{{ $t('sources.detail.hosts') }}</h4>
        <p v-if="!detail.rules.length" class="m-small">{{ $t('sources.detail.no_host') }}</p>
        <ul v-else class="m-src__rules m-small">
          <li v-for="r in detail.rules" :key="r.host">
            <span class="m-code">{{ r.host }}</span> — {{ $t(r.allowed ? 'sources.detail.allowed' : 'sources.detail.not_allowed') }}
          </li>
        </ul>
        <p v-if="detail.tech.length" class="m-small">{{ $t('sources.detail.tech', { tags: detail.tech.join(', ') }) }}</p>
        <p v-if="stars !== null" class="m-small">{{ $t('sources.detail.status', { stars, date: pushed }) }}</p>
        <template v-if="settings.length">
          <h4 class="m-src__sub">{{ $t('sources.detail.settings') }}</h4>
          <dl class="m-src__settings m-small">
            <div v-for="s in settings" :key="s.k"><dt class="m-code">{{ s.k }}</dt><dd class="m-code">{{ s.v }}</dd></div>
          </dl>
        </template>
        <template v-if="detail.items.length">
          <h4 class="m-src__sub">{{ $t('sources.detail.items') }}</h4>
          <ul class="m-src__items m-small">
            <li v-for="it in detail.items" :key="it.id">
              <a v-if="safeURL(it.url)" :href="it.url" target="_blank" rel="noopener noreferrer">{{ it.title }}</a>
              <span v-else>{{ it.title }}</span>
            </li>
          </ul>
        </template>
      </template>
      <p v-else-if="failure" class="m-small m-src__last--error" role="alert">{{ failure }}</p>
    </div>
  </li>
</template>

<script>
import { api } from '../api.js'
import { formatDate } from '../lib/digestView.js'
import { badgeKeys, lastReadText, rowActions, stateLabelKey, switchOn } from '../lib/sourcesView.js'

// mdi dots-vertical, for the default svg icon set.
const dots = 'M12,16A2,2 0 0,1 14,18A2,2 0 0,1 12,20A2,2 0 0,1 10,18A2,2 0 0,1 12,16M12,10A2,2 0 0,1 14,12A2,2 0 0,1 12,14A2,2 0 0,1 10,12A2,2 0 0,1 12,10M12,4A2,2 0 0,1 14,6A2,2 0 0,1 12,8A2,2 0 0,1 10,6A2,2 0 0,1 12,4Z'

export default {
  name: 'SourceRow',
  props: {
    source: { type: Object, required: true },
    now: { type: Date, required: true },
    busy: { type: Boolean, default: false },
  },
  emits: ['toggle', 'act'],
  data() {
    return { dots, open: false, loading: false, detail: null, failure: '' }
  },
  computed: {
    on() {
      return switchOn(this.source)
    },
    stateKey() {
      return stateLabelKey(this.source.state)
    },
    badges() {
      return badgeKeys(this.source)
    },
    lastRead() {
      return lastReadText(this.source.last_read, this.now, this.$t)
    },
    actions() {
      return rowActions(this.source)
    },
    stars() {
      const n = this.detail?.status?.stars
      return typeof n === 'number' ? n : null
    },
    pushed() {
      return formatDate(this.detail?.status?.pushed_at, this.$ui.lang) || '?'
    },
    settings() {
      const c = this.detail?.config || {}
      return Object.keys(c).sort().map((k) => ({ k, v: typeof c[k] === 'object' ? JSON.stringify(c[k]) : String(c[k]) }))
    },
  },
  watch: {
    '$ui.lang'() {
      if (this.open) this.loadDetail()
    },
  },
  methods: {
    safeURL(u) {
      return /^https?:\/\//i.test(String(u || ''))
    },
    onAction(a) {
      if (a !== 'detail') return this.$emit('act', a, this.source)
      this.open = !this.open
      if (this.open) this.loadDetail()
      return undefined
    },
    async loadDetail() {
      this.loading = true
      this.failure = ''
      try {
        this.detail = await api.get(`/sources/${encodeURIComponent(this.source.key)}?lang=${encodeURIComponent(this.$ui.lang)}`)
      } catch (err) {
        this.detail = null
        if (err?.status !== 401) this.failure = err?.error || this.$t('sources.failed')
      } finally {
        this.loading = false
      }
    },
  },
}
</script>

<style scoped>
.m-src { padding: 0.75rem 0; }
.m-src + .m-src { border-top: 1px dashed rgba(var(--v-theme-on-surface), 0.1); }
.m-src__line { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
.m-src__main { min-width: 0; display: grid; gap: 0.2rem; }
.m-src__name { font-weight: 650; overflow-wrap: anywhere; }
.m-src__chips { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem 0.5rem; }
.m-src__state {
  padding: 0 0.5rem;
  border-radius: 999px;
  font-weight: 650;
  background: rgba(var(--v-theme-on-surface), 0.08);
}
.m-src__state--on { color: rgb(var(--v-theme-success)); background: rgba(var(--v-theme-success), 0.12); }
.m-src__state--waiting_consent { color: rgb(var(--v-theme-warning)); background: rgba(var(--v-theme-warning), 0.14); }
.m-src__controls { display: flex; align-items: center; gap: 0.25rem; flex-shrink: 0; }
.m-src__hosts { margin: 0.25rem 0 0; }
.m-src__last { margin: 0.15rem 0 0; color: rgba(var(--v-theme-on-surface), 0.72); }
.m-src__last--error { color: rgb(var(--v-theme-error)); }
.m-src__detail {
  margin-top: 0.6rem;
  padding: 0.75rem 1rem;
  border-radius: 10px;
  background: rgba(var(--v-theme-on-surface), 0.035);
}
.m-src__detail p { margin: 0 0 0.4rem; }
.m-src__note { line-height: 1.5; }
.m-src__sub { font-size: 0.9rem; font-weight: 650; margin: 0.6rem 0 0.25rem; }
.m-src__rules, .m-src__items { margin: 0; padding-left: 1.2rem; }
.m-src__settings { margin: 0; display: grid; gap: 0.2rem; }
.m-src__settings > div { display: grid; grid-template-columns: minmax(7rem, 11rem) 1fr; gap: 0.75rem; }
.m-src__settings dd { margin: 0; overflow-wrap: anywhere; }
</style>
