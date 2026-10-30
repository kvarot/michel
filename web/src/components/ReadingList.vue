<template>
  <section v-if="shown.length" class="m-reading" aria-labelledby="reading-title">
    <h2 id="reading-title" class="m-reading__title">{{ $t('reading.title') }}</h2>
    <p class="m-muted m-small m-reading__hint">{{ $t('reading.hint') }}</p>
    <ul class="m-reading__list">
      <li v-for="it in shown" :key="it.id" class="m-reading__item">
        <div class="m-reading__text">
          <p class="m-small m-muted m-reading__meta">{{ it.source }}<span v-if="date(it.published_at)"> · {{ date(it.published_at) }}</span></p>
          <a v-if="safeURL(it.url)" :href="it.url" target="_blank" rel="noopener noreferrer" class="m-reading__link">{{ it.title }}</a>
          <span v-else>{{ it.title }}</span>
        </div>
        <v-btn
          v-if="it.id"
          size="small"
          variant="tonal"
          color="primary"
          :loading="busy === it.id"
          :aria-label="$t('reading.read_label', { title: it.title })"
          @click="markRead(it)"
        >
          {{ $t('reading.read') }}
        </v-btn>
      </li>
    </ul>
    <p v-if="failed" class="m-small m-reading__failed" role="alert">{{ $t('reading.failed') }}</p>
  </section>
</template>

<script>
import { api } from '../api.js'
import { formatDate } from '../lib/digestView.js'

export default {
  name: 'ReadingList',
  props: {
    items: { type: Array, default: () => [] },
  },
  emits: ['read'],
  data() {
    return { done: [], busy: '', failed: false }
  },
  computed: {
    shown() {
      return this.items.filter((it) => !this.done.includes(it.id))
    },
  },
  methods: {
    date(d) {
      return formatDate(d, this.$ui.lang)
    },
    safeURL(u) {
      return /^https?:\/\//i.test(String(u || ''))
    },
    async markRead(it) {
      this.busy = it.id
      this.failed = false
      try {
        await api.post(`/sources/items/${encodeURIComponent(it.id)}/read`)
        this.done.push(it.id)
        this.$emit('read', it.id)
      } catch (err) {
        if (err?.status !== 401) this.failed = true
      } finally {
        this.busy = ''
      }
    },
  },
}
</script>

<style scoped>
.m-reading {
  border-top: 1px solid rgba(var(--v-theme-on-background), 0.1);
  margin-top: 2rem;
  padding-top: 1.25rem;
}
.m-reading__title { font-size: 1.2rem; font-weight: 650; margin: 0; }
.m-reading__hint { margin: 0.2rem 0 0.75rem; }
.m-reading__list { list-style: none; padding: 0; margin: 0; display: grid; gap: 0.75rem; }
.m-reading__item { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.m-reading__text { min-width: 0; }
.m-reading__meta { margin: 0; }
.m-reading__link { color: rgb(var(--v-theme-primary)); overflow-wrap: anywhere; }
.m-reading__failed { color: rgb(var(--v-theme-error)); }
</style>
