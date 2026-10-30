<template>
  <section v-if="list.length" class="m-discover" aria-labelledby="discover-title">
    <h2 id="discover-title" class="m-discover__title">{{ $t('discover.title') }}</h2>
    <p class="m-muted m-small">{{ $t('discover.hint') }}</p>
    <div class="m-discover__cards">
      <article v-for="d in list" :key="d.repo" class="m-discover__card">
        <header class="m-discover__head">
          <a v-if="safeURL(d.html_url)" :href="d.html_url" target="_blank" rel="noopener noreferrer" class="m-code m-discover__repo">{{ d.repo }}</a>
          <span v-else class="m-code m-discover__repo">{{ d.repo }}</span>
          <span class="m-small m-muted">{{ $t('discover.stars', { n: d.stars }) }}</span>
        </header>
        <p v-if="d.description" class="m-small m-discover__desc">{{ d.description }}</p>
        <p class="m-small m-muted m-discover__topic">{{ d.topic }}</p>
        <form v-if="adding === d.repo" class="m-discover__form" @submit.prevent="add(d)">
          <v-select v-model="kind" :items="kindItems" :label="$t('discover.as')" density="compact" hide-details />
          <v-text-field v-model.trim="pin" :label="$t('add.pin')" :hint="$t('add.pin_hint')" persistent-hint density="compact" spellcheck="false" maxlength="40" />
          <div class="m-discover__actions">
            <v-btn variant="text" size="small" @click="adding = ''">{{ $t('common.cancel') }}</v-btn>
            <v-btn type="submit" color="primary" variant="flat" size="small" :loading="busy === d.repo">{{ $t('discover.add') }}</v-btn>
          </div>
        </form>
        <div v-else class="m-discover__actions">
          <v-btn variant="text" size="small" :loading="busy === d.repo" @click="ignore(d)">{{ $t('discover.ignore') }}</v-btn>
          <v-btn color="primary" variant="tonal" size="small" @click="startAdd(d)">{{ $t('discover.add') }}</v-btn>
        </div>
        <div v-if="failure && failure.repo === d.repo" class="m-discover__error m-small" role="alert">
          <p>{{ failure.error || $t('sources.failed') }}</p>
          <p v-if="failure.hint">{{ failure.hint }}</p>
        </div>
      </article>
    </div>
  </section>
</template>

<script>
import { api } from '../api.js'

export default {
  name: 'DiscoverList',
  emits: ['changed'],
  data() {
    return { list: [], adding: '', kind: 'skill', pin: '', busy: '', failure: null }
  },
  computed: {
    kindItems() {
      return ['skill', 'mcp'].map((k) => ({ title: this.$t(`add.kinds.${k}`), value: k }))
    },
  },
  created() {
    this.load()
  },
  methods: {
    async load() {
      try {
        this.list = await api.get('/sources/discoveries')
      } catch {
        this.list = []
      }
    },
    safeURL(u) {
      return /^https:\/\//i.test(String(u || ''))
    },
    startAdd(d) {
      this.adding = d.repo
      this.pin = ''
      this.failure = null
    },
    path(d) {
      return `/sources/discoveries/${d.repo.split('/').map(encodeURIComponent).join('/')}?lang=${encodeURIComponent(this.$ui.lang)}`
    },
    async act(d, body) {
      this.busy = d.repo
      this.failure = null
      try {
        await api.post(this.path(d), body)
        this.adding = ''
        await this.load()
        this.$emit('changed')
      } catch (err) {
        if (err?.status !== 401) this.failure = { repo: d.repo, error: err?.error, hint: err?.hint }
      } finally {
        this.busy = ''
      }
    },
    add(d) {
      return this.act(d, { action: 'add', kind: this.kind, pin: this.pin })
    },
    ignore(d) {
      return this.act(d, { action: 'ignore' })
    },
  },
}
</script>

<style scoped>
.m-discover { margin-top: 2.5rem; }
.m-discover__title { font-size: 1.2rem; font-weight: 650; margin: 0; }
.m-discover__cards { display: grid; gap: 0.9rem; grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); margin-top: 0.75rem; }
.m-discover__card {
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
  border-radius: 12px;
  padding: 0.9rem 1rem;
  display: grid;
  gap: 0.4rem;
  align-content: start;
}
.m-discover__head { display: flex; justify-content: space-between; align-items: baseline; gap: 0.5rem; }
.m-discover__repo { font-weight: 650; overflow-wrap: anywhere; }
a.m-discover__repo { color: rgb(var(--v-theme-primary)); }
.m-discover__desc, .m-discover__topic { margin: 0; }
.m-discover__form { display: grid; gap: 0.6rem; }
.m-discover__actions { display: flex; justify-content: flex-end; gap: 0.25rem; }
.m-discover__error { color: rgb(var(--v-theme-error)); }
.m-discover__error p { margin: 0; }
</style>
