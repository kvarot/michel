<template>
  <v-card class="m-install" aria-labelledby="install-title">
    <v-card-title id="install-title" class="m-install__title">
      {{ upgrade ? $t('install.upgrade_title', { name: source.name }) : $t('install.title', { name: source.name }) }}
    </v-card-title>
    <v-card-text>
      <div v-if="loading" class="m-install__loading m-small m-muted" role="status">
        <v-progress-circular indeterminate size="18" width="2" color="primary" />
        {{ $t('install.loading') }}
      </div>

      <div v-else-if="failure" role="alert">
        <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('sources.failed') }}</p>
        <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
      </div>

      <template v-else-if="p">
        <p class="m-small m-code">{{ $t('install.version', { sha: p.sha }) }}</p>
        <p class="m-small">
          <span v-if="p.license.spdx === 'unknown'">{{ $t('install.license_unknown') }}</span>
          <span v-else>{{ $t('install.license', { spdx: p.license.spdx }) }}</span>
          <span v-if="licenseDiffers"> {{ $t('install.license_differs', { declared: p.declared_license }) }}</span>
        </p>
        <ul class="m-install__trust m-small">
          <li>{{ $t(p.trust.in_catalog ? 'install.trust.in_catalog' : 'install.trust.user') }}</li>
          <li v-if="!p.trust.archived">{{ $t('install.trust.unchecked') }}</li>
          <li v-else>{{ $t('install.trust.stars', { n: p.trust.stars, date: date(p.trust.pushed_at) }) }}</li>
          <li v-if="p.trust.archived === 'yes'" class="m-install__warn">{{ $t('install.trust.archived') }}</li>
        </ul>
        <h4 class="m-install__sub">{{ $t('install.files', { n: p.files.length, size: size(totalSize) }) }}</h4>
        <ul class="m-install__files m-small">
          <li v-for="f in p.files.slice(0, 30)" :key="f.path" class="m-code">{{ f.path }} <span class="m-muted">{{ size(f.size) }}</span></li>
          <li v-if="p.files.length > 30" class="m-muted">{{ $t('sheet.more', { n: p.files.length - 30 }) }}</li>
        </ul>
        <template v-if="(p.head || []).length">
          <h4 class="m-install__sub">{{ $t('install.head') }}</h4>
          <pre class="m-code m-install__pre">{{ p.head.slice(0, 40).join('\n') }}</pre>
        </template>
        <p class="m-install__never">{{ $t('install.never_run') }}</p>
        <template v-if="source.kind === 'skill'">
          <p v-if="p.old_dir" class="m-small">{{ $t('install.replaces', { old: p.old_dir }) }}</p>
          <p class="m-small">{{ $t('install.will_write', { dir: p.will_write }) }}</p>
        </template>
        <template v-else>
          <p v-if="!p.launch" class="m-small">{{ $t('install.mcp_no_launch') }}</p>
          <template v-else>
            <p class="m-small">{{ $t('install.mcp_nothing') }}</p>
            <div class="m-install__launch">
              <pre class="m-code m-install__pre">{{ p.launch }}</pre>
              <v-btn size="small" variant="tonal" @click="copy(p.launch)">{{ copied ? $t('install.copied') : $t('install.copy') }}</v-btn>
            </div>
            <p v-if="p.downloads" class="m-small m-install__warn">{{ $t('install.mcp_downloads') }}</p>
          </template>
        </template>
      </template>

      <template v-else-if="d">
        <p class="m-small m-code">{{ $t('install.versions', { from: short(d.from), to: short(d.to) }) }}</p>
        <p v-if="d.new_dir && d.old_dir && d.new_dir !== d.old_dir" class="m-small">{{ $t('install.replaces', { old: d.old_dir }) }}</p>
        <p v-if="d.new_dir" class="m-small">{{ $t('install.will_write', { dir: d.new_dir }) }}</p>
        <p v-if="(d.added || []).length" class="m-small">{{ $t('install.added', { files: d.added.join(', ') }) }}</p>
        <p v-if="(d.changed || []).length" class="m-small">{{ $t('install.changed', { files: d.changed.join(', ') }) }}</p>
        <p v-if="(d.removed || []).length" class="m-small">{{ $t('install.removed', { files: d.removed.join(', ') }) }}</p>
        <p v-if="!(d.added || []).length && !(d.changed || []).length && !(d.removed || []).length" class="m-small">{{ $t('install.same_files') }}</p>
        <template v-if="d.skill_md_diff">
          <h4 class="m-install__sub">{{ $t('install.skill_md') }}</h4>
          <pre class="m-code m-install__pre">{{ d.skill_md_diff.split('\n').slice(0, 40).join('\n') }}</pre>
        </template>
        <p class="m-install__never">{{ $t('install.never_run') }}</p>
      </template>

      <p v-if="installError" class="m-install__error" role="alert">{{ installError }}</p>
    </v-card-text>
    <v-card-actions class="m-install__actions">
      <v-btn variant="text" :disabled="installing" @click="$emit('cancel')">{{ $t('common.cancel') }}</v-btn>
      <v-btn color="primary" variant="flat" :disabled="!sha || loading" :loading="installing" @click="install">
        {{ upgrade ? $t('install.upgrade_confirm') : $t('install.confirm') }}
      </v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
import { api } from '../api.js'
import { formatDate } from '../lib/digestView.js'

export default {
  name: 'InstallDialog',
  props: {
    source: { type: Object, required: true },
  },
  emits: ['done', 'cancel'],
  data() {
    return { loading: true, failure: null, preview: null, installing: false, installError: '', copied: false }
  },
  computed: {
    upgrade() {
      return this.preview?.kind === 'upgrade'
    },
    p() {
      return this.preview?.install || null
    },
    d() {
      return this.preview?.upgrade || null
    },
    sha() {
      return this.p?.sha || this.d?.to || ''
    },
    totalSize() {
      return (this.p?.files || []).reduce((a, f) => a + f.size, 0)
    },
    licenseDiffers() {
      const p = this.p
      return p && p.declared_license && p.declared_license !== 'unknown' && p.declared_license !== p.license.spdx
    },
  },
  created() {
    this.load()
  },
  methods: {
    async load() {
      this.loading = true
      this.failure = null
      try {
        this.preview = await api.get(`/sources/${encodeURIComponent(this.source.key)}/preview?lang=${encodeURIComponent(this.$ui.lang)}`)
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
      }
    },
    async install() {
      this.installing = true
      this.installError = ''
      const action = this.upgrade ? 'upgrade' : 'install'
      try {
        const view = await api.post(`/sources/${encodeURIComponent(this.source.key)}/${action}?lang=${encodeURIComponent(this.$ui.lang)}`, { sha: this.sha })
        this.$emit('done', view)
      } catch (err) {
        if (err?.status !== 401) this.installError = [err?.error || this.$t('sources.failed'), err?.hint].filter(Boolean).join(' ')
      } finally {
        this.installing = false
      }
    },
    async copy(text) {
      try {
        await navigator.clipboard.writeText(text)
        this.copied = true
      } catch {
        this.copied = false
      }
    },
    size(n) {
      if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`
      if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KB`
      return `${n} B`
    },
    short(sha) {
      return String(sha || '').slice(0, 12)
    },
    date(d) {
      return formatDate(d, this.$ui.lang) || '?'
    },
  },
}
</script>

<style scoped>
.m-install__title { white-space: normal; }
.m-install__loading { display: flex; align-items: center; gap: 0.6rem; }
.m-install__sub { font-size: 0.95rem; font-weight: 650; margin: 1rem 0 0.35rem; }
.m-install__trust { margin: 0.5rem 0 0; padding-left: 1.2rem; }
.m-install__files { list-style: none; padding: 0; margin: 0; max-height: 12rem; overflow: auto; }
.m-install__pre {
  margin: 0;
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  background: rgba(var(--v-theme-on-surface), 0.06);
  white-space: pre-wrap;
  max-height: 16rem;
  overflow: auto;
}
.m-install__launch { display: flex; align-items: flex-start; gap: 0.5rem; }
.m-install__launch .m-install__pre { flex: 1; }
.m-install__never { font-weight: 650; margin: 1rem 0 0.5rem; }
.m-install__warn { color: rgb(var(--v-theme-warning)); font-weight: 600; }
.m-install__error { color: rgb(var(--v-theme-error)); margin: 0.75rem 0 0; }
.m-install__actions { justify-content: flex-end; }
</style>
