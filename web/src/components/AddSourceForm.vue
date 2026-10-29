<template>
  <v-card class="m-add" aria-labelledby="add-title">
    <v-card-title id="add-title">{{ $t('add.title') }}</v-card-title>
    <v-card-text>
      <form id="add-source" class="m-add__form" @submit.prevent="submit">
        <v-select
          v-model="kind"
          :items="kindItems"
          :label="$t('add.kind')"
          :hint="$t('add.kind_hint')"
          persistent-hint
        />
        <template v-if="kind === 'feed'">
          <v-text-field v-model.trim="name" :label="$t('add.name')" :hint="$t('add.name_hint')" persistent-hint />
          <v-select v-model="format" :items="['auto', 'rss', 'atom', 'page', 'github_advisories']" :label="$t('add.format')" :hint="$t('add.format_hint_feed')" persistent-hint />
          <v-text-field v-if="format !== 'github_advisories'" v-model.trim="url" type="url" :label="$t('add.url')" :hint="$t('add.url_hint')" persistent-hint />
          <v-text-field v-else v-model.trim="repo" :label="$t('add.repo')" :hint="$t('add.repo_hint_feed')" persistent-hint spellcheck="false" />
          <v-text-field v-model="tech" :label="$t('add.tech')" :hint="$t('add.tech_hint')" persistent-hint />
        </template>
        <template v-else-if="kind === 'osv'">
          <v-text-field v-model.trim="ecosystem" :label="$t('add.ecosystem')" :hint="$t('add.ecosystem_hint')" persistent-hint spellcheck="false" />
        </template>
        <template v-else-if="kind === 'plugin'">
          <v-text-field v-model.trim="name" :label="$t('add.name')" :hint="$t('add.name_hint')" persistent-hint />
          <v-select v-model="pluginFormat" :items="['sarif', 'trivy_json']" :label="$t('add.format')" :hint="$t('add.format_hint_plugin')" persistent-hint />
          <v-select v-model="tool" :items="['generic', 'trivy', 'semgrep', 'codeql', 'zap']" :label="$t('add.tool')" :hint="$t('add.tool_hint')" persistent-hint />
          <v-text-field v-model.trim="input" :label="$t('add.input')" :hint="$t('add.input_hint')" persistent-hint spellcheck="false" />
        </template>
        <template v-else>
          <v-text-field v-model.trim="repo" :label="$t('add.repo')" :hint="$t('add.repo_hint')" persistent-hint spellcheck="false" />
          <v-text-field v-model.trim="pin" :label="$t('add.pin')" :hint="$t('add.pin_hint')" persistent-hint spellcheck="false" maxlength="40" />
          <v-text-field v-if="kind === 'skill'" v-model.trim="path" :label="$t('add.path')" :hint="$t('add.path_hint')" persistent-hint spellcheck="false" />
          <v-text-field v-model.trim="name" :label="$t('add.name')" :hint="$t('add.name_hint')" persistent-hint />
        </template>
      </form>
      <div v-if="failure" class="m-add__error" role="alert">
        <p>{{ failure.error || $t('sources.failed') }}</p>
        <p v-if="failure.hint" class="m-small">{{ failure.hint }}</p>
      </div>
    </v-card-text>
    <v-card-actions class="m-add__actions">
      <v-btn variant="text" :disabled="saving" @click="$emit('cancel')">{{ $t('common.cancel') }}</v-btn>
      <v-btn type="submit" form="add-source" color="primary" variant="flat" :loading="saving">{{ $t('add.submit') }}</v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
import { api } from '../api.js'

export default {
  name: 'AddSourceForm',
  emits: ['added', 'cancel'],
  data() {
    return {
      kind: 'feed', name: '', url: '', format: 'auto', pluginFormat: 'sarif', repo: '', ecosystem: '', tool: 'generic',
      input: '', path: '', pin: '', tech: '', saving: false, failure: null,
    }
  },
  computed: {
    kindItems() {
      return ['feed', 'osv', 'plugin', 'skill', 'mcp'].map((k) => ({ title: this.$t(`add.kinds.${k}`), value: k }))
    },
  },
  methods: {
    /** body sends only the fields of the chosen kind, as michel source add takes them. */
    body() {
      switch (this.kind) {
        case 'feed': {
          const tech = this.tech.split(',').map((t) => t.trim()).filter(Boolean)
          const b = { kind: 'feed', name: this.name, format: this.format, tech }
          if (this.format === 'github_advisories') b.repo = this.repo
          else b.url = this.url
          return b
        }
        case 'osv':
          return { kind: 'osv', ecosystem: this.ecosystem }
        case 'plugin':
          return { kind: 'plugin', name: this.name, format: this.pluginFormat, tool: this.tool, input: this.input }
        default:
          return { kind: this.kind, repo: this.repo, pin: this.pin, path: this.kind === 'skill' ? this.path : '', name: this.name }
      }
    },
    async submit() {
      this.saving = true
      this.failure = null
      try {
        const view = await api.post(`/sources?lang=${encodeURIComponent(this.$ui.lang)}`, this.body())
        this.$emit('added', view)
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.saving = false
      }
    },
  },
}
</script>

<style scoped>
.m-add__form { display: grid; gap: 0.9rem; }
.m-add__error { color: rgb(var(--v-theme-error)); margin-top: 0.75rem; }
.m-add__error p { margin: 0; }
.m-add__actions { justify-content: flex-end; }
</style>
