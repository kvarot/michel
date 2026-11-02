<template>
  <v-card class="m-hk" aria-labelledby="hostkey-title">
    <v-card-title id="hostkey-title" class="m-hk__title">{{ $t('servers.hostkey.title', { name: target.name }) }}</v-card-title>
    <v-card-text class="m-hk__body">
      <p v-if="loading" class="m-muted" role="status">
        <v-progress-circular indeterminate size="16" width="2" color="primary" />
        {{ $t('servers.hostkey.loading') }}
      </p>

      <div v-else-if="failure" role="alert" class="m-hk__failure">
        <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
        <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
        <v-btn size="small" variant="tonal" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
      </div>

      <template v-else-if="key">
        <!-- A key that changed since it was confirmed: a possible attack. -->
        <template v-if="changed">
          <v-alert type="error" variant="tonal" density="comfortable" class="m-hk__alert">
            <p class="m-hk__strong">{{ $t('servers.hostkey.changed') }}</p>
            <p>{{ $t('servers.hostkey.changed_why') }}</p>
          </v-alert>
          <p class="m-small m-code">{{ $t('servers.hostkey.was', { fp: key.pinned }) }}</p>
          <p class="m-small m-code">{{ $t('servers.hostkey.now', { fp: key.fingerprint }) }}</p>
          <v-checkbox v-model="replaceOk" :label="$t('servers.hostkey.replace_ok')" color="error" density="comfortable" hide-details />
        </template>

        <p v-else-if="key.matches" class="m-voice">{{ $t('servers.hostkey.pinned') }}</p>

        <template v-else>
          <p>{{ $t('servers.hostkey.first') }}</p>
          <p class="m-hk__fp m-code">{{ key.fingerprint }}</p>
          <p class="m-muted m-small">{{ $t('servers.hostkey.type', { type: key.key_type }) }}</p>
        </template>
      </template>

      <p v-if="error" class="m-hk__error" role="alert">{{ error }}</p>
      <p v-if="errorHint" class="m-muted m-small">{{ errorHint }}</p>
    </v-card-text>
    <v-card-actions class="m-hk__actions">
      <template v-if="changed">
        <v-btn variant="flat" color="primary" :disabled="busy" @click="$emit('close')">{{ $t('servers.hostkey.keep') }}</v-btn>
        <v-btn variant="outlined" color="error" :loading="busy" :disabled="busy || !replaceOk" @click="confirm(true)">{{ $t('servers.hostkey.replace') }}</v-btn>
      </template>
      <template v-else-if="key && !key.matches">
        <v-btn variant="text" :disabled="busy" @click="$emit('close')">{{ $t('servers.hostkey.cancel') }}</v-btn>
        <v-btn color="primary" variant="flat" :loading="busy" :disabled="busy" @click="confirm(false)">{{ $t('servers.hostkey.confirm') }}</v-btn>
      </template>
      <v-btn v-else variant="text" @click="$emit('close')">{{ $t('app.close') }}</v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
import { api } from '../api.js'

// HostKeyDialog shows the fingerprint a server presents so the user can
// compare it with the one their host gives, then confirm it. A key that
// changed since it was confirmed is shown as a possible attack: nothing is
// done unless the user ticks that they know why and asks to replace it
// (replace: true). Michel reads the key again on confirmation, so a
// fingerprint that changed meanwhile pins nothing.
export default {
  name: 'HostKeyDialog',
  props: {
    // target is the TargetView (id, name).
    target: { type: Object, required: true },
  },
  emits: ['close', 'confirmed'],
  data() {
    return { loading: true, failure: null, key: null, busy: false, error: '', errorHint: '', replaceOk: false }
  },
  computed: {
    changed() {
      return !!this.key && !!this.key.pinned && !this.key.matches
    },
  },
  watch: {
    'target.id'() {
      this.load()
    },
  },
  created() {
    this.load()
  },
  methods: {
    q(path) {
      return `${path}?lang=${encodeURIComponent(this.$ui.lang)}`
    },
    async load() {
      this.loading = true
      this.failure = null
      this.error = ''
      this.errorHint = ''
      this.replaceOk = false
      try {
        this.key = await api.get(this.q(`/targets/${encodeURIComponent(this.target.id)}/hostkey`))
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
      }
    },
    async confirm(replace) {
      if (!this.key || this.busy) return
      this.busy = true
      this.error = ''
      this.errorHint = ''
      try {
        const body = { fingerprint: this.key.fingerprint }
        if (replace) body.replace = true
        const v = await api.post(this.q(`/targets/${encodeURIComponent(this.target.id)}/hostkey`), body)
        this.$emit('confirmed', v)
      } catch (err) {
        if (err?.status === 401) return
        this.error = err?.offline ? this.$t('offline.hint') : err?.error || this.$t('error.generic')
        this.errorHint = err?.hint || ''
        // The server may show another key now: read it again.
        if (err?.status === 409) {
          const shown = this.error
          const hint = this.errorHint
          await this.load()
          this.error = shown
          this.errorHint = hint
        }
      } finally {
        this.busy = false
      }
    },
  },
}
</script>

<style scoped>
.m-hk__title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-hk__body { display: grid; gap: 0.6rem; }
.m-hk__body p { margin: 0; line-height: 1.55; }
.m-hk__fp {
  font-size: 1rem;
  padding: 0.6rem 0.75rem;
  border-radius: 8px;
  background: rgba(var(--v-theme-on-surface), 0.06);
}
.m-hk__strong { font-weight: 650; }
.m-hk__alert p { margin: 0 0 0.35rem; }
.m-hk__error { color: rgb(var(--v-theme-error)); }
.m-hk__failure { display: grid; gap: 0.4rem; justify-items: start; }
.m-hk__actions { justify-content: flex-end; flex-wrap: wrap; gap: 0.25rem; }
</style>
