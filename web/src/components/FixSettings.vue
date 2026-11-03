<template>
  <details class="m-fixset" @toggle="onToggle">
    <summary class="m-fixset__summary">{{ $t('fixset.title') }}</summary>

    <p v-if="loading" class="m-muted m-small" role="status">{{ $t('fixset.loading') }}</p>
    <div v-else-if="failure" role="alert" class="m-fixset__failure">
      <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
      <v-btn size="small" variant="tonal" color="primary" @click="load">{{ $t('app.retry') }}</v-btn>
    </div>

    <div v-else-if="view" class="m-fixset__body">
      <section class="m-fixset__group" :aria-labelledby="`${uid}-code`">
        <h4 :id="`${uid}-code`" class="m-fixset__label">{{ $t('fixset.code') }}</h4>
        <v-radio-group
          :model-value="view.fix_level"
          :aria-labelledby="`${uid}-code`"
          hide-details
          density="comfortable"
          :disabled="saving"
          @update:model-value="setLevel"
        >
          <v-radio v-for="l in levelList" :key="l.n" :value="l.n" color="primary">
            <template #label>
              <span class="m-fixset__level"><strong>{{ l.title }}</strong> — {{ l.text }}</span>
            </template>
          </v-radio>
        </v-radio-group>
        <FieldHelp id="project.level" :field="$t('fixset.code')" />
        <p v-if="view.fix_level >= 2 && consent && !consent.ready" class="m-fixset__note m-small">{{ $t('fixset.ai_levels') }}</p>
        <v-checkbox
          :model-value="view.auto_fix_minor"
          :label="$t('fixset.auto')"
          color="primary"
          density="comfortable"
          hide-details
          :disabled="saving"
          @update:model-value="setAuto"
        />
        <p class="m-muted m-small m-fixset__hint">{{ $t('fixset.auto_hint') }}</p>
        <FieldHelp id="project.auto" :field="$t('fixset.auto')" />
      </section>

      <section class="m-fixset__group" :aria-labelledby="`${uid}-ai`">
        <h4 :id="`${uid}-ai`" class="m-fixset__label">{{ $t('fixset.ai') }}</h4>
        <FieldHelp id="project.ai" :field="$t('fixset.ai')" />
        <template v-if="consent">
          <template v-if="consent.switch_mode">
            <p class="m-small">{{ $t('fixset.ai_strict') }}</p>
            <v-btn size="small" variant="tonal" color="primary" class="m-fixset__give" @click="dialog = true">{{ $t('fixset.ai_give') }}</v-btn>
          </template>
          <p v-else-if="consent.refusal" class="m-small">{{ consent.refusal }}</p>
          <p v-else-if="consent.consented && !(consent.lines || []).length" class="m-small">{{ $t('fixset.ai_given', { date: givenDate }) }}</p>
          <template v-else>
            <p class="m-small">{{ $t('fixset.ai_missing') }}</p>
            <v-btn size="small" variant="tonal" color="primary" class="m-fixset__give" @click="dialog = true">{{ $t('fixset.ai_give') }}</v-btn>
          </template>
        </template>
      </section>

      <section class="m-fixset__group" :aria-labelledby="`${uid}-server`">
        <h4 :id="`${uid}-server`" class="m-fixset__label">{{ $t('projsrv.title') }}</h4>
        <ul v-if="servers.length" class="m-fixset__servers m-small">
          <li v-for="t in servers" :key="t.id">
            <a :href="serverHref(t)">{{ t.name }}</a> ({{ envText(t) }}) : {{ serverLine(t) }}
          </li>
        </ul>
        <template v-else>
          <p class="m-small">{{ $t('projsrv.none') }}</p>
          <v-btn size="small" variant="text" color="primary" href="#/servers" class="m-fixset__give">{{ $t('projsrv.open') }}</v-btn>
        </template>
      </section>

      <p v-if="saved" class="m-small m-fixset__saved" role="status">{{ $t('fixset.saved') }}</p>
      <p v-if="saveError" class="m-small m-fixset__error" role="alert">{{ saveError }}</p>
    </div>

    <v-dialog v-model="dialog" max-width="520" scrollable persistent>
      <AiConsentDialog
        :project="name"
        :lines="consent ? consent.lines : []"
        :switch-mode="!!(consent && consent.switch_mode)"
        :busy="consentBusy"
        :error="consentError"
        @accept="giveConsent"
        @cancel="dialog = false"
      />
    </v-dialog>
  </details>
</template>

<script>
import FieldHelp from './FieldHelp.vue'
import AiConsentDialog from './AiConsentDialog.vue'
import { api } from '../api.js'
import { formatDate } from '../lib/digestView.js'
import { levelLabel, levels } from '../lib/fixView.js'
import { envLabel, serverStateLine, serversHash } from '../lib/serversView.js'

let seq = 0

// FixSettings is the fix part of a project's card, read when it is opened:
// "Corriger le code" (the four levels in sentences), the rule of the
// automatic minor updates, the AI consent, and the servers the project is
// deployed on (each one's fix settings live on its own sheet).
export default {
  name: 'FixSettings',
  components: { AiConsentDialog, FieldHelp },
  props: {
    name: { type: String, required: true },
  },
  data() {
    seq += 1
    return {
      uid: `fixset-${seq}`,
      loaded: false,
      loading: false,
      failure: null,
      view: null,
      consent: null,
      saving: false,
      saved: false,
      saveError: '',
      dialog: false,
      consentBusy: false,
      consentError: '',
      // servers are the servers this project is deployed on.
      servers: [],
    }
  },
  computed: {
    levelList() {
      return levels.map((n) => ({ n, ...levelLabel(n, this.$ui.lang) }))
    },
    givenDate() {
      return formatDate(this.consent?.given_at, this.$ui.lang) || '?'
    },
  },
  watch: {
    '$ui.lang'() {
      if (this.loaded) this.load()
    },
  },
  methods: {
    q(path) {
      return `${path}?lang=${encodeURIComponent(this.$ui.lang)}`
    },
    onToggle(e) {
      if (e.target.open && !this.loaded) this.load()
    },
    async load() {
      this.loading = !this.view
      this.failure = null
      try {
        const enc = encodeURIComponent(this.name)
        const [projects, consent, targets] = await Promise.all([api.get('/projects'), api.get(this.q(`/projects/${enc}/ai-consent`)),
          api.get(this.q('/targets')).catch(() => [])])
        this.view = (projects || []).find((p) => p.name === this.name) || null
        this.consent = consent
        this.servers = (targets || []).filter((t) => (t.projects || []).some((p) => p.project === this.name))
        this.loaded = true
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.loading = false
      }
    },
    async patch(body) {
      this.saving = true
      this.saved = false
      this.saveError = ''
      try {
        this.view = await api.patch(this.q(`/projects/${encodeURIComponent(this.name)}`), body)
        this.saved = true
      } catch (err) {
        if (err?.status !== 401) this.saveError = err?.offline ? this.$t('offline.hint') : err?.error || this.$t('error.generic')
      } finally {
        this.saving = false
      }
    },
    serverHref(t) {
      return serversHash(t.id)
    },
    envText(t) {
      return envLabel(t.env, this.$ui.lang)
    },
    serverLine(t) {
      return serverStateLine(t, this.$ui.lang)
    },
    setLevel(n) {
      if (typeof n === 'number' && n !== this.view.fix_level) this.patch({ fix_level: n })
    },
    setAuto(v) {
      this.patch({ auto_fix_minor: !!v })
    },
    async giveConsent() {
      this.consentBusy = true
      this.consentError = ''
      try {
        const body = this.consent?.switch_mode ? { switch_to_standard: true } : undefined
        this.consent = await api.post(this.q(`/projects/${encodeURIComponent(this.name)}/ai-consent`), body)
        this.dialog = false
      } catch (err) {
        this.consentError = err?.offline ? this.$t('offline.hint') : err?.error || this.$t('error.generic')
      } finally {
        this.consentBusy = false
      }
    },
  },
}
</script>

<style scoped>
.m-fixset { border-top: 1px solid rgba(var(--v-theme-on-surface), 0.08); padding: 0.75rem 0; }
.m-fixset__summary { cursor: pointer; font-size: 0.95rem; font-weight: 650; color: rgb(var(--v-theme-primary)); }
.m-fixset[open] .m-fixset__summary { margin-bottom: 0.75rem; }
.m-fixset__body { display: grid; gap: 1.1rem; }
.m-fixset__group { display: grid; gap: 0.35rem; }
.m-fixset__group p { margin: 0; }
.m-fixset__label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem; font-weight: 650; margin: 0; }
.m-fixset__level { line-height: 1.45; padding: 0.2rem 0; }
.m-fixset__hint { margin-left: 2.5rem !important; }
.m-fixset__note { padding: 0.4rem 0.7rem; border-radius: 8px; background: rgba(var(--v-theme-warning), 0.12); }
.m-fixset__give { justify-self: start; }
.m-fixset__servers { margin: 0; padding-left: 1.2rem; display: grid; gap: 0.2rem; }
.m-fixset__failure p { margin: 0 0 0.5rem; }
.m-fixset__saved { color: rgb(var(--v-theme-success)); margin: 0; }
.m-fixset__error { color: rgb(var(--v-theme-error)); margin: 0; }
</style>
