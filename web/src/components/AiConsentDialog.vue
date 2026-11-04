<template>
  <v-card class="m-consent" aria-labelledby="ai-consent-title">
    <v-card-title id="ai-consent-title" class="m-consent__title">{{ $t('fix.consent.title', { project }) }}</v-card-title>
    <v-card-text>
      <p v-for="k in view.plain" :key="k" class="m-voice m-consent__strict">{{ $t(k) }}</p>
      <!-- The advanced mode reads the whole text; the simple mode folds nothing but names: the plain paragraph above decides. -->
      <div v-if="switchMode && view.detailOpen" class="m-consent__detail">
        <p class="m-voice m-consent__strict">{{ $t('fix.consent.strict_intro') }}</p>
        <p class="m-consent__strict">{{ $t('fix.consent.strict_change') }}</p>
      </div>
      <details v-else-if="view.detailButton" class="m-consent__detail">
        <summary>{{ $t('fix.consent.detail') }}</summary>
        <p class="m-consent__strict">{{ $t('fix.consent.detail_names') }}</p>
      </details>
      <p class="m-consent__intro">{{ $t('fix.consent.intro') }}</p>
      <ul class="m-consent__lines">
        <li v-for="(l, i) in lines" :key="`${l.what}|${l.host || ''}|${i}`" class="m-voice m-consent__line">{{ l.text }}</li>
      </ul>
      <p v-if="error" class="m-consent__error" role="alert">{{ error }}</p>
    </v-card-text>
    <v-card-actions class="m-consent__actions m-consent__wrap">
      <v-btn variant="text" :disabled="busy" @click="$emit('cancel')">{{ $t('fix.consent.cancel') }}</v-btn>
      <v-btn color="primary" variant="flat" :loading="busy" :disabled="busy" @click="$emit('accept')">
        {{ $t(view.accept) }}
      </v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
// AiConsentDialog shows the lines of a project's AI consent exactly as the
// server wrote them (ruling 30: what leaves the computer, the hosts, and
// that the agent's code runs on a copy with the user's rights), with
// Accept and Cancel. Under strict_local it first says what that protection
// guarantees and that accepting loses it, for all of Michel, and the accept
// button says so. The parent sends the consent.
import { consentView } from '../lib/consentView.js'

export default {
  name: 'AiConsentDialog',
  props: {
    project: { type: String, default: '' },
    // kind says whose consent it is: a project's (files of a copy go out) or a server's.
    kind: { type: String, default: 'project' },
    // lines are ConsentLineView: {what, text, host?, purpose?}.
    lines: { type: Array, default: () => [] },
    // switchMode: the policy is strict_local; accepting also switches it to
    // standard, on this explicit click only (ruling 41).
    switchMode: { type: Boolean, default: false },
    busy: { type: Boolean, default: false },
    error: { type: String, default: '' },
  },
  emits: ['accept', 'cancel'],
  computed: {
    view() {
      return consentView({ kind: this.kind, switchMode: this.switchMode, advanced: !!this.$ui.advanced })
    },
  },
}
</script>

<style scoped>
.m-consent__title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-consent__strict { margin: 0 0 0.75rem; line-height: 1.55; }
.m-consent__intro { margin: 0 0 0.6rem; font-weight: 600; }
.m-consent__lines { margin: 0; padding-left: 1.2rem; display: grid; gap: 0.6rem; }
.m-consent__line { font-size: 1.02rem; line-height: 1.55; }
.m-consent__detail summary { cursor: pointer; font-weight: 600; color: rgb(var(--v-theme-primary)); padding: 0.25rem 0; }
.m-consent__detail[open] summary { margin-bottom: 0.5rem; }
.m-consent__error { color: rgb(var(--v-theme-error)); margin: 0.75rem 0 0; }
.m-consent__actions { justify-content: flex-end; }
.m-consent__wrap { flex-wrap: wrap; gap: 0.25rem; }
</style>
