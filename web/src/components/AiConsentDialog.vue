<template>
  <v-card class="m-consent" role="alertdialog" aria-labelledby="ai-consent-title">
    <v-card-title id="ai-consent-title" class="m-consent__title">{{ $t('fix.consent.title', { project }) }}</v-card-title>
    <v-card-text>
      <p class="m-consent__intro">{{ $t('fix.consent.intro') }}</p>
      <ul class="m-consent__lines">
        <li v-for="(l, i) in lines" :key="`${l.what}|${l.host || ''}|${i}`" class="m-voice m-consent__line">{{ l.text }}</li>
      </ul>
      <p v-if="error" class="m-consent__error" role="alert">{{ error }}</p>
    </v-card-text>
    <v-card-actions class="m-consent__actions">
      <v-btn variant="text" :disabled="busy" @click="$emit('cancel')">{{ $t('fix.consent.cancel') }}</v-btn>
      <v-btn color="primary" variant="flat" :loading="busy" @click="$emit('accept')">{{ $t('fix.consent.accept') }}</v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
// AiConsentDialog shows the lines of a project's AI consent exactly as the
// server wrote them (ruling 30: what leaves the computer, the hosts, and
// that the agent's code runs on a copy with the user's rights), with
// Accept and Cancel. The parent sends the consent.
export default {
  name: 'AiConsentDialog',
  props: {
    project: { type: String, default: '' },
    // lines are ConsentLineView: {what, text, host?, purpose?}.
    lines: { type: Array, default: () => [] },
    busy: { type: Boolean, default: false },
    error: { type: String, default: '' },
  },
  emits: ['accept', 'cancel'],
}
</script>

<style scoped>
.m-consent__title { white-space: normal; font-family: var(--m-voice); font-weight: 600; }
.m-consent__intro { margin: 0 0 0.6rem; font-weight: 600; }
.m-consent__lines { margin: 0; padding-left: 1.2rem; display: grid; gap: 0.6rem; }
.m-consent__line { font-size: 1.02rem; line-height: 1.55; }
.m-consent__error { color: rgb(var(--v-theme-error)); margin: 0.75rem 0 0; }
.m-consent__actions { justify-content: flex-end; }
</style>
