<template>
  <v-card class="m-consent" role="alertdialog" aria-labelledby="consent-title">
    <v-card-title id="consent-title" class="m-consent__title">{{ $t('consent.title') }}</v-card-title>
    <v-card-text>
      <p class="m-consent__name">{{ name }}</p>
      <section v-for="c in consent" :key="`${c.host}|${c.purpose}`" class="m-consent__host">
        <p class="m-voice m-consent__what">{{ sentence(c) }}</p>
        <p class="m-small m-consent__write">{{ $t('consent.will_write') }}</p>
        <pre class="m-code m-consent__rule">{{ c.rule }}</pre>
      </section>
      <p class="m-muted m-small">{{ $t('consent.why') }}</p>
      <p v-if="error" class="m-consent__error" role="alert">{{ error }}</p>
    </v-card-text>
    <v-card-actions class="m-consent__actions">
      <v-btn variant="text" :disabled="busy" @click="$emit('cancel')">{{ $t('consent.later') }}</v-btn>
      <v-btn color="primary" variant="flat" :loading="busy" @click="$emit('accept')">{{ $t('consent.accept') }}</v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
import { consentSentence } from '../lib/sourcesView.js'

export default {
  name: 'ConsentDialog',
  props: {
    name: { type: String, default: '' },
    // consent is the list of the 409 answer: {host, purpose, what, rule}.
    consent: { type: Array, default: () => [] },
    busy: { type: Boolean, default: false },
    error: { type: String, default: '' },
  },
  emits: ['accept', 'cancel'],
  methods: {
    sentence(c) {
      return consentSentence(c, this.$t)
    },
  },
}
</script>

<style scoped>
.m-consent__title { white-space: normal; }
.m-consent__name { font-weight: 650; margin: 0 0 0.75rem; }
.m-consent__host + .m-consent__host { margin-top: 1rem; }
.m-consent__what { font-size: 1.05rem; line-height: 1.55; margin: 0 0 0.5rem; }
.m-consent__write { margin: 0 0 0.25rem; }
.m-consent__rule {
  margin: 0 0 0.75rem;
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  background: rgba(var(--v-theme-on-surface), 0.06);
  white-space: pre-wrap;
}
.m-consent__error { color: rgb(var(--v-theme-error)); margin: 0.5rem 0 0; }
.m-consent__actions { justify-content: flex-end; }
</style>
