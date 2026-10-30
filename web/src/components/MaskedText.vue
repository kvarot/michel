<template>
  <span class="m-masked"><template v-for="(part, i) in parts" :key="i"><span
    v-if="part.secret"
    class="m-secret"
    tabindex="0"
    :title="$t('fix.secret_hint')"
    :aria-label="`${$t('fix.secret')}. ${$t('fix.secret_hint')}`"
  >{{ $t('fix.secret') }}<v-tooltip activator="parent" location="top" max-width="320">{{ $t('fix.secret_hint') }}</v-tooltip></span><template v-else>{{ part.text }}</template></template></span>
</template>

<script>
import { splitMasked } from '../lib/fixView.js'

// MaskedText shows a text from the API with each masked secret
// ("[secret-…]", always whole) as a small neutral chip: the page never
// unmasks (ruling 38).
export default {
  name: 'MaskedText',
  props: {
    text: { type: String, default: '' },
  },
  computed: {
    parts() {
      return splitMasked(this.text)
    },
  },
}
</script>

<style scoped>
.m-masked { white-space: inherit; }
.m-secret {
  display: inline-block;
  padding: 0 0.4rem;
  margin: 0 0.1rem;
  border-radius: 999px;
  font-family: var(--m-ui);
  font-size: 0.8em;
  line-height: 1.5;
  white-space: nowrap;
  color: rgba(var(--v-theme-on-surface), 0.78);
  background: rgba(var(--v-theme-on-surface), 0.08);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.18);
  cursor: help;
}
</style>
