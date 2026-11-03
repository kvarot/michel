<template>
  <span class="m-fh">
    <button
      type="button"
      class="m-fh__btn"
      :aria-expanded="String(open)"
      :aria-controls="textId"
      :aria-label="$t('help.label', { field })"
      @click="open = !open"
      @keydown.esc="close"
    >
      <span aria-hidden="true">?</span>
    </button>
    <!-- In line, under the field: it works with a finger and hides nothing. -->
    <span v-if="open" :id="textId" class="m-fh__text m-small" role="note" @keydown.esc="close">{{ $t(key) }}</span>
  </span>
</template>

<script>
import { helpKey } from '../lib/helpView.js'

let seq = 0

// FieldHelp is the "?" next to a field: a real button that opens, right under
// the field, what the field is for, what to put in it and what happens on a
// mistake (text help.<id>). Échap closes it and gives the focus back to the button.
export default {
  name: 'FieldHelp',
  props: {
    // id is a help id of lib/helpView.js.
    id: { type: String, required: true },
    // field is the name of the field, for the name of the button.
    field: { type: String, required: true },
  },
  data() {
    seq += 1
    return { open: false, textId: `fh-${seq}` }
  },
  computed: {
    key() {
      return helpKey(this.id)
    },
  },
  methods: {
    close() {
      if (!this.open) return
      this.open = false
      const btn = this.$el.querySelector('button')
      if (btn) btn.focus()
    },
  },
}
</script>

<style scoped>
.m-fh { display: block; margin: 0.15rem 0 0.35rem; }
.m-fh__btn {
  position: relative;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  border: 1px solid rgb(var(--v-theme-primary));
  background: transparent;
  color: rgb(var(--v-theme-primary));
  font: inherit;
  font-size: 0.8rem;
  font-weight: 650;
  line-height: 1;
  cursor: pointer;
  padding: 0;
}
/* A hit area of 44 px on a phone, without growing the button. */
.m-fh__btn::after { content: ''; position: absolute; inset: -11px; }
@media (min-width: 600px) { .m-fh__btn::after { inset: -4px; } }
.m-fh__btn[aria-expanded='true'] { background: rgb(var(--v-theme-primary)); color: rgb(var(--v-theme-on-primary)); }
.m-fh__btn:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 3px; }
.m-fh__text {
  display: block;
  margin-top: 0.4rem;
  padding: 0.5rem 0.75rem;
  border-left: 3px solid rgb(var(--v-theme-primary));
  background: rgba(var(--v-theme-primary), 0.07);
  border-radius: 0 6px 6px 0;
  max-width: 60ch;
}
</style>
