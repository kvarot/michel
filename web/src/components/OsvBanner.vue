<template>
  <v-alert v-if="stale" type="warning" variant="tonal" density="comfortable" class="m-osv" role="status">
    <p class="m-osv__line">{{ $t('osv.stale', { date: date }) }}</p>
    <p class="m-osv__line">{{ $t('osv.stale_hint') }}</p>
  </v-alert>
</template>

<script>
import { formatDate } from '../lib/digestView.js'

export default {
  name: 'OsvBanner',
  props: {
    fetchedAt: { type: String, default: '' },
    stale: { type: Boolean, default: false },
  },
  computed: {
    date() {
      return formatDate(this.fetchedAt, this.$ui.lang) || '?'
    },
  },
}
</script>

<style scoped>
.m-osv { margin-bottom: 1.25rem; }
.m-osv__line { margin: 0; }
.m-osv__line + .m-osv__line { margin-top: 0.25rem; }
</style>
