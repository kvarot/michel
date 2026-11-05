<template>
  <p class="m-unread-value m-unread"><span aria-hidden="true">—</span></p>
  <p class="m-small m-unread m-unread-value__why">{{ $t('overview.unread') }}</p>
</template>

<script>
// UnreadValue is a number Michel could not read: a dash and a short
// sentence, never a 0. The dash is for the eye; a screen reader hears the sentence.
export default {
  name: 'UnreadValue',
}
</script>

<style scoped>
.m-unread-value { margin: 0.15rem 0 0; font-size: 2rem; font-weight: 700; line-height: 1.1; }
.m-unread-value__why { margin: 0; }
</style>
