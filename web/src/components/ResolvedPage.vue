<template>
  <section aria-labelledby="resolved-title" class="m-resolved">
    <h1 id="resolved-title" class="m-verdict">{{ $t('resolved.title') }}</h1>
    <p class="m-muted">{{ $t('resolved.empty') }}</p>
  </section>
</template>

<script>
export default { name: 'ResolvedPage' }
</script>

<style scoped>
.m-resolved { display: grid; gap: 0.75rem; }
.m-resolved p { margin: 0; }
</style>
