<template>
  <ol class="m-path" role="list" :aria-label="$t('path.label')">
    <li
      v-for="s in steps"
      :key="s.key"
      class="m-path__step"
      :class="`m-path__step--${s.state}`"
      :aria-current="s.state === 'now' || s.state === 'stopped' ? 'step' : undefined"
    >
      <svg v-if="icons[s.state]" class="m-path__icon" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" focusable="false">
        <path :d="icons[s.state]" fill="currentColor" />
      </svg>
      <span class="m-path__label">{{ $t(`path.step.${s.label || s.key}`) }}</span>
      <span class="m-path__hidden">{{ $t(`path.state.${s.state}`) }}</span>
    </li>
  </ol>
</template>

<script>
// Each path is written here: the page's CSP allows no icon font. A step to come
// has no icon: it stays the plain one.
const icons = {
  done: 'M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z',
  now: 'M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 5a3 3 0 1 1 0 6 3 3 0 0 1 0-6z',
  stopped: 'M18.3 7.1 16.9 5.7 12 10.6 7.1 5.7 5.7 7.1l4.9 4.9-4.9 4.9 1.4 1.4 4.9-4.9 4.9 4.9 1.4-1.4-4.9-4.9z',
}

// FailurePath is the steps of a flaw, the signature of the guided
// interface: chevrons on a wide screen, a list on a phone. The state is said in
// words for a screen reader, in color and by an icon for the eye.
export default {
  name: 'FailurePath',
  props: {
    // steps is failurePath().steps.
    steps: { type: Array, required: true },
  },
  data() {
    return { icons }
  },
}
</script>

<style scoped>
.m-path {
  container-type: inline-size;
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 2px;
  font-size: 0.875rem;
  font-weight: 600;
}
.m-path__step {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  min-width: 0;
  min-height: 2.25rem;
  padding: 0.35rem 0.75rem;
  background: rgb(var(--v-theme-surface-variant));
  color: rgb(var(--v-theme-secondary));
}
.m-path__step:first-child { border-radius: 8px 8px 0 0; }
.m-path__step:last-child { border-radius: 0 0 8px 8px; }
.m-path__step--done { background: rgb(var(--v-theme-success)); color: rgb(var(--v-theme-on-primary)); }
.m-path__step--now { background: rgb(var(--v-theme-primary)); color: rgb(var(--v-theme-on-primary)); }
.m-path__step--stopped { background: rgb(var(--v-theme-error)); color: rgb(var(--v-theme-on-primary)); }
.m-path__icon { flex: none; }
.m-path__label { min-width: 0; line-height: 1.2; }
.m-path__hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
  border: 0;
}
@media (min-width: 640px) {
  .m-path { display: flex; flex-wrap: wrap; gap: 0; }
  .m-path__step {
    flex: 1 1 0;
    min-height: 2.75rem;
    padding: 0.4rem 0.8rem 0.4rem 1.4rem;
    margin-left: -6px;
    border-radius: 0;
    clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 50%, calc(100% - 12px) 100%, 0 100%, 12px 50%);
  }
  .m-path__step:first-child {
    margin-left: 0;
    padding-left: 0.75rem;
    border-radius: 8px 0 0 8px;
    clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 50%, calc(100% - 12px) 100%, 0 100%);
  }
  .m-path__step:last-child { border-radius: 0; }
}
/* The Fix page's column can be narrow on a wide screen (advanced mode, with the
   list): the chevrons would not hold their words there. */
@media (min-width: 640px) {
  @container (max-width: 459px) {
    .m-path__step, .m-path__step:first-child {
      flex: 0 0 100%;
      margin: 0 0 2px;
      padding: 0.35rem 0.75rem;
      border-radius: 0;
      clip-path: none;
    }
  }
}
</style>
