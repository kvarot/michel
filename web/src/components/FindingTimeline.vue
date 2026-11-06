<template>
  <section v-if="!hidden" class="m-card m-tl" aria-labelledby="fix-timeline-title">
    <component :is="$ui.advanced ? 'h3' : 'h2'" id="fix-timeline-title" class="m-card__title">{{ $t('timeline.title') }}</component>
    <p v-if="state === 'reading'" class="m-small m-muted m-tl__line" role="status">{{ $t('timeline.reading') }}</p>
    <p v-else-if="state === 'unread' || !folded" class="m-small m-unread m-tl__line"><span aria-hidden="true">— </span>{{ $t('timeline.unread') }}</p>
    <p v-else-if="!folded.shown.length" class="m-small m-muted m-tl__line">{{ $t('timeline.empty') }}</p>
    <template v-else>
      <p class="m-small m-muted m-tl__line">{{ $t('timeline.hint') }}</p>
      <ol class="m-tl__list">
        <li v-for="(l, i) in visible" :key="`${l.at}-${l.kind}-${i}`" class="m-tl__item">
          <time class="m-small m-muted m-tl__date" :datetime="l.at">{{ l.date }}</time>
          <span class="m-voice m-tl__text">
            {{ l.text }}
            <span v-if="l.reconstructed" class="m-small m-tag--info m-tl__rec">{{ $t('timeline.reconstructed') }}</span>
          </span>
        </li>
      </ol>
      <button
        v-if="folded.hidden.length"
        type="button"
        class="m-tl__more m-small"
        :aria-expanded="open ? 'true' : 'false'"
        @click="open = !open"
      >
        {{ open ? $t('timeline.less') : $t('timeline.more', { n: folded.hidden.length }) }}
      </button>
      <p v-if="note" class="m-small m-muted m-tl__line">{{ note }}</p>
    </template>
  </section>
</template>

<script>
import { api } from '../api.js'
import { fold, historyNote, lines } from '../lib/timelineView.js'

// FindingTimeline is what happened to a flaw of a project, under its guided
// sheet: one line per entry, newest first, folded above 10 lines. A flaw the
// timeline does not cover (a server's, answered 404) shows nothing.
export default {
  name: 'FindingTimeline',
  props: {
    findingId: { type: String, required: true },
  },
  data() {
    return { state: 'reading', answer: null, hidden: false, open: false, seq: 0, now: new Date() }
  },
  computed: {
    folded() {
      return fold(lines(this.answer?.entries ?? null, this.$ui.lang, this.now, { advanced: !!this.$ui.advanced }))
    },
    visible() {
      return this.open ? [...this.folded.shown, ...this.folded.hidden] : this.folded.shown
    },
    note() {
      return historyNote(this.answer?.entries, this.answer?.history_start, this.$ui.lang)
    },
  },
  watch: {
    findingId() {
      this.load()
    },
  },
  mounted() {
    this.load()
  },
  methods: {
    /** load reads the timeline again; a late answer for another flaw is dropped. */
    async load() {
      const seq = ++this.seq
      this.state = 'reading'
      this.hidden = false
      this.open = false
      try {
        const answer = await api.timeline(this.findingId)
        if (seq !== this.seq) return
        this.answer = answer
        this.now = new Date()
        this.state = 'read'
      } catch (err) {
        if (seq !== this.seq) return
        this.answer = null
        this.hidden = err?.status === 404
        this.state = 'unread'
      }
    },
  },
}
</script>

<style scoped>
.m-tl { display: grid; gap: 0.5rem; margin-top: 1rem; }
.m-tl__line { margin: 0; }
.m-tl__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.5rem; }
.m-tl__item { display: grid; grid-template-columns: 11rem minmax(0, 1fr); gap: 0.75rem; align-items: baseline; padding-left: 0.75rem; border-left: 2px solid var(--m-line); }
.m-tl__date { font-variant-numeric: tabular-nums; }
.m-tl__rec { display: inline-block; margin-left: 0.35rem; padding: 0 0.4rem; border-radius: 6px; }
.m-tl__more {
  justify-self: start;
  min-height: 40px;
  padding: 0.35rem 0.8rem;
  border: 1px solid var(--m-line);
  border-radius: 8px;
  background: rgb(var(--v-theme-surface-variant));
  color: rgb(var(--v-theme-primary));
  font-weight: 600;
  cursor: pointer;
}
.m-tl__more:hover { text-decoration: underline; }
@media (max-width: 599px) {
  .m-tl__item { grid-template-columns: minmax(0, 1fr); gap: 0.1rem; }
}
</style>
