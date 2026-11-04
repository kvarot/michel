<template>
  <div class="m-todo">
    <div v-if="!loaded" class="m-todo__loading" role="status">
      <v-progress-circular indeterminate color="primary" size="28" width="3" />
      <p class="m-muted">{{ $t('app.loading') }}</p>
    </div>

    <template v-else>
      <header class="m-todo__head">
        <div class="m-todo__say">
          <h1 id="todo-title" class="m-verdict">{{ nothingWatched ? $t('empty.todo') : todo.head }}</h1>
          <p v-if="nothingWatched" class="m-muted m-todo__sub">{{ $t('empty.todo_hint') }}</p>
          <p v-else-if="todo.sub" class="m-muted m-todo__sub">{{ todo.sub }}</p>
          <p v-if="$ui.advanced && digest.since_label" class="m-muted m-small m-todo__sub">{{ digest.since_label }}</p>
        </div>
        <v-btn variant="text" class="m-todo__refresh" :loading="refreshing" @click="$emit('refresh')">{{ $t('app.refresh') }}</v-btn>
      </header>

      <FirstSteps v-if="guideShown" ref="guide" :steps="guideSteps" :git="guideGit" @dismiss="dismissGuide" />
      <p v-else-if="guideNotice" ref="notice" class="m-small m-todo__notice" role="status" tabindex="-1">{{ $t('guide.dismissed') }}</p>
      <p v-if="lostShown" ref="lost" class="m-small m-todo__notice" role="status" tabindex="-1">{{ $t('guide.unreadable') }}</p>
      <v-btn v-if="nothingWatched && !guideShown" class="m-todo__empty-action" color="primary" variant="flat" href="#/projects">{{ $t('empty.todo_action') }}</v-btn>

      <OsvBanner :fetched-at="osvFetchedAt" :stale="digest.osv_stale" />

      <v-alert v-if="digest.failed_scans > 0" type="warning" variant="tonal" class="m-block" density="comfortable">
        {{ $t('today.failed_scans', { n: digest.failed_scans }) }}
      </v-alert>

      <ul v-if="todo.lines.length" class="m-panel m-todo__list" :aria-label="$t('todo.list')">
        <li v-for="line in todo.lines" :key="line.id" class="m-todo__row">
          <span class="m-small m-todo__word" :class="`m-tag--${line.tone}`">{{ line.word }}</span>
          <div class="m-todo__text">
            <p class="m-todo__title">{{ line.title }}</p>
            <p class="m-muted m-small m-todo__where">{{ line.where }}</p>
          </div>
          <v-btn
            v-if="line.action"
            class="m-todo__action"
            color="primary"
            :variant="line.tone === 'look' ? 'outlined' : 'flat'"
            :href="line.action.href"
          >
            {{ line.action.label }}
          </v-btn>
        </li>
      </ul>

      <p v-if="!$ui.advanced && digest.exploited_decided > 0" class="m-small m-todo__decided">{{ $t('exploited.decided', { n: digest.exploited_decided }) }}</p>

      <section v-if="unseen.length" class="m-panel m-todo__unseen" aria-labelledby="unseen-title">
        <h2 id="unseen-title" class="m-todo__unseen-title">{{ $t('todo.unseen.title') }}</h2>
        <ul class="m-todo__unseen-list">
          <li v-for="u in unseen" :key="u.key">{{ u.text }}</li>
        </ul>
      </section>

      <ExploitedBanner v-if="$ui.advanced" class="m-todo__exploited" :exploited="digest.exploited || []" :decided="digest.exploited_decided || 0" @decided="$emit('decided')" />

      <ReadingList v-if="$ui.advanced" :items="digest.reading || []" />

      <details v-if="$ui.advanced && catalog.line" class="m-catalog">
        <summary class="m-small">{{ catalog.line }}</summary>
        <ul class="m-catalog__list m-small">
          <li v-if="(catalog.failed || []).length">{{ $t('catalog.failed', { keys: catalog.failed.join(', ') }) }}</li>
          <li v-if="(catalog.waiting_consent || []).length">{{ $t('catalog.waiting', { keys: catalog.waiting_consent.join(', ') }) }}</li>
          <li v-if="(catalog.unreachable || []).length">{{ $t('catalog.unreachable', { keys: catalog.unreachable.join(', ') }) }}</li>
          <li v-if="(catalog.new_versions || []).length">{{ $t('catalog.new_versions', { names: catalog.new_versions.map((v) => v.name).join(', ') }) }}</li>
          <li v-if="digest.discover_new > 0">{{ $t('catalog.discover', { n: digest.discover_new }) }}</li>
        </ul>
        <v-btn variant="text" size="small" color="primary" href="#/sources" class="m-catalog__open">{{ $t('catalog.open') }}</v-btn>
      </details>
    </template>
  </div>
</template>

<script>
import ExploitedBanner from './ExploitedBanner.vue'
import FirstSteps from './FirstSteps.vue'
import OsvBanner from './OsvBanner.vue'
import ReadingList from './ReadingList.vue'
import { api } from '../api.js'
import { dismissGuide, emptyInstall, guideFlaw, guideGitQuestion, guideSteps, guideUnseen, guideVisible, guideWaiting, helpLostNow } from '../lib/guideView.js'
import { save } from '../lib/storage.js'
import { buildTodo, projectsToRead, serversToRead, unseenBelow } from '../lib/todoView.js'

// waitEvery is how long the page waits before it reads again, while a check runs.
const waitEvery = 5000

export default {
  name: 'TodayPage',
  components: { ExploitedBanner, FirstSteps, OsvBanner, ReadingList },
  props: {
    digest: { type: Object, required: true },
    meta: { type: Object, default: null },
    refreshing: { type: Boolean, default: false },
  },
  emits: ['decided', 'refresh'],
  data() {
    return {
      // loaded stays false until the first reading ended: an empty list is
      // never said before Michel has looked at the fixes and the servers.
      loaded: false,
      // readDigest is the digest the reads below go with: a newer one would
      // call « not read » what is still being read.
      readDigest: null,
      attempts: [],
      servers: [],
      // projectViews is GET /projects, null when it could not be read: the guide reads it.
      projectViews: null,
      guideNotice: false,
      // helpLost: "Revoir le guide" was asked on this page; the line it may bring is lostShown.
      helpLost: false,
      // timer reads the page again while a check runs, so the guide follows it.
      timer: null,
      details: {},
      findings: {},
      now: new Date(),
      // seq drops the answers of a reading that a newer one replaced.
      seq: 0,
    }
  },
  computed: {
    todo() {
      return buildTodo({
        digest: this.readDigest,
        attempts: this.attempts,
        servers: this.servers,
        details: this.details,
        findings: this.findings,
        lang: this.$ui.lang,
        now: this.now,
        advanced: this.$ui.advanced,
      })
    },
    unseen() {
      return unseenBelow(guideUnseen(this.todo.unseen, this.nothingWatched))
    },
    nothingWatched() {
      return emptyInstall(this.projectViews, this.servers)
    },
    guideSteps() {
      const flaw = guideFlaw({ lines: this.todo.lines, projects: this.projectViews, servers: this.servers })
      return guideSteps({ projects: this.projectViews, servers: this.servers, read: this.$ui.guide.read, anyFinding: flaw.any, flawHref: flaw.href })
    },
    // lostShown: asked for the guide, and a list could not be read (N-B).
    lostShown() {
      return helpLostNow({ asked: this.helpLost, loaded: this.loaded, guideShown: this.guideShown, projectViews: this.projectViews, servers: this.servers })
    },
    // Where a person stands is only said once both lists were read.
    guideShown() {
      return !!this.projectViews && !!this.servers && guideVisible(this.guideSteps, this.$ui.guide)
    },
    guideGit() {
      return guideGitQuestion(this.projectViews)
    },
    catalog() {
      return this.digest.catalog || {}
    },
    osvFetchedAt() {
      const t = this.digest.osv_fetched_at || ''
      return t.startsWith('0001-') ? '' : t
    },
  },
  watch: {
    // A new digest (refresh, decision, language) reads the rest again.
    digest() {
      this.load()
    },
    // "Revoir le guide" from the menu, on this very page.
    '$ui.guide.asks'() {
      this.guideNotice = false
      this.helpLost = true
      this.$nextTick(() => (this.lostShown ? this.$refs.lost : this.$refs.guide)?.focus())
    },
  },
  created() {
    this.load()
  },
  beforeUnmount() {
    clearTimeout(this.timer)
  },
  methods: {
    /**
     * load reads the fixes, the servers, their detail and the findings of the
     * projects with something open. What cannot be read stays null or missing:
     * the list then says so instead of leaving it out in silence.
     */
    async load() {
      const seq = ++this.seq
      clearTimeout(this.timer)
      const lang = `lang=${encodeURIComponent(this.$ui.lang)}`
      const read = (path) => api.get(path).then((r) => r || []).catch(() => null)
      const digest = this.digest
      const [attempts, servers, projectViews] = await Promise.all([read(`/fixes?${lang}`), read(`/targets?${lang}`), read(`/projects?${lang}`)])
      if (seq !== this.seq) return
      const wanted = serversToRead(servers)
      const toRead = projectsToRead(digest, attempts)
      const [answers, lists] = await Promise.all([
        Promise.all(wanted.map((s) => read(`/targets/${encodeURIComponent(s.id)}?${lang}`))),
        Promise.all(toRead.map((p) => read(`/projects/${encodeURIComponent(p.name)}/findings?${lang}`))),
      ])
      if (seq !== this.seq) return
      const details = {}
      wanted.forEach((s, i) => {
        if (answers[i]) details[s.id] = answers[i]
      })
      const findings = {}
      toRead.forEach((p, i) => {
        findings[p.name] = lists[i]
      })
      this.readDigest = digest
      this.attempts = attempts
      this.servers = servers
      this.projectViews = projectViews
      this.details = details
      this.findings = findings
      this.now = new Date()
      this.loaded = true
      // A check that runs ends without a click: ask the digest again, which reads the rest.
      if (this.guideShown && guideWaiting(projectViews, servers)) this.timer = setTimeout(() => this.$emit('decided'), waitEvery)
    },
    /** dismissGuide hides the guide, says where it went, and keeps the keyboard there. */
    dismissGuide() {
      dismissGuide(this.$ui.guide, save)
      this.helpLost = false
      this.guideNotice = true
      this.$nextTick(() => this.$refs.notice?.focus())
    },
  },
}
</script>

<style scoped>
.m-todo__loading { display: grid; gap: 0.9rem; justify-items: start; }
.m-todo__loading p { margin: 0; }
.m-todo__head { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.5rem 1rem; padding-bottom: 1.25rem; }
.m-todo__say { min-width: 0; }
.m-todo__sub { margin: 0.5rem 0 0; }
.m-todo__refresh { flex: none; margin-right: -0.5rem; }
.m-block { margin-bottom: 1.25rem; }
.m-todo__notice { margin: 0 0 1.25rem; outline: none; }
.m-todo__empty-action { margin-bottom: 1.25rem; }
.m-todo__list { list-style: none; margin: 0; padding: 0; }
.m-todo__row { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 0.9rem; }
.m-todo__row + .m-todo__row { border-top: 1px solid var(--m-line); }
.m-todo__word { flex: none; min-width: 5.75rem; justify-content: center; }
.m-todo__text { flex: 1 1 auto; min-width: 0; }
.m-todo__title { margin: 0; font-weight: 600; line-height: 1.35; overflow-wrap: anywhere; }
.m-todo__where { margin: 0.15rem 0 0; overflow-wrap: anywhere; }
.m-todo__action { flex: none; }
.m-todo__decided { margin: 0.75rem 0 0; }
.m-todo__unseen { margin-top: 1.25rem; padding: 0.75rem 0.9rem; }
.m-todo__unseen-title { font-size: 1rem; font-weight: 600; margin: 0 0 0.35rem; }
.m-todo__unseen-list { margin: 0; padding-left: 1.25rem; overflow-wrap: anywhere; }
.m-todo__unseen-list li + li { margin-top: 0.25rem; }
.m-todo__exploited { margin-top: 1.5rem; }
.m-catalog { margin-top: 2rem; color: rgba(var(--v-theme-on-background), 0.72); }
.m-catalog summary { cursor: pointer; }
.m-catalog__list { margin: 0.5rem 0 0; padding-left: 1.25rem; }
.m-catalog__open { margin: 0.25rem 0 0 -0.75rem; }

/* On a phone the button goes under the text, full width. */
@media (max-width: 599px) {
  .m-todo__row { flex-wrap: wrap; }
  .m-todo__word { min-width: 0; }
  .m-todo__text { flex-basis: 100%; }
  .m-todo__action { width: 100%; }
  .m-todo__empty-action { width: 100%; }
}
</style>
