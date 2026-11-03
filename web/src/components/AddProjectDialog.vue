<template>
  <v-card class="m-addp" aria-labelledby="add-project-title">
    <form @submit.prevent="save">
      <v-card-title id="add-project-title" class="m-addp__title">{{ $t('projects.add') }}</v-card-title>
      <v-card-text class="m-addp__body">
        <p class="m-muted m-small">{{ $t('projects.add_intro') }}</p>
        <div>
          <v-text-field
            v-model="path"
            :label="$t('projects.add_path')"
            autocomplete="off"
            spellcheck="false"
            hide-details="auto"
            :disabled="busy"
            autofocus
            @update:model-value="onPath"
          />
          <FieldHelp id="project.path" :field="$t('projects.add_path')" />
        </div>
        <div>
          <v-text-field
            v-model="name"
            :label="$t('projects.add_name')"
            autocomplete="off"
            spellcheck="false"
            hide-details="auto"
            :disabled="busy"
            @update:model-value="named = true"
          />
          <FieldHelp id="project.name" :field="$t('projects.add_name')" />
        </div>
        <div v-if="failure" class="m-addp__failure" role="alert">
          <p>{{ failure.offline ? $t('offline.hint') : failure.error || $t('error.generic') }}</p>
          <p v-if="failure.hint" class="m-muted m-small">{{ failure.hint }}</p>
        </div>
      </v-card-text>
      <v-card-actions class="m-addp__actions">
        <v-btn variant="text" :disabled="busy" @click="$emit('close')">{{ $t('common.cancel') }}</v-btn>
        <v-btn type="submit" color="primary" variant="flat" :loading="busy" :disabled="!canSave">{{ $t('projects.add_save') }}</v-btn>
      </v-card-actions>
    </form>
  </v-card>
</template>

<script>
import FieldHelp from './FieldHelp.vue'
import { api } from '../api.js'
import { cleanProjectPath, projectNameFromPath } from '../lib/projectsView.js'

// AddProjectDialog is "Ajouter un projet": the full path of a folder and a
// name, proposed from the path until the person changes it. Michel checks the
// path; a refusal stays in the dialog, in Michel's words. Nothing else can be
// set here: the level has its own control on the card, and a test command stays
// on the command line.
export default {
  name: 'AddProjectDialog',
  components: { FieldHelp },
  emits: ['close', 'added'],
  data() {
    return { path: '', name: '', named: false, busy: false, failure: null }
  },
  computed: {
    canSave() {
      return !this.busy && !!cleanProjectPath(this.path) && !!this.name.trim()
    },
  },
  methods: {
    onPath() {
      this.failure = null
      if (!this.named) this.name = projectNameFromPath(this.path)
    },
    async save() {
      if (!this.canSave) return
      this.busy = true
      this.failure = null
      try {
        const added = await api.post(`/projects?lang=${encodeURIComponent(this.$ui.lang)}`, {
          path: cleanProjectPath(this.path),
          name: this.name.trim(),
        })
        this.$emit('added', added)
      } catch (err) {
        if (err?.status !== 401) this.failure = err
      } finally {
        this.busy = false
      }
    },
  },
}
</script>

<style scoped>
.m-addp__title { white-space: normal; }
.m-addp__body { display: grid; gap: 1rem; }
.m-addp__body p { margin: 0; }
.m-addp__failure { display: grid; gap: 0.25rem; color: rgb(var(--v-theme-error)); }
.m-addp__failure .m-muted { color: rgba(var(--v-theme-on-surface), 0.72); }
.m-addp__actions { justify-content: flex-end; flex-wrap: wrap; }
</style>
