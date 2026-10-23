<template>
  <v-card class="m-settings">
    <v-card-title class="m-settings__title">{{ $t('settings.title') }}</v-card-title>
    <v-card-text class="m-settings__body">
      <section class="m-settings__group" aria-labelledby="settings-lang">
        <h3 id="settings-lang" class="m-settings__label">{{ $t('settings.lang') }}</h3>
        <div class="m-settings__choices" role="group" aria-labelledby="settings-lang">
          <v-btn
            v-for="l in languages"
            :key="l"
            :lang="l"
            color="primary"
            :variant="$ui.lang === l ? 'flat' : 'outlined'"
            :aria-pressed="String($ui.lang === l)"
            @click="$emit('lang', l)"
          >
            {{ $t(`lang.${l}`) }}
          </v-btn>
        </div>
        <p v-if="meta && meta.lang" class="m-muted m-small">{{ $t('settings.lang_default', { lang: $t(`lang.${metaLang}`) }) }}</p>
      </section>

      <section class="m-settings__group" aria-labelledby="settings-theme">
        <h3 id="settings-theme" class="m-settings__label">{{ $t('settings.theme') }}</h3>
        <div class="m-settings__choices" role="group" aria-labelledby="settings-theme">
          <v-btn
            v-for="t in ['light', 'dark']"
            :key="t"
            color="primary"
            :variant="theme === t ? 'flat' : 'outlined'"
            :aria-pressed="String(theme === t)"
            @click="$emit('theme', t)"
          >
            {{ $t(`settings.theme_${t}`) }}
          </v-btn>
        </div>
      </section>

      <section class="m-settings__group" aria-labelledby="settings-token">
        <h3 id="settings-token" class="m-settings__label">{{ $t('settings.token') }}</h3>
        <p class="m-small">{{ hasToken ? $t('settings.token_saved') : $t('settings.token_missing') }}</p>
        <p class="m-muted m-small">{{ $t('auth.why') }}</p>
        <form class="m-settings__token" @submit.prevent="useToken">
          <v-text-field v-model="pasted" :label="$t('settings.token_paste')" type="password" autocomplete="off" spellcheck="false" hide-details />
          <div class="m-settings__row">
            <v-btn type="submit" color="primary" variant="tonal" :disabled="!pasted.trim()">{{ $t('auth.save') }}</v-btn>
            <v-btn v-if="hasToken" variant="text" color="error" @click="forget">{{ $t('settings.token_forget') }}</v-btn>
          </div>
        </form>
      </section>

      <p v-if="meta && meta.version" class="m-muted m-small m-settings__version">{{ $t('settings.version', { version: meta.version }) }}</p>
    </v-card-text>
    <v-card-actions>
      <v-spacer />
      <v-btn variant="text" @click="$emit('close')">{{ $t('app.close') }}</v-btn>
    </v-card-actions>
  </v-card>
</template>

<script>
import { api } from '../api.js'
import { languages } from '../i18n/index.js'

export default {
  name: 'SettingsPanel',
  props: {
    meta: { type: Object, default: null },
    theme: { type: String, default: 'light' },
  },
  emits: ['lang', 'theme', 'token-forgotten', 'token-saved', 'close'],
  data() {
    return { languages, pasted: '', hasToken: !!api.token }
  },
  computed: {
    metaLang() {
      return this.meta?.lang === 'fr' ? 'fr' : 'en'
    },
  },
  methods: {
    useToken() {
      api.setToken(this.pasted)
      this.pasted = ''
      this.hasToken = !!api.token
      this.$emit('token-saved')
    },
    forget() {
      api.setToken('')
      this.hasToken = false
      this.$emit('token-forgotten')
    },
  },
}
</script>

<style scoped>
.m-settings__title { font-family: var(--m-voice); font-weight: 600; font-size: 1.4rem; padding-top: 1.25rem; }
.m-settings__body { display: grid; gap: 1.5rem; }
.m-settings__group { display: grid; gap: 0.5rem; justify-items: start; }
.m-settings__group p { margin: 0; }
.m-settings__label { font-size: 0.95rem; font-weight: 650; margin: 0; }
.m-settings__token { display: grid; gap: 0.6rem; width: 100%; }
.m-settings__row, .m-settings__choices { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.m-settings__version { margin: 0; }
</style>
