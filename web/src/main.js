import { createApp, reactive } from 'vue'
import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg'
import 'vuetify/styles'
import './styles.css'
import App from './App.vue'
import { takeTokenFromURL } from './api.js'
import { translate, normalizeLang } from './i18n/index.js'
import { keys, load } from './lib/storage.js'

// The token arrives once in the link printed by michel serve.
takeTokenFromURL()

/** systemTheme follows the computer's light or dark setting. */
function systemTheme() {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

const stored = load(keys.theme)
const shared = {
  // Severity colors carry meaning; the page always pairs them with words.
  light: {
    background: '#f3f6f8', surface: '#ffffff', 'surface-variant': '#e6ecef', 'on-surface-variant': '#2a3a42',
    primary: '#24685b', secondary: '#4c5f69', success: '#24685b', warning: '#8a5a00', error: '#a4161a', info: '#2f5f86',
    critical: '#a4161a', high: '#b4501a', medium: '#7a5c00', low: '#2f5f86', unknown: '#5b6770',
    'on-background': '#17262e', 'on-surface': '#17262e',
  },
  dark: {
    background: '#10181c', surface: '#172227', 'surface-variant': '#22313a', 'on-surface-variant': '#d4dfe3',
    primary: '#82c7b5', secondary: '#a9bcc4', success: '#82c7b5', warning: '#e8c766', error: '#ff8a80', info: '#8dc3ee',
    critical: '#ff8a80', high: '#ffb074', medium: '#e8c766', low: '#8dc3ee', unknown: '#a9b6bc',
    'on-background': '#e4ecee', 'on-surface': '#e4ecee',
  },
}

const vuetify = createVuetify({
  theme: {
    defaultTheme: stored === 'dark' || stored === 'light' ? stored : systemTheme(),
    themes: {
      light: { dark: false, colors: shared.light },
      dark: { dark: true, colors: shared.dark },
    },
  },
  icons: { defaultSet: 'mdi', aliases, sets: { mdi } },
  defaults: {
    VBtn: { rounded: 'lg' },
    VCard: { rounded: 'lg' },
    VTextField: { variant: 'outlined', density: 'comfortable' },
    VTextarea: { variant: 'outlined', density: 'comfortable' },
  },
})

// ui holds the interface language; $t reads it so every text follows a change.
const ui = reactive({ lang: normalizeLang(load(keys.lang) || navigator.language?.slice(0, 2)), langChosen: !!load(keys.lang) })

const app = createApp(App)
app.config.globalProperties.$ui = ui
app.config.globalProperties.$t = (key, params) => translate(ui.lang, key, params)
app.use(vuetify)
app.mount('#app')

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
      // Without a service worker the page still works; it only loses the offline shell.
    })
  })
}
