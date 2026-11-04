import { createApp, reactive } from 'vue'
import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg'
import 'vuetify/styles'
import './styles.css'
import App from './App.vue'
import { takeTokenFromURL } from './api.js'
import { translate, normalizeLang } from './i18n/index.js'
import { keys, load } from './lib/storage.js'
import { readAdvanced } from './lib/modeView.js'
import { readGuide } from './lib/guideView.js'
import { installDialogFocus } from './lib/dialogFocus.js'
import { themes } from './lib/theme.js'

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
const vuetify = createVuetify({
  theme: {
    defaultTheme: stored === 'dark' || stored === 'light' ? stored : systemTheme(),
    themes: {
      light: themes.light,
      dark: themes.dark,
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
// guide is the first steps guide: kept here, it outlives a page and a blocked storage.
const ui = reactive({ lang: normalizeLang(load(keys.lang) || navigator.language?.slice(0, 2)), langChosen: !!load(keys.lang), advanced: readAdvanced(load), guide: { ...readGuide(load), again: false, asks: 0 } })

const app = createApp(App)
app.config.globalProperties.$ui = ui
app.config.globalProperties.$t = (key, params) => translate(ui.lang, key, params)
app.use(vuetify)
app.mount('#app')
installDialogFocus(document)

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
      // Without a service worker the page still works; it only loses the offline shell.
    })
  })
}
