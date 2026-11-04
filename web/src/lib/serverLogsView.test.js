import { describe, expect, test } from 'vitest'
import {
  channelNotes, deviationWarning, domId, errorGroups, intervalChoices, intervalNote, logBadges, privacyChoices, privacyStrongNote, readState, routeChoices, settingsSaveOutcome,
} from './serverLogsView.js'

const now = new Date('2026-11-01T12:00:00Z')

/** settings builds GET /logs/settings as the API answers it. */
function settings(extra = {}) {
  return { interval: '5m', store_text: false, alert_text: false, retention_days: 90, sms: false, ...extra }
}

describe('privacyChoices', () => {
  test('recommended option comes first and is marked, whatever the current choice', () => {
    for (const st of [settings(), settings({ store_text: true, alert_text: true, retention_days: 365 })]) {
      const groups = privacyChoices(st, 'vps', 'fr')
      expect(groups.map((g) => g.key)).toEqual(['store_text', 'alert_text', 'retention'])
      for (const g of groups) {
        expect(g.choices[0].recommended).toBe(true)
        expect(g.choices.filter((c) => c.recommended)).toHaveLength(1)
        expect(g.choices[0].label).toContain('recommandé')
        expect(g.choices.slice(1).every((c) => !c.label.includes('recommandé'))).toBe(true)
      }
    }
    const en = privacyChoices(settings(), 'vps', 'en')
    expect(en[0].choices[0].label).toContain('recommended')
  })

  test('the current choice is the one selected, a retention outside the list is kept', () => {
    const groups = privacyChoices(settings({ store_text: true, retention_days: 100 }), 'vps', 'fr')
    expect(groups[0].choices.find((c) => c.current).value).toBe(true)
    const retention = groups[2].choices
    expect(retention.map((c) => c.value)).toContain(100)
    expect(retention.find((c) => c.current).value).toBe(100)
    expect(retention[0].value).toBe(90)
  })

  test('the text of alerts cannot be chosen while no text is kept', () => {
    const off = privacyChoices(settings(), 'vps', 'fr')[1].choices
    expect(off.find((c) => c.value === true).disabled).toBe(true)
    expect(off.find((c) => c.value === false).disabled).toBe(false)
    const on = privacyChoices(settings({ store_text: true }), 'vps', 'fr')[1].choices
    expect(on.find((c) => c.value === true).disabled).toBe(false)
  })
})

describe('privacyChoices on a health server', () => {
  test('a choice away from the recommendation is strong on a health (hds) server only', () => {
    const strong = (kind) => privacyChoices(settings({ store_text: true }), kind, 'fr').map((g) => g.choices.map((c) => c.strong))
    expect(strong('hds')).toEqual([[false, true], [false, true], [false, true, true, true, true]])
    for (const kind of ['vps', 'shared']) expect(strong(kind).flat().every((v) => v === false)).toBe(true)
  })
})

describe('deviationWarning', () => {
  test('hds warning names health data and hosting', () => {
    const w = deviationWarning('store_text', 'hds', 'fr')
    expect(w.strong).toBe(true)
    expect(w.health).toMatch(/données de santé/)
    expect(w.health).toMatch(/hébergement/)
    expect(w.health).toMatch(/responsable/)
    const en = deviationWarning('alert_text', 'hds', 'en')
    expect(en.health).toMatch(/health data/)
    expect(en.health).toMatch(/hosting/)
  })

  test('a server that is not hds gets the plain question only', () => {
    const w = deviationWarning('retention', 'vps', 'fr')
    expect(w.strong).toBe(false)
    expect(w.health).toBe('')
    expect(w.title).not.toBe('')
    expect(deviationWarning('store_text', 'shared', 'fr').title).not.toBe(w.title)
  })

  test('an unknown key still has a title', () => {
    expect(deviationWarning('other', 'vps', 'fr').title).not.toBe('')
  })
})

describe('intervalNote', () => {
  const note = (interval, lang = 'fr', advanced = false, extra = {}) => intervalNote({ interval, ...extra }, advanced, lang)

  test('interval above 10 minutes warns (local fallback without an API note)', () => {
    expect(note('5m')).toBe('')
    expect(note('10m')).toBe('')
    expect(note('15m')).toMatch(/10 minutes/)
    expect(note('2h')).toMatch(/10 minutes/)
    expect(note('1h30m0s')).toMatch(/10 minutes/)
    expect(note('24h', 'en')).toMatch(/10 minutes/)
  })

  test('by hand says nobody is warned in between, and names no button', () => {
    expect(note('manual', 'fr', false)).toMatch(/en ligne de commande/)
    expect(note('manual', 'fr', false)).toMatch(/Personne/)
    expect(note('manual', 'fr', true)).toMatch(/michel target logs read/)
    expect(note('manual', 'en', false)).toMatch(/command line/)
  })

  test('api interval note wins over the local one', () => {
    expect(note('15m', 'fr', false, { interval_note: 'Note de l API' })).toBe('Note de l API')
  })

  test('manual follows the mode, whatever the api says', () => {
    const api = { interval_note: 'Quand tu le demandes' }
    expect(note('manual', 'fr', false, api)).not.toBe('Quand tu le demandes')
    expect(note('manual', 'fr', false, api)).toMatch(/en ligne de commande/)
    expect(note('manual', 'fr', true, api)).toMatch(/michel target logs read/)
    expect(note('manual', 'fr', true, api)).not.toBe(note('manual', 'fr', false, api))
  })

  test('an unreadable value says nothing', () => {
    expect(note('')).toBe('')
    expect(note('soon')).toBe('')
    expect(intervalNote(null, false, 'fr')).toBe('')
  })
})

describe('domId', () => {
  test('has no space and differs for different paths', () => {
    const a = domId('php|/var/log/my app/error.log')
    const b = domId('php|/var/log/my_app/error.log')
    expect(a).not.toMatch(/\s/)
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(a).not.toBe(b)
    expect(domId('php|/var/log/my app/error.log')).toBe(a)
  })
})

describe('settingsSaveOutcome', () => {
  test('reads the 409 logs.confirm_needed', () => {
    const err = { status: 409, data: { code: 'logs.confirm_needed', deviations: [{ code: 'store_text' }], health: 'Santé' } }
    expect(settingsSaveOutcome(err)).toEqual({ kind: 'confirm', deviations: [{ code: 'store_text' }], health: 'Santé' })
    expect(settingsSaveOutcome({ status: 409, data: { code: 'logs.confirm_needed' } })).toEqual({ kind: 'confirm', deviations: [], health: '' })
  })

  test('another failure is an error, none is ok', () => {
    const e = { status: 409, data: { code: 'other' } }
    expect(settingsSaveOutcome(e)).toEqual({ kind: 'error', error: e })
    expect(settingsSaveOutcome({ status: 500 }).kind).toBe('error')
    expect(settingsSaveOutcome(null)).toEqual({ kind: 'ok' })
  })
})

describe('intervalChoices', () => {
  test('5 minutes comes first and is marked, by hand last, an odd current value is kept', () => {
    const list = intervalChoices('7m', 'fr')
    expect(list[0].value).toBe('5m')
    expect(list[0].title).toContain('recommandé')
    expect(list[list.length - 1].value).toBe('manual')
    expect(list.map((c) => c.value)).toContain('7m')
    expect(list.slice(1).every((c) => !c.title.includes('recommandé'))).toBe(true)
  })
})

describe('readState', () => {
  test('last read and unseen wording', () => {
    const r = readState({ active: true, last_read_at: '2026-11-01T11:30:00Z', unseen: [{ what: '/var/log/app.log', reason: 'Michel n’a pas le droit de le lire.' }] }, now, 'fr')
    expect(r.line).toBe('Dernière lecture réussie il y a 30 min.')
    expect(r.unseen).toEqual([{ what: '/var/log/app.log', reason: 'Michel n’a pas le droit de le lire.', text: "Michel n'a pas pu lire : /var/log/app.log — Michel n’a pas le droit de le lire." }])
    expect(readState({ active: true, last_read_at: '2026-11-01T11:30:00Z' }, now, 'en').line).toBe('Last successful read 30 min ago.')
  })

  test('never read, and turned off', () => {
    expect(readState({ active: true, last_read_at: '' }, now, 'fr').line).toBe("Michel n'a pas encore réussi à lire ce journal.")
    expect(readState({ active: false, last_read_at: '' }, now, 'fr').line).toBe('Michel ne lit pas ce journal pour le moment.')
    expect(readState({ active: true }, now, 'fr').unseen).toEqual([])
  })
})

describe('channelNotes', () => {
  test('no channel warning', () => {
    const notes = channelNotes({ noChannel: true, sms: false }, 'fr')
    expect(notes).toHaveLength(1)
    expect(notes[0]).toMatch(/personne/i)
    expect(channelNotes({ noChannel: false, sms: false }, 'fr')).toEqual([])
  })

  test('a text message uses the same 3-per-day limit as flaw alerts', () => {
    const notes = channelNotes({ noChannel: false, sms: true }, 'fr')
    expect(notes).toHaveLength(1)
    expect(notes[0]).toMatch(/3 par jour/)
    expect(notes[0]).toMatch(/failles/)
    expect(channelNotes({ noChannel: false, sms: true }, 'en')[0]).toMatch(/3 a day/)
  })
})

describe('logBadges', () => {
  test('a setting away from the recommendation, no channel and new errors each have a badge', () => {
    const b = logBadges({ log_deviations: ['store_text'], log_no_channel: true, log_new: 2 }, 'fr')
    expect(b.map((x) => x.key)).toEqual(['new', 'no_channel', 'deviation'])
    expect(b[0].text).toBe('2 nouvelles erreurs dans les journaux')
    expect(logBadges({ log_new: 1 }, 'fr')[0].text).toBe('1 nouvelle erreur dans les journaux')
    expect(logBadges({}, 'fr')).toEqual([])
  })
})

describe('errorGroups', () => {
  test('errors grouped by level, the worst first, empty levels left out', () => {
    const g = errorGroups([{ id: 'a', level: 'warning' }, { id: 'b', level: 'critical' }, { id: 'c', level: 'warning' }, { id: 'd', level: 'weird' }])
    expect(g.map((x) => x.level)).toEqual(['critical', 'warning'])
    expect(g[1].errors.map((e) => e.id)).toEqual(['a', 'c'])
  })
})

describe('routeChoices', () => {
  test('the default way of being warned comes first, by environment', () => {
    const prod = routeChoices('critical', 'prod', 'fr')
    expect(prod.map((c) => c.value)).toEqual(['immediate', 'digest', 'ignored'])
    expect(prod[0].title).toBe('tout de suite (recommandé)')
    expect(routeChoices('critical', 'dev', 'fr')[0].value).toBe('digest')
    expect(routeChoices('error', 'prod', 'fr')[0].value).toBe('digest')
    expect(routeChoices('warning', 'prod', 'fr').map((c) => c.value)).toEqual(['ignored', 'immediate', 'digest'])
    expect(routeChoices('info', 'prod', 'fr').filter((c) => c.recommended)).toHaveLength(1)
  })
})

describe('privacyStrongNote', () => {
  const group = (kind, extra, key) => privacyChoices(settings(extra), kind, 'en').find((g) => g.key === key)

  test('a health server on a choice away from the recommendation gets a marked warning, per setting', () => {
    expect(privacyStrongNote(group('hds', { store_text: true }, 'store_text'), 'en')).toMatch(/health data/)
    expect(privacyStrongNote(group('hds', { store_text: true }, 'store_text'), 'fr')).toMatch(/données de santé/)
    // The setting still on the recommended choice says nothing, even on this server.
    expect(privacyStrongNote(group('hds', { store_text: true }, 'alert_text'), 'en')).toBe('')
    expect(privacyStrongNote(group('hds', { retention_days: 30 }, 'retention'), 'en')).not.toBe('')
  })

  test('other servers, and the recommended choices, say nothing', () => {
    for (const kind of ['vps', 'shared']) expect(privacyStrongNote(group(kind, { store_text: true }, 'store_text'), 'en')).toBe('')
    expect(privacyStrongNote(group('hds', {}, 'store_text'), 'en')).toBe('')
    expect(privacyStrongNote(undefined, 'en')).toBe('')
  })
})
