import { describe, expect, test } from 'vitest'
import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import { anyScanning, checkedWell, cleanProjectPath, needsDigest, projectNameFromPath, runsHere, scanHintKey, scanPath, scanSentence, showsFailure, withScanState, goneRows } from './projectsView.js'

const card = import.meta.glob('../components/ProjectCard.vue', { query: '?raw', import: 'default', eager: true })

const now = new Date('2026-11-03T12:00:00Z')

describe('projectNameFromPath', () => {
  test('name from a windows or unix path', () => {
    expect(projectNameFromPath('C:\\Sites\\mon-site')).toBe('mon-site')
    expect(projectNameFromPath('C:\\Sites\\mon-site\\')).toBe('mon-site')
    expect(projectNameFromPath('/home/toi/mon-site')).toBe('mon-site')
    expect(projectNameFromPath('/home/toi/mon-site/')).toBe('mon-site')
    expect(projectNameFromPath('C:/Sites/mon site')).toBe('mon site')
  })
  test('a disk or nothing gives no name', () => {
    expect(projectNameFromPath('C:\\')).toBe('')
    expect(projectNameFromPath('C:')).toBe('')
    expect(projectNameFromPath('/')).toBe('')
    expect(projectNameFromPath('')).toBe('')
    expect(projectNameFromPath(undefined)).toBe('')
  })
  test('the quotes of a copied path do not count', () => {
    expect(projectNameFromPath('"C:\\Sites\\mon-site"')).toBe('mon-site')
    expect(cleanProjectPath('  "C:\\Sites\\mon-site" ')).toBe('C:\\Sites\\mon-site')
    expect(cleanProjectPath(" '/home/toi/site' ")).toBe('/home/toi/site')
    expect(cleanProjectPath('/home/toi/site')).toBe('/home/toi/site')
    expect(cleanProjectPath(null)).toBe('')
  })
})

describe('scanSentence', () => {
  test('scan sentence for never, running, failed, ok', () => {
    expect(scanSentence({ last_scan_status: 'never' }, 'fr', now)).toBe(fr['project.scan.never'])
    expect(scanSentence({ last_scan_status: 'never', scanning: true }, 'fr', now)).toBe(fr['project.scan.running'])
    expect(scanSentence({ last_scan_status: 'running', scanning: true }, 'en', now)).toBe(en['project.scan.running'])
    expect(scanSentence({ last_scan_status: 'failed' }, 'fr', now)).toBe(fr['project.scan.failed'])
    expect(scanSentence({ last_scan_status: 'ok', last_scan_at: '2026-11-03T10:00:00Z' }, 'fr', now)).toBe('Dernier contrôle : il y a 2 h.')
    expect(scanSentence({ last_scan_status: 'ok', last_scan_at: '2026-11-03T10:00:00Z' }, 'en', now)).toBe('Last check: 2 h ago.')
  })
  test('without a time, a done check says only that', () => {
    expect(scanSentence({ last_scan_status: 'ok' }, 'fr', now)).toBe(fr['project.scan.done'])
  })
  test('the failure of the last click comes first, unless a new check runs', () => {
    const last_failure = { code: 'api.project.no_database', error: 'Pas de liste' }
    expect(scanSentence({ last_scan_status: 'ok', last_failure }, 'fr', now)).toBe('Pas de liste')
    expect(scanSentence({ last_scan_status: 'ok', last_failure, scanning: true }, 'fr', now)).toBe(fr['project.scan.running'])
  })
  test('every status has its sentence, and none says a thing is safe', () => {
    for (const status of ['ok', 'partial', 'failed', 'interrupted', 'running', 'empty', 'never']) {
      const out = scanSentence({ last_scan_status: status, last_scan_at: '2026-11-03T10:00:00Z' }, 'fr', now)
      expect(out, status).toBeTruthy()
      expect(out, status).not.toMatch(/project\.scan|sécurisé|sûr\b|protégé|aucune faille/i)
    }
    expect(scanSentence({ last_scan_status: 'unheard-of' }, 'fr', now)).toBe(fr['project.scan.never'])
    expect(scanSentence({}, 'fr', now)).toBe(fr['project.scan.never'])
  })
})

describe('scan state of a card', () => {
  test('a card reassures only after a whole check', () => {
    expect(checkedWell({ last_scan_status: 'ok' }, true)).toBe(true)
    for (const status of ['never', 'failed', 'interrupted', 'partial', 'running', 'empty', undefined]) {
      expect(checkedWell({ last_scan_status: status }, true), status).toBe(false)
    }
    expect(checkedWell({ last_scan_status: 'ok', scanning: true }, true)).toBe(false)
    expect(checkedWell({ last_scan_status: 'ok', last_failure: { code: 'api.project.no_database' } }, true)).toBe(false)
    const src = Object.values(card)[0]
    expect(src).toContain('v-else-if="seen" class="m-keep"')
    expect(src).toContain('v-if="seen && project.critical_open === 0"')
  })
  test('the state of the API joins the digest of the page, the rest stays', () => {
    const d = { name: 'demo', open: { high: 1 }, last_scan_status: 'never' }
    const out = withScanState(d, { name: 'demo', scanning: true, last_failure: null, last_scan_at: 'x', last_scan_status: 'running', open: { high: 9 } })
    expect(out.open).toEqual({ high: 1 })
    expect(out.scanning).toBe(true)
    expect(out.last_scan_status).toBe('running')
    expect(out.git_answer).toBe('')
    expect(out.git_attached).toBe(false)
    expect(withScanState(d, { name: 'demo', git_answer: 'yes', git_attached: true }).git_attached).toBe(true)
    expect(withScanState(d, { name: 'demo', git_answer: 'yes', git_attached: true }).git_answer).toBe('yes')
    expect(out.last_scan_at).toBe('x')
    expect(d.scanning).toBeUndefined()
    expect(withScanState(d, undefined)).toEqual(d)
  })
  test('anyScanning', () => {
    expect(anyScanning([{ scanning: false }, { scanning: true }])).toBe(true)
    expect(anyScanning([{ scanning: false }])).toBe(false)
    expect(anyScanning(null)).toBe(false)
  })
  test('a failure shows only when no new check runs', () => {
    const last_failure = { code: 'x', error: 'y' }
    expect(showsFailure({ last_failure })).toBe(true)
    expect(showsFailure({ last_failure, scanning: true })).toBe(false)
    expect(showsFailure({})).toBe(false)
  })
  test('the address of a check holds the name, encoded', () => {
    expect(scanPath('mon site/é', 'fr')).toBe('/projects/mon%20site%2F%C3%A9/scan?lang=fr')
  })
})

describe('the digest a card reassures on (H2)', () => {
  const idle = [{ name: 'demo', last_scan_status: 'ok' }]
  const running = [{ name: 'demo', scanning: true, last_scan_status: 'running' }]

  test('no reassuring word until the digest read after the check has arrived', () => {
    expect(checkedWell({ last_scan_status: 'ok' }, false)).toBe(false)
    expect(checkedWell({ last_scan_status: 'ok' })).toBe(false)
    expect(checkedWell({ last_scan_status: 'ok' }, true)).toBe(true)
  })
  test('a check that ended while the page was open', () => {
    expect(needsDigest(running, idle, false, false)).toBe(true)
  })
  test('a click on a check too short to be seen running', () => {
    expect(needsDigest(idle, idle, true, false)).toBe(true)
  })
  test('coming back to the page after the check ended', () => {
    expect(needsDigest([], idle, false, true)).toBe(true)
  })
  test('not while a check runs, and not on an ordinary look', () => {
    expect(needsDigest([], running, true, true)).toBe(false)
    expect(needsDigest(idle, idle, false, false)).toBe(false)
    expect(needsDigest(null, null, false, false)).toBe(false)
  })
  test('the end of a check nobody started here counts too', () => {
    expect(needsDigest([{ last_scan_status: 'running' }], idle, false, false)).toBe(true)
  })
})

describe('a check that may have died (H3)', () => {
  test('only a check of this process counts as running here', () => {
    expect(runsHere({ scanning: true, last_scan_status: 'running' })).toBe(true)
    expect(runsHere({ last_scan_status: 'running' })).toBe(false)
    expect(runsHere({ scanning: false })).toBe(false)
    expect(Object.values(card)[0]).toContain('return runsHere(this.project)')
  })
  test('a status left at running has its own sentence, and no promise', () => {
    expect(scanSentence({ last_scan_status: 'running' }, 'fr', now)).toBe(fr['project.scan.elsewhere'])
    expect(scanSentence({ last_scan_status: 'running' }, 'en', now)).toBe(en['project.scan.elsewhere'])
    expect(scanSentence({ last_scan_status: 'running', scanning: true }, 'fr', now)).toBe(fr['project.scan.running'])
    expect(fr['project.scan.elsewhere']).not.toContain('il continue')
    expect(en['project.scan.elsewhere']).not.toContain('goes on')
  })
  test('the page keeps looking at such a status, and never reassures', () => {
    expect(anyScanning([{ last_scan_status: 'running' }])).toBe(true)
    expect(checkedWell({ last_scan_status: 'running' }, true)).toBe(false)
  })
})

describe('what a card offers after a check that is not whole (M4)', () => {
  test('starting again is offered for a failure, not for a partial check', () => {
    expect(scanHintKey('failed')).toBe('project.scan_hint')
    expect(scanHintKey('interrupted')).toBe('project.scan_hint')
    expect(scanHintKey('partial')).toBe('project.scan.partial_hint')
    expect(fr['project.scan.partial']).toBe("Le dernier contrôle est incomplet : Michel n'a pas lu tous les fichiers.")
    for (const cat of [fr, en]) {
      expect(cat['project.scan.partial_hint']).not.toContain(cat['project.check'])
      expect(cat['project.scan.partial_hint']).toContain('Sources')
    }
  })
})

describe('the button is the one the texts name', () => {
  test('git.manual.next names the label of the button', () => {
    expect(fr['project.check']).toBe('Contrôler ce projet')
    expect(en['project.check']).toBe('Check this project')
    expect(fr['git.manual.next']).toContain(`« ${fr['project.check']} »`)
    expect(en['git.manual.next']).toContain(`"${en['project.check']}"`)
    expect(Object.values(card)[0]).toContain("$t('project.check')")
  })
  test('the page sends to the button, not to the command line', () => {
    for (const cat of [fr, en]) {
      expect(cat['today.no_projects_hint']).not.toContain('michel ')
      expect(cat['project.scan_hint']).toContain(cat['project.check'])
    }
    expect(fr['help.project.path']).toContain("n'y écrit rien")
    expect(en['help.project.path']).toContain('writes nothing')
  })
})

describe('goneRows (D-3)', () => {
  const pkg = (ids, proven = []) => ({ name: 'acme/lib', worst_severity: 'high', finding_ids: ids, proven_ids: proven, osv_ids: ids, installed: '1', target: '2' })
  test('a flaw Michel proved fixed is not « he cannot prove it »', () => {
    expect(goneRows({ gone: [pkg(['a'], ['a'])] })).toEqual([])
  })
  test('a package keeps the flaws that only vanished', () => {
    const rows = goneRows({ gone: [pkg(['a', 'b'], ['a'])] })
    expect(rows.length).toBe(1)
    expect(rows[0].findingIds).toEqual(['b'])
    expect(rows[0].kind).toBe('gone')
  })
  test('nothing proved: as it was; no list: nothing', () => {
    expect(goneRows({ gone: [pkg(['a'])] })[0].findingIds).toEqual(['a'])
    expect(goneRows({})).toEqual([])
  })
})
