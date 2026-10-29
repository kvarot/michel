import { describe, expect, test } from 'vitest'
import { decisionLabel, formatDate, groupAttention, validateDecision } from './digestView.js'
import { translate } from '../i18n/index.js'

const digest = {
  projects: [
    {
      name: 'demo',
      new: [
        { name: 'acme/lib', worst_severity: 'medium', what: 'medium what', finding_ids: ['f1'], osv_ids: ['GHSA-1'] },
        { name: 'vuln-pkg', worst_severity: 'critical', what: 'critical what', finding_ids: ['f2', 'f3'], osv_ids: ['GHSA-2'] },
      ],
      superseded: [{ package: 'acme/lib', osv_id: 'GHSA-9', finding_id: 'f9', previous_action: 'defer', reason: 'severity_changed' }],
      due: [{ package: 'other', osv_id: 'GHSA-8', finding_id: 'f8', due_at: '2026-11-22T00:00:00Z', overdue: false }],
    },
    {
      name: 'project-a',
      new: [
        { name: 'low-pkg', worst_severity: 'low', what: 'low what', finding_ids: ['f4'], osv_ids: ['GHSA-4'] },
        { name: 'high-pkg', worst_severity: 'high', what: 'high what', finding_ids: ['f5'], osv_ids: ['GHSA-5'] },
      ],
    },
    { name: 'quiet' },
  ],
}

describe('digestView', () => {
  test('groupAttention sorts critical first and keeps project order', () => {
    const groups = groupAttention(digest)
    expect(groups.map((g) => g.project)).toEqual(['demo', 'project-a', 'quiet'])
    expect(groups[0].items.map((i) => [i.kind, i.package, i.severity])).toEqual([
      ['new', 'vuln-pkg', 'critical'],
      ['new', 'acme/lib', 'medium'],
      ['superseded', 'acme/lib', 'medium'],
      ['due', 'other', 'unknown'],
    ])
    expect(groups[0].items[0].text).toBe('critical what')
    expect(groups[0].items[0].findingIds).toEqual(['f2', 'f3'])
    expect(groups[0].items[2].text).toBe('severity_changed')
    expect(groups[0].items[3].text).toBe('2026-11-22T00:00:00Z')
    expect(groups[1].items.map((i) => i.severity)).toEqual(['high', 'low'])
    expect(groups[2].items).toEqual([])
    expect(groupAttention(null)).toEqual([])
  })

  test('groupAttention uses the severity of decisions to review and deferrals', () => {
    const groups = groupAttention({
      projects: [{
        name: 'demo',
        new: [{ name: 'acme/lib', worst_severity: 'medium', finding_ids: ['f1'], osv_ids: ['A-1'] }],
        superseded: [{ package: 'acme/lib', osv_id: 'A-9', finding_id: 'f9', reason: 'severity_changed', severity: 'critical' }],
        due: [{ package: 'vuln-pkg', osv_id: 'A-8', finding_id: 'f8', due_at: '2026-11-22T00:00:00Z', severity: 'high' }],
      }],
    })
    expect(groups[0].items.map((i) => [i.kind, i.severity])).toEqual([['superseded', 'critical'], ['due', 'high'], ['new', 'medium']])
  })

  test('groupAttention keeps the decision already taken on a new package', () => {
    const groups = groupAttention({
      projects: [{
        name: 'demo',
        new: [
          { name: 'acme/lib', worst_severity: 'critical', finding_ids: ['f1'], osv_ids: ['A-1'], decided: 'fix' },
          { name: 'vuln-pkg', worst_severity: 'high', finding_ids: ['f2'], osv_ids: ['A-2'] },
        ],
      }],
    })
    expect(groups[0].items.map((i) => [i.package, i.decided])).toEqual([['acme/lib', 'fix'], ['vuln-pkg', '']])
  })

  test('groupAttention takes kev, malicious, epss and kind from the package, exploited for the others', () => {
    const groups = groupAttention({
      exploited: [{ finding_id: 'f9', kev_added: '2026-03-12', malicious: false }],
      projects: [{
        name: 'demo',
        new: [
          { name: 'acme/lib', worst_severity: 'critical', finding_ids: ['f0', 'f1'], osv_ids: ['A-1'], kev: true, epss: 0.42 },
          { name: 'vuln-pkg', worst_severity: 'high', finding_ids: ['f2'], osv_ids: ['A-2'], kind: 'code' },
          { name: 'evil-pkg', worst_severity: 'critical', finding_ids: ['f3'], osv_ids: ['MAL-1'], malicious: true },
        ],
        superseded: [{ package: 'old-pkg', osv_id: 'A-9', finding_id: 'f9', reason: 'severity_changed', severity: 'low' }],
      }],
    })
    expect(groups[0].items.map((i) => [i.package, i.kev, i.malicious, i.epss, i.findingKind])).toEqual([
      ['acme/lib', true, false, 0.42, 'dependency'], ['evil-pkg', false, true, 0, 'dependency'], ['vuln-pkg', false, false, 0, 'code'],
      ['old-pkg', true, false, 0, 'dependency'],
    ])
  })

  test('formatDate per lang', () => {
    expect(formatDate('2026-11-22T00:00:00Z', 'fr')).toBe('22/11/2026')
    expect(formatDate('2026-11-22T00:00:00Z', 'en')).toBe('2026-11-22')
    expect(formatDate('2026-11-22', 'fr')).toBe('22/11/2026')
    expect(formatDate('', 'fr')).toBe('')
    expect(formatDate('not a date', 'en')).toBe('')
  })

  test('decisionLabel', () => {
    expect(decisionLabel(null, 'fr')).toBe('')
    expect(decisionLabel({ action: 'fix' }, 'en')).toBe(translate('en', 'decision.label.fix'))
    expect(decisionLabel({ action: 'ignore' }, 'fr')).toBe(translate('fr', 'decision.label.ignore'))
    const fr = decisionLabel({ action: 'defer', due_at: '2026-11-22T00:00:00Z' }, 'fr')
    expect(fr).toBe(translate('fr', 'decision.label.defer', { date: '22/11/2026' }))
    expect(fr).toContain('22/11/2026')
    expect(decisionLabel({ action: 'defer', due_at: '2026-11-22T00:00:00Z' }, 'en')).toContain('2026-11-22')
    expect(decisionLabel({ action: 'other' }, 'en')).toBe('')
  })

  test('validateDecision mirrors decide rules', () => {
    const now = new Date('2026-10-23T09:00:00Z')
    expect(validateDecision({ action: 'fix', why: '', until: '' }, now)).toEqual({ ok: true, errorKey: '' })
    expect(validateDecision({ action: 'ignore', why: '  ', until: '' }, now)).toEqual({ ok: false, errorKey: 'decision.why_required' })
    expect(validateDecision({ action: 'ignore', why: 'dev only', until: '' }, now).ok).toBe(true)
    expect(validateDecision({ action: 'defer', why: '', until: '2026-10-22' }, now).errorKey).toBe('decision.until_past')
    // The server reads the date as midnight UTC and wants it after now.
    expect(validateDecision({ action: 'defer', why: '', until: '2026-10-23' }, now).errorKey).toBe('decision.until_past')
    expect(validateDecision({ action: 'defer', why: '', until: '2026-10-24' }, now).ok).toBe(true)
    expect(validateDecision({ action: 'defer', why: '', until: '' }, now).ok).toBe(true)
    expect(validateDecision({ action: 'defer', why: '', until: '24/10/2026' }, now).errorKey).toBe('decision.until_invalid')
    expect(validateDecision({ action: 'fix', why: '', until: '2026-12-01' }, now).errorKey).toBe('decision.until_not_defer')
    expect(validateDecision({ action: 'later', why: '', until: '' }, now).errorKey).toBe('decision.action_unknown')
    expect(validateDecision({ action: 'fix', why: 'x'.repeat(1001), until: '' }, now).errorKey).toBe('decision.why_too_long')
    expect(validateDecision({ action: 'fix', why: 'é'.repeat(1000), until: '' }, now).ok).toBe(true)
  })
})

describe('i18n', () => {
  test('catalogs have the same keys, none empty', async () => {
    const { catalogs } = await import('../i18n/index.js')
    expect(Object.keys(catalogs.fr).sort()).toEqual(Object.keys(catalogs.en).sort())
    for (const lang of ['en', 'fr']) {
      for (const [k, v] of Object.entries(catalogs[lang])) expect(v.trim(), `${lang} ${k}`).not.toBe('')
    }
  })

  test('plural: French 0 and 1 singular, English only 1', () => {
    expect(translate('fr', 'project.open', { n: 0 })).toBe('0 faille ouverte')
    expect(translate('fr', 'project.open', { n: 1 })).toBe('1 faille ouverte')
    expect(translate('fr', 'project.open', { n: 2 })).toBe('2 failles ouvertes')
    expect(translate('en', 'project.open', { n: 0 })).toBe('0 open vulnerabilities')
    expect(translate('en', 'project.open', { n: 1 })).toBe('1 open vulnerability')
    expect(translate('xx', 'app.retry')).toBe('Try again')
    expect(translate('fr', 'no.such.key')).toBe('no.such.key')
  })
})
