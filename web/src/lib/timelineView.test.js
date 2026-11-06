import { describe, expect, test } from 'vitest'
import { fold, historyNote, lineDate, lines } from './timelineView.js'

// The days are the person's: the tests run on a clock with a summer time.
process.env.TZ = 'Europe/Paris'

const now = new Date('2026-11-06T15:00:00+01:00')

/** one is the single line of one entry. */
function one(entry, lang, opts) {
  return lines([entry], lang, now, opts)[0]
}

describe('lines: the words of each kind', () => {
  const at = '2026-11-02T09:30:00Z'
  const cases = [
    [{ kind: 'seen' }, 'Vue pour la première fois', 'First seen'],
    [{ kind: 'gone' }, "N'est plus trouvée", 'No longer found'],
    [{ kind: 'back' }, 'Revenue', 'Came back'],
    [{ kind: 'reopened', detail: { reason: 'due_reached' } }, 'Remise à traiter : la date que tu avais fixée est arrivée', 'Back on your list: the date you set has come'],
    [{ kind: 'reopened', detail: { reason: 'kev_changed' } }, "Remise à traiter : ce qu'on sait des attaques qui l'utilisent a changé", 'Back on your list: what is known of attacks using it changed'],
    [{ kind: 'reopened' }, 'Remise à traiter : la situation a changé', 'Back on your list: something changed'],
    [{ kind: 'decision', detail: { action: 'fix', author: 'web' } }, 'Décision : la corriger, prise sur la page de Michel', "Decision: fix it, made on Michel's page"],
    [{ kind: 'decision', detail: { action: 'ignore', author: 'cli' } }, "Décision : l'ignorer, prise en ligne de commande", 'Decision: ignore it, made from the command line'],
    [{ kind: 'decision', detail: { action: 'defer', author: 'web', due: '2026-12-01T00:00:00+01:00' } }, "Décision : la reporter jusqu'au 01/12/2026, prise sur la page de Michel", "Decision: put it off until 2026-12-01, made on Michel's page"],
    [{ kind: 'decision', detail: { action: 'fix', author: 'web', superseded_at: '2026-11-03T10:00:00Z', reason: 'redecided' } }, "Décision : la corriger, prise sur la page de Michel. Remplacée le 03/11/2026 par une nouvelle décision", "Decision: fix it, made on Michel's page. Replaced on 2026-11-03 by a new decision"],
    [{ kind: 'decision', detail: { action: 'defer', author: 'web', superseded_at: '2026-11-03T10:00:00Z', reason: 'severity_changed' } }, "Décision : la reporter, prise sur la page de Michel. Plus valable depuis le 03/11/2026 : la gravité a changé", "Decision: put it off, made on Michel's page. No longer in force since 2026-11-03: the severity changed"],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'preparing' } }, 'Correction lancée : Michel commence à la préparer', 'Fix launched: Michel starts preparing it'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'proposed' } }, 'Correction proposée : elle attend ta validation', 'Fix proposed: it waits for your approval'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'approved' } }, 'Correction validée', 'Fix approved'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'refused' } }, 'Correction refusée', 'Fix refused'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'applied' } }, 'Correction appliquée : la branche est prête', 'Fix applied: the branch is ready'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'proven_fixed' } }, 'Correction vérifiée : un nouveau contrôle ne trouve plus la faille', 'Fix proven: a new check no longer finds the flaw'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'inconclusive' } }, "Correction pas confirmée : Michel n'a pas pu vérifier qu'elle marche", 'Fix not confirmed: Michel could not check that it works'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'failed' } }, "La correction n'a pas abouti", 'The fix did not succeed'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'withdrawn' } }, 'Correction arrêtée avant de démarrer', 'Fix stopped before it started'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'superseded' } }, 'Correction remplacée par une plus récente', 'Fix replaced by a newer one'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'held' } }, 'Correction en attente de ta réponse', 'Fix waiting for your answer'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'running' } }, 'Michel applique la correction', 'Michel is applying the fix'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'unknown' } }, 'Michel ne sait pas si la correction a abouti', 'Michel does not know whether the fix worked'],
    [{ kind: 'attempt', detail: { attempt_id: 'a1', state: 'odd' } }, 'Correction : étape inconnue', 'Fix: unknown step'],
    [{ kind: 'odd' }, 'Changement inconnu', 'Unknown change'],
  ]
  for (const [entry, fr, en] of cases) {
    test(`${entry.kind} ${entry.detail?.state || entry.detail?.reason || entry.detail?.action || ''}`, () => {
      expect(one({ at, ...entry }, 'fr').text).toBe(fr)
      expect(one({ at, ...entry }, 'en').text).toBe(en)
    })
  }
  test('an author Michel does not know is left out in simple mode and named in advanced mode', () => {
    const e = { at, kind: 'decision', detail: { action: 'fix', author: 'robot' } }
    expect(one(e, 'fr').text).toBe('Décision : la corriger')
    expect(one(e, 'fr', { advanced: true }).text).toBe('Décision : la corriger, prise par robot')
  })
  test('advanced mode adds the attempt id, simple mode does not', () => {
    const e = { at, kind: 'attempt', detail: { attempt_id: 'a1b2', state: 'proposed' } }
    expect(one(e, 'fr', { advanced: true }).text).toBe('Correction proposée : elle attend ta validation (tentative a1b2)')
    expect(one(e, 'en', { advanced: true }).text).toBe('Fix proposed: it waits for your approval (attempt a1b2)')
    expect(one(e, 'fr').text).not.toContain('a1b2')
  })
})

describe('lines: dates and order', () => {
  test('today and yesterday are said so, with the hour on the person clock', () => {
    expect(one({ at: '2026-11-06T08:05:00Z', kind: 'seen' }, 'fr').date).toBe("aujourd'hui à 09:05")
    expect(one({ at: '2026-11-05T22:30:00Z', kind: 'seen' }, 'fr').date).toBe('hier à 23:30')
    expect(one({ at: '2026-11-05T22:30:00Z', kind: 'seen' }, 'en').date).toBe('yesterday at 23:30')
    expect(one({ at: '2026-07-14T10:00:00Z', kind: 'seen' }, 'fr').date).toBe('14/07/2026 à 12:00')
    expect(one({ at: '2026-07-14T10:00:00Z', kind: 'seen' }, 'en').date).toBe('2026-07-14 at 12:00')
  })
  test('a date that cannot be read is said unknown', () => {
    expect(one({ at: 'x', kind: 'seen' }, 'fr').date).toBe('date inconnue')
    expect(lineDate('', 'en', now)).toBe('unknown date')
  })
  test('keeps the order of the API (newest first) and gives at and kind', () => {
    const out = lines([{ at: '2026-11-03T00:00:00Z', kind: 'gone' }, { at: '2026-11-01T00:00:00Z', kind: 'seen' }], 'en', now)
    expect(out.map((l) => l.kind)).toEqual(['gone', 'seen'])
    expect(out[0].at).toBe('2026-11-03T00:00:00Z')
  })
  test('no entry gives no line; an answer that cannot be read gives null', () => {
    expect(lines([], 'fr', now)).toEqual([])
    expect(lines(null, 'fr', now)).toBe(null)
  })
})

describe('reconstructed entries', () => {
  test('are flagged, the others not', () => {
    const out = lines([{ at: '2026-11-03T00:00:00Z', kind: 'gone', reconstructed: true }, { at: '2026-11-01T00:00:00Z', kind: 'seen' }], 'fr', now)
    expect(out.map((l) => l.reconstructed)).toEqual([true, false])
  })
  test('the note says from when the history is whole, only when a line is reconstructed', () => {
    const rec = [{ at: '2026-10-01T00:00:00Z', kind: 'seen', reconstructed: true }]
    expect(historyNote(rec, '2026-11-06T09:00:00Z', 'fr')).toBe("Avant le 06/11, Michel ne gardait que le dernier changement d'une faille. Les lignes marquées « reconstituée » en sont déduites.")
    expect(historyNote(rec, '2026-11-06T09:00:00Z', 'en')).toBe('Before 11-06, Michel only kept the last change of a flaw. The lines marked « reconstructed » are worked out from it.')
    expect(historyNote([{ at: '2026-11-06T10:00:00Z', kind: 'seen' }], '2026-11-06T09:00:00Z', 'fr')).toBe('')
    expect(historyNote(rec, 'x', 'fr')).toBe("Avant, Michel ne gardait que le dernier changement d'une faille. Les lignes marquées « reconstituée » en sont déduites.")
  })
})

describe('the fold above 10 lines', () => {
  const entries = Array.from({ length: 13 }, (_, i) => ({ at: `2026-10-${String(20 - i).padStart(2, '0')}T10:00:00Z`, kind: 'seen' }))
  test('10 lines or fewer come as a list', () => {
    expect(lines(entries.slice(0, 10), 'fr', now)).toHaveLength(10)
  })
  test('above 10, the 10 newest are shown and the rest hidden', () => {
    const out = lines(entries, 'fr', now)
    expect(out.shown).toHaveLength(10)
    expect(out.hidden).toHaveLength(3)
    expect(out.shown[0].at).toBe(entries[0].at)
    expect(out.hidden[2].at).toBe(entries[12].at)
  })
  test('fold gives the same shape for both, for the page', () => {
    expect(fold(lines(entries.slice(0, 2), 'fr', now))).toEqual({ shown: lines(entries.slice(0, 2), 'fr', now), hidden: [] })
    expect(fold(lines(entries, 'fr', now)).hidden).toHaveLength(3)
    expect(fold(null)).toBe(null)
  })
})
