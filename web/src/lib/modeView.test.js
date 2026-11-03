import { describe, expect, test } from 'vitest'
import { readAdvanced, stripTechnicalIds } from './modeView.js'
import { keys } from './storage.js'

describe('readAdvanced', () => {
  test('advanced defaults to off', () => {
    expect(readAdvanced(() => '')).toBe(false)
    expect(readAdvanced(() => 'yes')).toBe(false)
    expect(readAdvanced(() => 'true')).toBe(false)
    expect(readAdvanced(() => {
      throw new Error('blocked')
    })).toBe(false)
  })
  test('only the value 1 turns it on, under its own key', () => {
    let asked = ''
    expect(readAdvanced((k) => ((asked = k), '1'))).toBe(true)
    expect(asked).toBe(keys.advanced)
    expect(keys.advanced).toBe('michel.advanced')
  })
})

describe('stripTechnicalIds', () => {
  test('stripTechnicalIds removes ids and keeps the sentence', () => {
    expect(stripTechnicalIds('La faille CVE-2024-12345 permet de lire des fichiers.')).toBe('La faille permet de lire des fichiers.')
    expect(stripTechnicalIds('Corrigée (GHSA-abcd-1234-wxyz) dans la 2.0.')).toBe('Corrigée dans la 2.0.')
    expect(stripTechnicalIds('Voir PHP2Shell (CVE-2024-1111).')).toBe('Voir PHP2Shell.')
  })
  test('keeps names that only look close', () => {
    expect(stripTechnicalIds('PHP2Shell reste.')).toBe('PHP2Shell reste.')
    expect(stripTechnicalIds('')).toBe('')
    expect(stripTechnicalIds(undefined)).toBe('')
  })
})
