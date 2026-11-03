/**
 * helpIds lists the fields that have a "?" help. The text of an id is the
 * key help.<id> in both catalogs; help.label is the name of the button and is
 * not an id. Later tasks add their own ids here, in the same commit as the
 * component that shows them.
 * @type {string[]}
 */
export const helpIds = [
  'server.host', 'server.user', 'server.port', 'server.name', 'server.site', 'server.kind', 'server.env',
  'server.level', 'server.auto', 'server.executor', 'server.sudo', 'server.interval', 'server.preprod',
  'server.active', 'server.fingerprint', 'server.check', 'server.snapshot',
  'project.level', 'project.auto', 'project.ai',
  'decision.action', 'decision.until', 'decision.why',
  'logs.path', 'logs.format', 'logs.try', 'logs.interval', 'logs.store_text', 'logs.alert_text', 'logs.retention', 'logs.sms',
  'fix.approve', 'fix.refuse',
  'settings.token', 'settings.advanced', 'settings.theme', 'settings.lang',
]

/** The longest help text, in characters. A help is read in a hurry. */
export const maxHelpLength = 280

/**
 * helpKey is the catalog key of the text of a help id.
 * @param {string} id
 * @returns {string}
 */
export function helpKey(id) {
  return `help.${id}`
}

/**
 * helpIdsIn lists the ids of the <FieldHelp id="..."> found in a component source.
 * @param {string} source
 * @returns {string[]}
 */
export function helpIdsIn(source) {
  const out = []
  for (const m of source.matchAll(/<FieldHelp\b[^>]*?\sid="([^"]+)"/g)) out.push(m[1])
  return out
}
