// Shared safe-HTML helpers for Vaultify ES-module islands.
//
// Phase 4: the old app.js pattern — `${this.esc(value)}` manually on
// every interpolation — is easy to forget and has bitten us before.
// `html\`<div>${user}</div>\`` automatically escapes interpolated
// values and returns a string ready for innerHTML. Use `raw(s)` to
// opt out when you are splicing a pre-rendered fragment.

const ENT = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/**
 * esc(value) escapes the 5 characters that matter for HTML attribute
 * and text contexts. null/undefined become empty strings so template
 * usage stays forgiving.
 */
export function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, ch => ENT[ch]);
}

/**
 * Marker used by html`` to recognise pre-escaped fragments and splice
 * them without a second escape pass.
 */
const RAW = Symbol('html.raw');

/**
 * raw(str) marks a string as already-escaped HTML so html`` leaves it
 * alone. Only use with strings you produced yourself.
 */
export function raw(str) {
  return { [RAW]: true, value: String(str ?? '') };
}

/**
 * Tagged template: html`<div class="${cls}">${body}</div>` returns an
 * HTML string. Interpolated values are escaped unless wrapped in raw()
 * or produced by another html`` call (arrays of such values are
 * joined). Arrays of primitives are joined after escaping each entry.
 */
export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    out += renderValue(values[i]);
    out += strings[i + 1];
  }
  return out;
}

function renderValue(v) {
  if (v === null || v === undefined || v === false) return '';
  if (v && typeof v === 'object' && v[RAW] === true) return v.value;
  if (Array.isArray(v)) return v.map(renderValue).join('');
  return esc(v);
}
