// Tiny DOM helpers shared by Vaultify ES-module islands.

/** Short alias for getElementById that returns null-safe. */
export function byId(id) {
  return document.getElementById(id);
}

/** Toggles a class when a predicate is true. */
export function toggleClass(el, cls, on) {
  if (!el) return;
  el.classList.toggle(cls, !!on);
}

/** Dispatches a debounced wrapper around fn. */
export function debounce(fn, ms) {
  let t;
  return function debounced(...args) {
    clearTimeout(t);
    t = setTimeout(() => fn.apply(this, args), ms);
  };
}
