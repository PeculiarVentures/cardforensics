/**
 * Hybrid storage adapter.
 *
 * Uses window.storage (Anthropic artifact sandbox) when available,
 * falls back to localStorage for standalone HTML deployment.
 * Same async interface in both modes.
 */

/** True if running inside an Anthropic artifact sandbox. Checked lazily. */
export function isSandbox() {
  return typeof window !== "undefined" && !!window.storage;
}

export const storage = {
  async get(key) {
    if (isSandbox()) return window.storage.get(key);
    try {
      const val = localStorage.getItem(key);
      return val ? { key, value: val } : null;
    } catch { return null; }
  },

  async set(key, value) {
    if (isSandbox()) return window.storage.set(key, value);
    try { localStorage.setItem(key, value); return { key, value }; }
    catch { return null; }
  },

  async delete(key) {
    if (isSandbox()) return window.storage.delete(key);
    try { localStorage.removeItem(key); return { key, deleted: true }; }
    catch { return null; }
  },
};
