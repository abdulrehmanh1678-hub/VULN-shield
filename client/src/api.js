/** API base URL — empty string uses same origin (production). Set VITE_API_URL for dev proxy override. */
export const API_BASE = import.meta.env.VITE_API_URL || '';

export function apiUrl(path) {
  return `${API_BASE}${path}`;
}
