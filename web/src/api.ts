async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = window.localStorage.getItem('magic_security_api_key') || import.meta.env.VITE_MAGIC_SECURITY_API_KEY
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers || {}),
    },
  })
  if (!res.ok) {
    if (res.status === 401 && window.location.pathname !== '/login') window.location.assign('/login')
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || JSON.stringify(body)
    } catch {
      /* ignore */
    }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  health: () => request<{ status: string }>('/api/health'),
  workspace: () => request<{ id: string; name: string }>('/api/workspace'),
  me: () => request<{ id: string; name: string; role: string; authenticated: boolean }>('/api/me'),
  listFindings: () => request<import('./types').Finding[]>('/api/findings'),
  listTargets: () => request<import('./types').Target[]>('/api/targets'),
  addTarget: (body: {
    base_url: string
    environment?: string
    trusted_local?: boolean
  }) =>
    request('/api/targets', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  listScans: (targetId?: string) => {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : ''
    return request<import('./types').ScanListItem[]>(`/api/scans${q}`)
  },
  getScan: (id: string) =>
    request<import('./types').ScanDetail>(`/api/scans/${id}`),
  getFindings: (id: string) =>
    request<import('./types').Finding[]>(`/api/scans/${id}/findings`),
  getCoverage: (id: string) =>
    request<Record<string, unknown>>(`/api/scans/${id}/coverage`),
  getDiff: (id: string) =>
    request<Record<string, unknown>>(`/api/scans/${id}/diff`),
  setBaseline: (id: string) =>
    request<{ ok: boolean }>(`/api/scans/${id}/baseline`, { method: 'POST' }),
  startScan: (body: {
    target: string
    browser?: boolean
    active?: boolean
    auth_contexts_path?: string | null
    max_pages?: number
  }) =>
    request<{ id: string; target_id: string; status: string }>('/api/scans', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  cancelScan: (id: string) => request<{ id: string; status: string }>(`/api/scans/${id}/cancel`, { method: 'POST' }),
  retryScan: (id: string) => request<{ id: string; status: string }>(`/api/scans/${id}/retry`, { method: 'POST' }),
  queue: () => request<{ queued: number; workers: number }>('/api/queue'),
}

export function setApiToken(token: string) {
  window.localStorage.setItem('magic_security_api_key', token)
}

export function clearApiToken() {
  window.localStorage.removeItem('magic_security_api_key')
}

export function reportHtmlUrl(scanId: string): string {
  return `/api/scans/${scanId}/report.html`
}

export async function pollScan(
  id: string,
  onUpdate?: (scan: import('./types').ScanDetail) => void,
  intervalMs = 1500,
): Promise<import('./types').ScanDetail> {
  for (;;) {
    const scan = await api.getScan(id)
    onUpdate?.(scan)
    if (scan.status === 'completed' || scan.status === 'failed') return scan
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}
