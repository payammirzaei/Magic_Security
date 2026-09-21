async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = window.localStorage.getItem('magic_security_api_key') || import.meta.env.VITE_MAGIC_SECURITY_API_KEY
  const activeWorkspace = window.localStorage.getItem('magic_security_workspace') || 'default'
  const shouldScope = path.startsWith('/api/targets') || path.startsWith('/api/scans') || path.startsWith('/api/findings') || path.startsWith('/api/workspace') || path.startsWith('/api/me')
  const separator = path.includes('?') ? '&' : '?'
  const scopedPath = shouldScope ? `${path}${separator}workspace_id=${encodeURIComponent(activeWorkspace)}` : path
  const requestId = window.crypto?.randomUUID?.() || `req-${Date.now()}-${Math.random().toString(16).slice(2)}`
  const res = await fetch(scopedPath, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      'X-Request-ID': requestId,
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
    const requestId = res.headers.get('x-request-id')
    const message = typeof detail === 'string' ? detail : JSON.stringify(detail)
    throw new Error(requestId ? `${message} (request ${requestId})` : message)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  createSession: (apiKey: string) => request<{ token: string; expires_in: number }>('/api/session', { method: 'POST', body: JSON.stringify({ api_key: apiKey }) }),
  deleteSession: () => request<{ ok: boolean }>('/api/session', { method: 'DELETE' }),
  refreshSession: () => request<{ expires_in: number }>('/api/session/refresh', { method: 'POST' }),
  health: () => request<{ status: string; workers: number; queued: number; active_scans: number; failed_scans: number }>('/api/health'),
  workspace: () => request<{ id: string; name: string }>('/api/workspace'),
  workspaces: () => request<{ id: string; name: string; created_at: string }[]>('/api/workspaces'),
  createWorkspace: (name: string) => request<{ id: string; name: string; created_at: string }>('/api/workspaces', { method: 'POST', body: JSON.stringify({ name }) }),
  renameWorkspace: (id: string, name: string) => request<{ id: string; name: string; created_at: string }>(`/api/workspaces/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ name }) }),
  me: () => request<{ id: string; name: string; role: string; authenticated: boolean }>('/api/me'),
  listFindings: (options?: { limit?: number; offset?: number }) => request<import('./types').Finding[]>(`/api/findings?limit=${options?.limit ?? 200}&offset=${options?.offset ?? 0}`),
  getFinding: (id: string) => request<import('./types').Finding>(`/api/findings/${encodeURIComponent(id)}`),
  updateFindingStatus: (id: string, status: 'open' | 'triaged' | 'ignored') => request<import('./types').Finding>(`/api/findings/${encodeURIComponent(id)}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  listTargets: (options?: { limit?: number; offset?: number }) => request<import('./types').Target[]>(`/api/targets?limit=${options?.limit ?? 200}&offset=${options?.offset ?? 0}`),
  addTarget: (body: {
    base_url: string
    environment?: string
    trusted_local?: boolean
  }) =>
    request('/api/targets', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  listScans: (targetId?: string, options?: { limit?: number; offset?: number }) => {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : ''
    const join = q ? '&' : '?'
    return request<import('./types').ScanListItem[]>(`/api/scans${q}${join}limit=${options?.limit ?? 50}&offset=${options?.offset ?? 0}`)
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
  deleteTarget: (id: string) => request<{ ok: boolean; id: string }>(`/api/targets/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  cancelScan: (id: string) => request<{ id: string; status: string }>(`/api/scans/${id}/cancel`, { method: 'POST' }),
  retryScan: (id: string) => request<{ id: string; status: string }>(`/api/scans/${id}/retry`, { method: 'POST' }),
  queue: () => request<{ queued: number; workers: number; active_scans: number; failed_scans: number }>('/api/queue'),
  operations: () => request<{ workspace_id: string; queued: number; workers: number; active: import('./types').ScanListItem[]; recent_failures: import('./types').ScanListItem[] }>('/api/operations'),
}

export function setApiToken(token: string) {
  window.localStorage.setItem('magic_security_api_key', token)
}

export function clearApiToken() {
  window.localStorage.removeItem('magic_security_api_key')
}

export function reportHtmlUrl(scanId: string): string {
  const workspace = window.localStorage.getItem('magic_security_workspace') || 'default'
  return `/api/scans/${scanId}/report.html?workspace_id=${encodeURIComponent(workspace)}`
}

export function reportJsonUrl(scanId: string): string {
  const workspace = window.localStorage.getItem('magic_security_workspace') || 'default'
  return `/api/scans/${scanId}/report.json?workspace_id=${encodeURIComponent(workspace)}`
}

export async function openAuthenticatedReport(scanId: string, format: 'html' | 'json' | 'md'): Promise<void> {
  const workspace = window.localStorage.getItem('magic_security_workspace') || 'default'
  const token = window.localStorage.getItem('magic_security_api_key') || import.meta.env.VITE_MAGIC_SECURITY_API_KEY
  const response = await fetch(`/api/scans/${encodeURIComponent(scanId)}/report.${format}?workspace_id=${encodeURIComponent(workspace)}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
  if (!response.ok) { const requestId = response.headers.get('x-request-id'); throw new Error(`Report request failed (${response.status})${requestId ? ` (request ${requestId})` : ''}`) }
  const blob = await response.blob(); const url = URL.createObjectURL(blob)
  if (format === 'html') window.open(url, '_blank', 'noopener,noreferrer')
  else { const anchor = document.createElement('a'); anchor.href = url; anchor.download = `magic-security-${scanId}.${format}`; anchor.click() }
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
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
