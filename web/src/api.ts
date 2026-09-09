async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  })
  if (!res.ok) {
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
