export type ScanSummary = {
  findings?: number
  vulnerabilities?: number
  exposures?: number
  hardening?: number
  verified?: number
}

export type ScanValidity = {
  status?: string
  checks_executed?: number
  zero_tests_executed?: boolean
  zero_findings_means?: string
  pages_crawled?: number
  endpoints_normalized?: number
  findings_total?: number
}

export type Target = {
  id: string
  base_url: string
  environment?: string
  metadata_json?: string
  last_scan_at?: string | null
  last_scan_status?: string | null
  last_scan_summary?: ScanSummary | null
}

export type ScanListItem = {
  id: string
  target_id: string
  created_at: string
  status: string
  error?: string | null
  summary?: ScanSummary | null
  scan_validity?: ScanValidity | null
  stage?: { current?: string; completed?: string[]; progress?: number } | null
}

export type Finding = {
  title: string
  severity: string
  kind: string
  url?: string
  description?: string
  evidence?: string
  remediation?: string
  confidence?: number
  confidence_level?: string
  verified?: boolean
  fingerprint?: string
  check_id?: string
  target_id?: string
  detected_at?: string
  status?: 'open' | 'triaged' | 'ignored'
}

export type ScanDetail = ScanListItem & {
  config?: { browser?: boolean; active?: boolean; max_pages?: number }
  report?: {
    summary?: ScanSummary
    scan_validity?: ScanValidity
    decision?: {
      regressions?: Record<string, unknown[]>
      coverage_equivalence?: boolean | null
    }
    findings?: Finding[]
    coverage?: Record<string, unknown>
    attack_surface?: unknown
    attack_surface_graph?: unknown
    repository_findings?: Finding[] | Record<string, unknown>[]
    modes?: Record<string, unknown>
  }
  snapshot?: Record<string, unknown>
}
