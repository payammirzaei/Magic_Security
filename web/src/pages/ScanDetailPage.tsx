import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, reportHtmlUrl } from '../api'
import type { Finding, ScanDetail } from '../types'

type Tab = 'decision' | 'findings' | 'coverage' | 'surface' | 'diff'

export function ScanDetailPage() {
  const { scanId = '' } = useParams()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [diff, setDiff] = useState<Record<string, unknown> | null>(null)
  const [diffError, setDiffError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('decision')
  const [sev, setSev] = useState('all')
  const [kind, setKind] = useState('all')
  const [checkId, setCheckId] = useState('')
  const [verifiedOnly, setVerifiedOnly] = useState(false)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)

  useEffect(() => {
    if (!scanId) return
    Promise.all([api.getScan(scanId), api.getFindings(scanId)])
      .then(([s, f]) => {
        setScan(s)
        setFindings(f.length ? f : s.report?.findings || [])
      })
      .catch((err: Error) => setError(err.message))
  }, [scanId])

  useEffect(() => {
    if (tab !== 'diff' || !scanId) return
    setDiffError(null)
    api
      .getDiff(scanId)
      .then(setDiff)
      .catch((err: Error) => setDiffError(err.message))
  }, [tab, scanId])

  const filtered = useMemo(() => {
    const needle = checkId.trim().toLowerCase()
    return findings.filter((f) => {
      if (sev !== 'all' && f.severity !== sev) return false
      if (kind !== 'all' && f.kind !== kind) return false
      if (verifiedOnly && !f.verified) return false
      if (needle && !(f.check_id || '').toLowerCase().includes(needle)) return false
      return true
    })
  }, [findings, sev, kind, checkId, verifiedOnly])

  async function setBaseline() {
    if (!scanId) return
    setBusy(true)
    setMsg(null)
    try {
      await api.setBaseline(scanId)
      setMsg('Baseline set from this scan.')
    } catch (err) {
      setMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return <div className="callout danger">{error}</div>
  }
  if (!scan) {
    return <p className="muted">Loading scan…</p>
  }

  const report = scan.report || {}
  const validity = report.scan_validity || scan.scan_validity
  const summary = report.summary || scan.summary
  const decision = report.decision
  const regressions = decision?.regressions || {}
  const surface =
    report.attack_surface_graph || report.attack_surface || null
  const repo = report.repository_findings || []

  return (
    <div>
      <header className="page-header">
        <h1>Scan detail</h1>
        <p>
          <span className="mono">{scan.id}</span> ·{' '}
          <span className={`badge ${scan.status}`}>{scan.status}</span>
        </p>
      </header>

      {scan.error && <div className="callout danger">{scan.error}</div>}
      {msg && <div className="callout">{msg}</div>}

      <div className="toolbar">
        <a className="btn ghost" href={reportHtmlUrl(scan.id)} target="_blank" rel="noreferrer">
          Open HTML report
        </a>
        <button className="btn ghost" type="button" disabled={busy} onClick={setBaseline}>
          Set as baseline
        </button>
        <Link className="btn ghost" to="/history">
          Back to history
        </Link>
      </div>

      <div className="tabs">
        {(
          [
            ['decision', 'Decision'],
            ['findings', 'Findings'],
            ['coverage', 'Coverage'],
            ['surface', 'Attack surface'],
            ['diff', 'Baseline diff'],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={tab === id ? 'active' : undefined}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'decision' && (
        <>
          <div className="grid-stats">
            <div className="stat">
              <div className="label">Validity</div>
              <div className="value accent">{validity?.status || '—'}</div>
            </div>
            <div className="stat">
              <div className="label">Checks</div>
              <div className="value">{validity?.checks_executed ?? '—'}</div>
            </div>
            <div className="stat">
              <div className="label">Vulns</div>
              <div className="value danger">
                {summary?.vulnerabilities ?? 0}
              </div>
            </div>
            <div className="stat">
              <div className="label">Exposures</div>
              <div className="value">{summary?.exposures ?? 0}</div>
            </div>
            <div className="stat">
              <div className="label">Verified</div>
              <div className="value ok">{summary?.verified ?? 0}</div>
            </div>
          </div>
          {validity?.zero_tests_executed ? (
            <div className="callout warn">
              Zero tests executed — do not treat empty findings as a clean bill
              of health.
            </div>
          ) : (
            <div className="callout ok">
              {validity?.zero_findings_means?.replaceAll('_', ' ') ||
                'Scan validity recorded.'}
            </div>
          )}
          <div className="panel">
            <h2>Regressions</h2>
            {Object.keys(regressions).length === 0 ? (
              <p className="muted">No regression block on this report.</p>
            ) : (
              <pre className="pre-block">
                {JSON.stringify(regressions, null, 2)}
              </pre>
            )}
          </div>
          {Array.isArray(repo) && repo.length > 0 && (
            <div className="panel">
              <h2>Source findings</h2>
              <p className="muted">
                Repository signals never auto-promote to verified runtime
                vulnerabilities.
              </p>
              <pre className="pre-block">{JSON.stringify(repo, null, 2)}</pre>
            </div>
          )}
        </>
      )}

      {tab === 'findings' && (
        <>
          <div className="toolbar">
            <label className="muted">
              Severity{' '}
              <select value={sev} onChange={(e) => setSev(e.target.value)}>
                <option value="all">all</option>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
              </select>
            </label>
            <label className="muted">
              Kind{' '}
              <select value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="all">all</option>
                <option value="vulnerability">vulnerability</option>
                <option value="exposure">exposure</option>
                <option value="hardening">hardening</option>
                <option value="observation">observation</option>
              </select>
            </label>
            <label className="muted">
              Check ID{' '}
              <input
                value={checkId}
                onChange={(e) => setCheckId(e.target.value)}
                placeholder="e.g. idor"
                style={{ minWidth: '10rem' }}
              />
            </label>
            <label className="check muted">
              <input
                type="checkbox"
                checked={verifiedOnly}
                onChange={(e) => setVerifiedOnly(e.target.checked)}
              />
              Verified only
            </label>
          </div>
          <div className="panel">
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Sev</th>
                    <th>Kind</th>
                    <th>Check</th>
                    <th>Title</th>
                    <th>Verified</th>
                    <th>URL</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((f, idx) => (
                    <tr key={`${f.fingerprint || f.title}-${idx}`}>
                      <td>
                        <span className={`badge ${f.severity}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td>{f.kind}</td>
                      <td className="mono">{f.check_id || '—'}</td>
                      <td>
                        <div>{f.title}</div>
                        <div className="muted" style={{ fontSize: '0.85rem' }}>
                          {f.evidence}
                        </div>
                      </td>
                      <td>{f.verified ? 'yes' : 'no'}</td>
                      <td className="mono">{f.url}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length === 0 && (
                <p className="empty">No findings match filters.</p>
              )}
            </div>
          </div>
        </>
      )}

      {tab === 'coverage' && (
        <div className="panel">
          <h2>Coverage</h2>
          <pre className="pre-block">
            {JSON.stringify(report.coverage || {}, null, 2)}
          </pre>
        </div>
      )}

      {tab === 'surface' && (
        <div className="panel">
          <h2>Attack surface</h2>
          <pre className="pre-block">
            {JSON.stringify(surface || {}, null, 2)}
          </pre>
        </div>
      )}

      {tab === 'diff' && (
        <div className="panel">
          <h2>Baseline diff</h2>
          {diffError && <div className="callout warn">{diffError}</div>}
          {diff && (
            <pre className="pre-block">{JSON.stringify(diff, null, 2)}</pre>
          )}
          {!diff && !diffError && <p className="muted">Loading diff…</p>}
        </div>
      )}
    </div>
  )
}
