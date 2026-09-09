import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { ScanListItem } from '../types'

export function HomePage() {
  const [scans, setScans] = useState<ScanListItem[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .listScans()
      .then(setScans)
      .catch((err: Error) => setError(err.message))
  }, [])

  const latest = scans.find((s) => s.status === 'completed') || scans[0]
  const summary = latest?.summary
  const validity = latest?.scan_validity

  return (
    <div>
      <header className="page-header">
        <h1>Latest security status</h1>
        <p>
          Decision-first view of your most recent scan. Zero findings is not the
          same as zero tests executed.
        </p>
      </header>

      {error && <div className="callout danger">{error}</div>}

      {!latest && !error && (
        <div className="panel">
          <p className="empty">
            No scans yet.{' '}
            <Link to="/scan">Run your first scan</Link> against a local target.
          </p>
        </div>
      )}

      {latest && (
        <>
          <div className="callout">
            <div>
              Scan <span className="mono">{latest.id.slice(0, 12)}</span>{' '}
              <span className={`badge ${latest.status}`}>{latest.status}</span>
            </div>
            <div className="muted" style={{ marginTop: '0.35rem' }}>
              {latest.created_at} · target{' '}
              <span className="mono">{latest.target_id}</span>
            </div>
            {validity?.zero_tests_executed ? (
              <p style={{ margin: '0.75rem 0 0' }}>
                <strong>0 tests executed</strong> — no meaningful security
                conclusion.
              </p>
            ) : (
              <p style={{ margin: '0.75rem 0 0' }} className="muted">
                {validity?.zero_findings_means?.replaceAll('_', ' ') ||
                  'Scan recorded.'}
              </p>
            )}
          </div>

          <div className="grid-stats">
            <div className="stat">
              <div className="label">Validity</div>
              <div className="value accent">{validity?.status || '—'}</div>
            </div>
            <div className="stat">
              <div className="label">Checks run</div>
              <div className="value">{validity?.checks_executed ?? '—'}</div>
            </div>
            <div className="stat">
              <div className="label">Vulnerabilities</div>
              <div className="value danger">
                {summary?.vulnerabilities ?? '—'}
              </div>
            </div>
            <div className="stat">
              <div className="label">Exposures</div>
              <div className="value">{summary?.exposures ?? '—'}</div>
            </div>
            <div className="stat">
              <div className="label">Hardening</div>
              <div className="value">{summary?.hardening ?? '—'}</div>
            </div>
            <div className="stat">
              <div className="label">Verified</div>
              <div className="value ok">{summary?.verified ?? '—'}</div>
            </div>
          </div>

          <div className="toolbar">
            <Link className="btn" to={`/scans/${latest.id}`}>
              Open scan detail
            </Link>
            <Link className="btn ghost" to="/scan">
              New scan
            </Link>
          </div>
        </>
      )}

      {scans.length > 1 && (
        <div className="panel">
          <h2>Recent</h2>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 8).map((scan) => (
                  <tr key={scan.id}>
                    <td className="mono">{scan.created_at}</td>
                    <td>
                      <span className={`badge ${scan.status}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>{scan.summary?.findings ?? '—'}</td>
                    <td>
                      <Link to={`/scans/${scan.id}`}>View</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
