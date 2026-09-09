import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import type { ScanListItem } from '../types'

export function HistoryPage() {
  const [params] = useSearchParams()
  const targetFilter = params.get('target') || undefined
  const [scans, setScans] = useState<ScanListItem[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .listScans(targetFilter)
      .then(setScans)
      .catch((err: Error) => setError(err.message))
  }, [targetFilter])

  return (
    <div>
      <header className="page-header">
        <h1>Scan history</h1>
        <p>
          {targetFilter
            ? `Filtered to target ${targetFilter}`
            : 'All persisted scans from the local control plane.'}
        </p>
      </header>

      {error && <div className="callout danger">{error}</div>}

      <div className="panel">
        <h2>Scans</h2>
        {scans.length === 0 ? (
          <p className="empty">No scans stored yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Validity</th>
                  <th>Findings</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="mono">{scan.created_at}</td>
                    <td className="mono">{scan.target_id}</td>
                    <td>
                      <span className={`badge ${scan.status}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>{scan.scan_validity?.status || '—'}</td>
                    <td>{scan.summary?.findings ?? '—'}</td>
                    <td>
                      <Link to={`/scans/${scan.id}`}>Open</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
