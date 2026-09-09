import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Target } from '../types'

export function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([])
  const [url, setUrl] = useState('http://127.0.0.1:8000')
  const [environment, setEnvironment] = useState('local')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = () =>
    api
      .listTargets()
      .then(setTargets)
      .catch((err: Error) => setError(err.message))

  useEffect(() => {
    refresh()
  }, [])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.addTarget({
        base_url: url,
        environment,
        trusted_local: true,
      })
      setUrl('http://127.0.0.1:8000')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <header className="page-header">
        <h1>Targets</h1>
        <p>Register owned local or authorized targets for scanning and history.</p>
      </header>

      {error && <div className="callout danger">{error}</div>}

      <div className="panel">
        <h2>Add target</h2>
        <form className="form" onSubmit={onSubmit}>
          <label>
            Base URL
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
          </label>
          <label>
            Environment
            <input
              type="text"
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
            />
          </label>
          <button className="btn" type="submit" disabled={busy}>
            {busy ? 'Saving…' : 'Register target'}
          </button>
        </form>
      </div>

      <div className="panel">
        <h2>Registered</h2>
        {targets.length === 0 ? (
          <p className="empty">No targets yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>URL</th>
                  <th>Env</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr key={t.id}>
                    <td className="mono">{t.id}</td>
                    <td>{t.base_url}</td>
                    <td>{t.environment || '—'}</td>
                    <td>
                      <Link to={`/history?target=${encodeURIComponent(t.id)}`}>
                        History
                      </Link>
                      {' · '}
                      <Link
                        to={`/scan?target=${encodeURIComponent(t.base_url)}`}
                      >
                        Scan
                      </Link>
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
