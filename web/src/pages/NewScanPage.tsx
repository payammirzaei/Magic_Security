import { useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, pollScan } from '../api'

export function NewScanPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const initialTarget = params.get('target') || 'http://127.0.0.1:8000'

  const [target, setTarget] = useState(initialTarget)
  const [maxPages, setMaxPages] = useState(50)
  const [active, setActive] = useState(true)
  const [browser, setBrowser] = useState(false)
  const [authPath, setAuthPath] = useState(
    'examples/auth_contexts.example.json',
  )
  const [useAuth, setUseAuth] = useState(false)
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const hint = useMemo(
    () =>
      browser
        ? 'Browser mode needs Playwright Chromium installed.'
        : 'Passive + optional active verification against localhost.',
    [browser],
  )

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    setStatus('queued')
    try {
      const started = await api.startScan({
        target,
        max_pages: maxPages,
        active,
        browser,
        auth_contexts_path: useAuth ? authPath : null,
      })
      setStatus(started.status)
      const finished = await pollScan(started.id, (scan) => {
        setStatus(scan.status)
      })
      if (finished.status === 'failed') {
        setError(finished.error || 'Scan failed')
        return
      }
      navigate(`/scans/${finished.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <header className="page-header">
        <h1>New scan</h1>
        <p>{hint}</p>
      </header>

      {error && <div className="callout danger">{error}</div>}
      {busy && status && (
        <div className="callout">
          Scan status: <span className={`badge ${status}`}>{status}</span>
          <span className="muted"> — polling until complete…</span>
        </div>
      )}

      <div className="panel">
        <form className="form" onSubmit={onSubmit}>
          <label>
            Target URL
            <input
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
            />
          </label>
          <label>
            Max pages
            <input
              type="number"
              min={1}
              max={500}
              value={maxPages}
              onChange={(e) => setMaxPages(Number(e.target.value))}
            />
          </label>
          <div className="row">
            <label className="check">
              <input
                type="checkbox"
                checked={active}
                onChange={(e) => setActive(e.target.checked)}
              />
              Active verification
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={browser}
                onChange={(e) => setBrowser(e.target.checked)}
              />
              Browser discovery
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={useAuth}
                onChange={(e) => setUseAuth(e.target.checked)}
              />
              Auth contexts
            </label>
          </div>
          {useAuth && (
            <label>
              Auth contexts path (server-local)
              <input
                type="text"
                value={authPath}
                onChange={(e) => setAuthPath(e.target.value)}
              />
            </label>
          )}
          <button className="btn" type="submit" disabled={busy}>
            {busy ? 'Scanning…' : 'Start scan'}
          </button>
        </form>
      </div>

      <p className="muted">
        Prefer the CLI for heavy runs?{' '}
        <span className="mono">
          magic-security http://127.0.0.1:8000 --active
        </span>{' '}
        then refresh <Link to="/history">History</Link>.
      </p>
    </div>
  )
}
