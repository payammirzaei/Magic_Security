import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, setApiToken } from '../api'

export function LoginPage() {
  const navigate = useNavigate(); const [token, setToken] = useState(''); const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(null); setApiToken(token.trim()); try { await api.me(); navigate('/', { replace: true }) } catch { setError('Token is invalid or the API is unavailable.'); localStorage.removeItem('magic_security_api_key') } finally { setBusy(false) } }
  return <main className="auth-page"><div className="auth-card panel"><div className="brand-lockup"><span className="brand-dot" /> magic security</div><span className="eyebrow">Workspace access</span><h1>Sign in to your workspace</h1><p className="muted">Enter the API key configured for this Magic Security instance.</p>{error && <div className="callout danger">{error}</div>}<form className="form" onSubmit={submit}><label>API key<input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="••••••••••••" required autoFocus /></label><button className="btn" type="submit" disabled={busy}>{busy ? 'Checking…' : 'Continue →'}</button></form><small className="auth-note">Your key is stored locally in this browser and sent only to this API.</small></div></main>
}
