import { NavLink, Outlet } from 'react-router-dom'
import { clearApiToken } from '../api'

const links = [
  { to: '/', label: 'Status', end: true },
  { to: '/targets', label: 'Targets' },
  { to: '/findings', label: 'Findings' },
  { to: '/scan', label: 'New scan' },
  { to: '/history', label: 'History' },
]

export function AppLayout() {
  const logout = () => { clearApiToken(); window.location.assign('/login') }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-lockup"><span className="brand-dot" /> magic security</div>
          <div className="brand-sub">security workspace</div>
        </div>
        <div className="workspace-switcher">
          <span className="eyebrow">Workspace</span>
          <strong>Acme Labs</strong>
          <span className="chevron">⌄</span>
        </div>
        <div className="nav-section-label">Monitor</div>
        <nav className="nav">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.end}
              className={({ isActive }) => (isActive ? 'active' : undefined)}
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="status-dot"><span /> Scanner online</div>
          <button className="user-chip" type="button" onClick={logout}><span className="avatar">PM</span><span><strong>Payam</strong><small>Owner · Sign out</small></span><span className="more">↗</span></button>
        </div>
      </aside>
      <main className="main">
        <div className="topbar"><span className="breadcrumb">Acme Labs <span>/</span> Overview</span><div className="topbar-actions"><button className="icon-btn" aria-label="Notifications">♢</button><button className="help-btn">?</button></div></div>
        <Outlet />
      </main>
    </div>
  )
}
