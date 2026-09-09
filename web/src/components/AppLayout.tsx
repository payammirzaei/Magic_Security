import { NavLink, Outlet } from 'react-router-dom'

const links = [
  { to: '/', label: 'Status', end: true },
  { to: '/targets', label: 'Targets' },
  { to: '/scan', label: 'New scan' },
  { to: '/history', label: 'History' },
]

export function AppLayout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">Magic Security</div>
          <div className="brand-sub">local · evidence-first</div>
        </div>
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
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
