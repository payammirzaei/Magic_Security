import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { api, clearApiToken } from '../api'
import { useEffect, useState } from 'react'

const links = [
  { to: '/', label: 'Status', end: true },
  { to: '/targets', label: 'Targets' },
  { to: '/findings', label: 'Findings' },
  { to: '/scan', label: 'New scan' },
  { to: '/history', label: 'History' },
]

export function AppLayout() {
  const location = useLocation()
  const [workspaceName, setWorkspaceName] = useState('Acme Labs')
  const [userName, setUserName] = useState('Payam')
  const [role, setRole] = useState('Owner')
  const [workspaces, setWorkspaces] = useState<{ id: string; name: string }[]>([])
  useEffect(() => { Promise.all([api.workspace(), api.me(), api.workspaces()]).then(([workspace, user, all]) => { setWorkspaceName(workspace.name); setUserName(user.name); setRole(user.role); setWorkspaces(all) }).catch(() => undefined) }, [])
  const logout = () => { clearApiToken(); window.location.assign('/login') }
  const createWorkspace = async () => { const name = window.prompt('Workspace name'); if (!name?.trim()) return; try { const created = await api.createWorkspace(name.trim()); setWorkspaces((current) => [...current, created]); window.localStorage.setItem('magic_security_workspace', created.id); window.location.reload() } catch (err) { window.alert(err instanceof Error ? err.message : String(err)) } }
  const renameWorkspace = async () => { const active = window.localStorage.getItem('magic_security_workspace') || 'default'; const name = window.prompt('New workspace name', workspaceName); if (!name?.trim()) return; try { await api.renameWorkspace(active, name.trim()); window.location.reload() } catch (err) { window.alert(err instanceof Error ? err.message : String(err)) } }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-lockup"><span className="brand-dot" /> magic security</div>
          <div className="brand-sub">security workspace</div>
        </div>
        <div className="workspace-switcher">
          <span className="eyebrow">Workspace</span>
          <select className="workspace-select" value={window.localStorage.getItem('magic_security_workspace') || 'default'} onChange={(event) => { window.localStorage.setItem('magic_security_workspace', event.target.value); window.location.reload() }} aria-label="Active workspace">{(workspaces.length ? workspaces : [{ id: 'default', name: workspaceName }]).map((workspace) => <option value={workspace.id} key={workspace.id}>{workspace.name}</option>)}</select>
          <span className="chevron">⌄</span>
          <button className="workspace-add" type="button" onClick={createWorkspace}>+ New workspace</button>
          <button className="workspace-add" type="button" onClick={renameWorkspace}>Rename workspace</button>
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
          <button className="user-chip" type="button" onClick={logout}><span className="avatar">{userName.slice(0, 2).toUpperCase()}</span><span><strong>{userName}</strong><small>{role} · Sign out</small></span><span className="more">↗</span></button>
        </div>
      </aside>
      <main className="main">
        <div className="topbar"><span className="breadcrumb">{workspaceName} <span>/</span> {location.pathname === '/' ? 'Overview' : location.pathname.split('/')[1]?.replace('-', ' ') || 'Overview'}</span><div className="topbar-actions"><button className="icon-btn" aria-label="Notifications">♢</button><button className="help-btn">?</button></div></div>
        <Outlet />
      </main>
    </div>
  )
}
