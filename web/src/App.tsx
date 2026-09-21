import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { api } from './api'
import { AppLayout } from './components/AppLayout'
import { HistoryPage } from './pages/HistoryPage'
import { FindingsPage } from './pages/FindingsPage'
import { FindingDetailPage } from './pages/FindingDetailPage'
import { LoginPage } from './pages/LoginPage'

function ProtectedLayout() {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    const token = window.localStorage.getItem('magic_security_api_key') || import.meta.env.VITE_MAGIC_SECURITY_API_KEY
    if (!token) { setReady(true); return }
    api.me().then(() => setReady(true)).catch(() => window.location.assign('/login'))
  }, [])
  if (!ready) return <div className="auth-loading">Checking workspace access…</div>
  return <AppLayout />
}
import { HomePage } from './pages/HomePage'
import { NewScanPage } from './pages/NewScanPage'
import { ScanDetailPage } from './pages/ScanDetailPage'
import { TargetsPage } from './pages/TargetsPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedLayout />}>
          <Route index element={<HomePage />} />
          <Route path="targets" element={<TargetsPage />} />
          <Route path="scan" element={<NewScanPage />} />
          <Route path="history" element={<HistoryPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:findingId" element={<FindingDetailPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
