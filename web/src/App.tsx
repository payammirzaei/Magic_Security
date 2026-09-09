import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/AppLayout'
import { HistoryPage } from './pages/HistoryPage'
import { HomePage } from './pages/HomePage'
import { NewScanPage } from './pages/NewScanPage'
import { ScanDetailPage } from './pages/ScanDetailPage'
import { TargetsPage } from './pages/TargetsPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<HomePage />} />
          <Route path="targets" element={<TargetsPage />} />
          <Route path="scan" element={<NewScanPage />} />
          <Route path="history" element={<HistoryPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
