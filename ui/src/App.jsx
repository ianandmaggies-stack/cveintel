import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { isAuthenticated } from './store/authStore.js'
import Login from './pages/Login.jsx'
import AppShell from './components/layout/AppShell.jsx'
import Brief from './pages/Brief.jsx'
import Dashboard from './pages/Dashboard.jsx'
import CveList from './pages/CveList.jsx'
import CveDetail from './pages/CveDetail.jsx'
import ExecutiveReport from './pages/ExecutiveReport.jsx'
import ThreatLandscape from './pages/ThreatLandscape.jsx'
import About from './pages/About.jsx'
import Diagnostics from './pages/Diagnostics.jsx'

function PrivateRoute({ children }) {
  return isAuthenticated() ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={
          <PrivateRoute>
            <AppShell />
          </PrivateRoute>
        }>
          <Route index              element={<Navigate to="/brief" replace />} />
          <Route path="brief"       element={<Brief />} />
          <Route path="dashboard"   element={<Dashboard />} />
          <Route path="cves"        element={<CveList />} />
          <Route path="cves/:cveId" element={<CveDetail />} />
          <Route path="report"      element={<ExecutiveReport />} />
          <Route path="landscape"   element={<ThreatLandscape />} />
          <Route path="about"       element={<About />} />
          <Route path="diagnostics" element={<Diagnostics />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
