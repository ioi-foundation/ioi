import { BrowserRouter, Routes, Route, Outlet } from 'react-router-dom';
import AppLayout from './components/Layout'; // Your existing OCB layout
import MarketingNav from './components/MarketingNav';
import Footer from './components/Footer';

// App Pages
import Dashboard from './pages/Dashboard';
import Canvas from './pages/Canvas';
import Services from './pages/Services';
import Deployments from './pages/Deployments';
import Policies from './pages/Policies';
import Receipts from './pages/Receipts';
import Observability from './pages/Observability';
import Billing from './pages/Billing';
import Customers from './pages/Customers';
import Marketplace from './pages/Marketplace';
import Settings from './pages/Settings';
import Disputes from './pages/Disputes';

// Marketing Pages
import Landing from './pages/marketing/Landing';
import Framework from './pages/marketing/Framework';
import Network from './pages/marketing/Network';
import Templates from './pages/marketing/Templates';
import Docs from './pages/marketing/Docs';
import Economics from './pages/marketing/Economics';
import Security from './pages/marketing/Security';
import Solutions from './pages/marketing/Solutions';
import Changelog from './pages/marketing/Changelog';

// Auth Pages
import Login from './pages/auth/Login';

// Marketing Shell
function MarketingLayout() {
  return (
    <div className="min-h-screen bg-black text-white font-sans selection:bg-white/30">
      <MarketingNav />
      <main>
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* PUBLIC MARKETING SITE */}
        <Route element={<MarketingLayout />}>
          <Route path="/" element={<Landing />} />
          <Route path="/framework" element={<Framework />} />
          <Route path="/network" element={<Network />} />
          <Route path="/templates" element={<Templates />} />
          <Route path="/docs" element={<Docs />} />
          <Route path="/economics" element={<Economics />} />
          <Route path="/security" element={<Security />} />
          <Route path="/solutions" element={<Solutions />} />
          <Route path="/changelog" element={<Changelog />} />
        </Route>

        {/* AUTH ROUTES */}
        <Route path="/login" element={<Login />} />

        {/* AUTHENTICATED APP DASHBOARD */}
        <Route path="/app" element={<AppLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="services" element={<Services />} />
          <Route path="canvas" element={<Canvas />} />
          <Route path="deployments" element={<Deployments />} />
          <Route path="policies" element={<Policies />} />
          <Route path="receipts" element={<Receipts />} />
          <Route path="observability" element={<Observability />} />
          <Route path="billing" element={<Billing />} />
          <Route path="customers" element={<Customers />} />
          <Route path="marketplace" element={<Marketplace />} />
          <Route path="disputes" element={<Disputes />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
