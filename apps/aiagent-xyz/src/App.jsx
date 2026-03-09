// src/App.jsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import ProductDetail from './pages/ProductDetail';
import Freelance from './pages/Freelance';
import PostJob from './pages/PostJob';
import Profile from './pages/Profile';
import SellAgent from './pages/SellAgent';
import JobDetail from './pages/JobDetail';
import Dashboard from './pages/Dashboard';
import Status from './pages/Status'; // Import new page
import NotFound from './pages/NotFound';
import Footer from './components/Footer';

function App() {
  return (
    <Router>
      <div className="flex flex-col min-h-screen">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/agent/:id" element={<ProductDetail />} />
          <Route path="/freelance" element={<Freelance />} />
          <Route path="/freelance/:id" element={<JobDetail />} />
          <Route path="/post-job" element={<PostJob />} />
          <Route path="/profile/:id" element={<Profile />} />
          <Route path="/sell" element={<SellAgent />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/status" element={<Status />} /> {/* Wired up */}
          <Route path="*" element={<NotFound />} />
        </Routes>
        <Footer />
      </div>
    </Router>
  );
}

export default App;