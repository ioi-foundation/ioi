// src/App.jsx
import React from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import MarketplaceApp from './product/MarketplaceApp';

function App() {
  return (
    <Router>
      <MarketplaceApp />
    </Router>
  );
}

export default App;
