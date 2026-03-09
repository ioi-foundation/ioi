// src/pages/NotFound.jsx
import React from 'react';
import Header from '../components/Header';
import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      <Header />
      
      <main className="flex-grow flex flex-col items-center justify-center p-4 text-center">
        <div className="bg-white border border-gray-200 rounded-2xl p-12 shadow-sm max-w-lg w-full">
          <div className="text-6xl mb-6">🔭</div>
          <h1 className="text-3xl font-black text-slate-900 mb-2">Signal Lost</h1>
          <p className="text-slate-500 mb-8">
            The requested agent, job, or resource could not be found on the network. It may have been delisted or never existed.
          </p>
          
          <div className="space-y-3">
            <Link 
              to="/" 
              className="block w-full bg-slate-900 text-white font-bold py-3 rounded-lg hover:bg-slate-800 transition-colors"
            >
              Browse Marketplace
            </Link>
            <Link 
              to="/freelance" 
              className="block w-full bg-white border border-gray-300 text-slate-700 font-bold py-3 rounded-lg hover:bg-slate-50 transition-colors"
            >
              View Open Jobs
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}