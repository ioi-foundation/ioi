// src/components/MarketGrid.jsx
import React, { useState } from 'react';
import { Link } from 'react-router-dom';

export default function MarketGrid({ products }) {
  const [favorites, setFavorites] = useState(new Set());

  const toggleFavorite = (e, id) => {
    e.preventDefault();
    const newFavs = new Set(favorites);
    if (newFavs.has(id)) {
      newFavs.delete(id);
    } else {
      newFavs.add(id);
    }
    setFavorites(newFavs);
  };

  if (!products) return null;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-6">
      {products.map(p => (
        <Link to={`/agent/${p.id}`} key={p.id} className="block group h-full relative">
          <div className="bg-white border border-gray-200 rounded-lg overflow-hidden hover:shadow-lg transition-shadow cursor-pointer h-full flex flex-col">
            
            <div className="h-32 relative" style={{ background: p.image }}>
              <div className="absolute top-2 left-2 bg-black/40 text-white text-xs px-2 py-1 rounded backdrop-blur-sm">
                {p.type}
              </div>
              <button 
                onClick={(e) => toggleFavorite(e, p.id)}
                className="absolute top-2 right-2 p-1.5 rounded-full bg-white/10 hover:bg-white/20 backdrop-blur-sm transition-all"
              >
                <svg 
                  className={`w-4 h-4 transition-colors ${favorites.has(p.id) ? 'fill-red-500 text-red-500' : 'text-white fill-transparent'}`} 
                  viewBox="0 0 24 24" 
                  stroke="currentColor" 
                  strokeWidth="2"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
                </svg>
              </button>
            </div>
            
            <div className="p-4 flex flex-col flex-grow">
              <h3 className="font-bold text-slate-800 mb-1 group-hover:text-blue-600 truncate">{p.name}</h3>
              <p className="text-xs text-slate-500 mb-4 flex items-center gap-1">
                by <span className="text-blue-500 hover:underline">{p.dev}</span>
                <svg className="w-3 h-3 text-blue-500" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
              </p>
              
              <div className="flex items-center justify-between mt-auto pt-3 border-t border-gray-100">
                <div className="flex items-center gap-1">
                  <span className="text-yellow-500">★</span>
                  <span className="text-sm font-bold text-slate-700">{p.rating}</span>
                  <span className="text-xs text-slate-400">({p.reviews})</span>
                </div>
                <span className="font-bold text-slate-900 bg-slate-100 px-2 py-1 rounded text-sm">
                  {p.price}
                </span>
              </div>
            </div>
          </div>
        </Link>
      ))}
    </div>
  );
}