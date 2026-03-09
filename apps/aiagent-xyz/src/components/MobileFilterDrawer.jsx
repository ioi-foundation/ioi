// src/components/MobileFilterDrawer.jsx
import React from 'react';

export default function MobileFilterDrawer({ isOpen, onClose, children }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 lg:hidden">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200"
        onClick={onClose}
      ></div>
      
      {/* Drawer */}
      <div className="absolute inset-y-0 right-0 w-80 bg-white shadow-xl animate-in slide-in-from-right duration-300 flex flex-col">
        <div className="p-4 border-b border-gray-100 flex justify-between items-center">
          <h2 className="font-bold text-slate-900">Filters</h2>
          <button 
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-full hover:bg-slate-100 text-slate-500"
          >
            ✕
          </button>
        </div>
        
        <div className="flex-1 overflow-y-auto p-6">
          {children}
        </div>
        
        <div className="p-4 border-t border-gray-100">
          <button 
            onClick={onClose}
            className="w-full bg-slate-900 text-white font-bold py-3 rounded-lg"
          >
            Show Results
          </button>
        </div>
      </div>
    </div>
  );
}