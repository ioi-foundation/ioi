// src/components/BrandLogo.jsx
import React from 'react';

export default function BrandLogo({ className = '', surface = 'light' }) {
  const image = (
    <img
      src="/animated-logo.svg"
      alt="aiagent.xyz"
      className={`block h-full w-full object-contain ${className}`}
    />
  );

  if (surface === 'dark') {
    return (
      <span className="inline-flex h-10 w-[156px] items-center">
        {image}
      </span>
    );
  }

  return image;
}
