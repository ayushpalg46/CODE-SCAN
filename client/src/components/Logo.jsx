import React from 'react';
import logoImg from '../assets/logo.jpg';

export default function Logo({ className }) {
  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <img
        src={logoImg}
        className={className}
        style={{
          width: '100%',
          height: '100%',
          transform: 'scale(2.2)',
          objectFit: 'contain'
        }}
        alt="CODE-SCAN Logo"
      />
    </div>
  );
}
