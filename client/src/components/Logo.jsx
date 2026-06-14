import React from 'react';

export default function Logo({ className }) {
  return (
    <svg
      viewBox="0 0 100 100"
      className={className}
      style={{ width: '100%', height: '100%' }}
    >
      <defs>
        {/* Clip path to cut left bracket vertically at x = 38 */}
        <clipPath id="clip-left">
          <rect x="0" y="0" width="38" height="100" />
        </clipPath>
        
        {/* Clip path to cut right bracket vertically at x = 62 */}
        <clipPath id="clip-right">
          <rect x="62" y="0" width="38" height="100" />
        </clipPath>
        
        {/* Clip path to cut slashes horizontally at y = 25 and y = 75 */}
        <clipPath id="clip-slashes">
          <rect x="0" y="25" width="100" height="50" />
        </clipPath>
      </defs>

      {/* Left Bracket < */}
      <g clipPath="url(#clip-left)">
        {/* Outer Left Bracket */}
        <path
          d="M 38 37 L 25 50 L 38 63"
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
          strokeLinecap="butt"
          strokeLinejoin="miter"
        />
        {/* Inner Left Bracket (perfectly parallel, shifted right by 6 units) */}
        <path
          d="M 38 43 L 31 50 L 38 57"
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
          strokeLinecap="butt"
          strokeLinejoin="miter"
        />
      </g>

      {/* Center Slashes / */}
      <g clipPath="url(#clip-slashes)">
        {/* Left Slash Line */}
        <path
          d="M 40 75 L 54 25"
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
          strokeLinecap="butt"
        />
        {/* Right Slash Line */}
        <path
          d="M 46 75 L 60 25"
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
          strokeLinecap="butt"
        />
      </g>

      {/* Right Bracket > */}
      <g clipPath="url(#clip-right)">
        {/* Outer Right Bracket */}
        <path
          d="M 62 37 L 75 50 L 62 63"
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
          strokeLinecap="butt"
          strokeLinejoin="miter"
        />
        {/* Inner Right Bracket (perfectly parallel, shifted left by 6 units) */}
        <path
          d="M 62 43 L 69 50 L 62 57"
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
          strokeLinecap="butt"
          strokeLinejoin="miter"
        />
      </g>
    </svg>
  );
}
