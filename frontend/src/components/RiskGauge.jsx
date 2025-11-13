import React from 'react';

export default function RiskGauge({ score, status }) {
  const getColor = () => {
    switch (status) {
      case 'SAFE':
        return '#10b981';
      case 'SUSPICIOUS':
        return '#f59e0b';
      case 'MALICIOUS':
        return '#ef4444';
      default:
        return '#9ca3af';
    }
  };

  const getStatusText = () => {
    switch (status) {
      case 'SAFE':
        return 'Safe';
      case 'SUSPICIOUS':
        return 'Suspicious';
      case 'MALICIOUS':
        return 'Malicious';
      default:
        return 'Unknown';
    }
  };

  // Calculate needle position
  const degrees = 180 - (score * 1.8);
  const radians = (degrees * Math.PI) / 180;
  
  const centerX = 100;
  const centerY = 90;
  const needleLength = 70;
  
  const needleX = centerX + needleLength * Math.cos(radians);
  const needleY = centerY - needleLength * Math.sin(radians);

  // Determine which sections should be bright vs faded
  const greenOpacity = score <= 30 ? 1 : 0.2;
  const yellowOpacity = score > 30 && score <= 70 ? 1 : 0.2;
  const redOpacity = score > 70 ? 1 : 0.2;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-80 h-40">
        <svg viewBox="0 0 200 100" className="w-full h-full">
          
          {/* Green section (0-30) */}
          <path
            d="M 20 90 A 80 80 0 0 1 68 24"
            fill="none"
            stroke="#10b981"
            strokeWidth="20"
            strokeLinecap="round"
            opacity={greenOpacity}
          />

          {/* Yellow section (30-70) */}
          <path
            d="M 68 24 A 80 80 0 0 1 132 24"
            fill="none"
            stroke="#f59e0b"
            strokeWidth="20"
            strokeLinecap="round"
            opacity={yellowOpacity}
          />

          {/* Red section (70-100) */}
          <path
            d="M 132 24 A 80 80 0 0 1 180 90"
            fill="none"
            stroke="#ef4444"
            strokeWidth="20"
            strokeLinecap="round"
            opacity={redOpacity}
          />

          {/* Center circle */}
          <circle cx="100" cy="90" r="8" fill="white" stroke={getColor()} strokeWidth="2" />

          {/* Needle */}
          <line
            x1="100"
            y1="90"
            x2={needleX}
            y2={needleY}
            stroke={getColor()}
            strokeWidth="3"
            strokeLinecap="round"
          />
          
          {/* Needle tip circle */}
          <circle cx={needleX} cy={needleY} r="4" fill={getColor()} />
        </svg>
      </div>

      {/* Score Display */}
      <div className="text-center mt-4">
        <div className="text-6xl font-bold mb-2" style={{ color: getColor() }}>
          {Math.round(score * 10) / 10}
        </div>
        <div className="text-sm text-gray-500 mb-1">Risk Score</div>
        <div className="text-xl font-semibold uppercase tracking-wide" style={{ color: getColor() }}>
          {getStatusText()}
        </div>
      </div>
    </div>
  );
}