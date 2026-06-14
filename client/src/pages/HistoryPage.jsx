import React from 'react';
import Navbar from '../components/Navbar';

export default function HistoryPage({ activeTab, setActiveTab, scanHistory }) {
  return (
    <div className="frame board-2ca2c79e627d history-page">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={1} />

      <div className="history-content">
        {(!scanHistory || scanHistory.length === 0) ? (
          <div className="history-empty">
            <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3 }}>
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <p className="history-empty-text">No Scan History Yet</p>
            <p className="history-empty-sub">Complete a scan to see your history here.</p>
          </div>
        ) : (
          <div className="history-list">
            {scanHistory.map((entry, index) => (
              <div key={index} className="history-card">
                {/* Index number */}
                <div className="history-index">{index + 1}]</div>

                {/* Details */}
                <div className="history-details">
                  <div className="history-row">
                    <span className="history-label">Project Name:-</span>
                    <span className="history-value">{entry.projectName || 'N/A'}</span>
                  </div>
                  <div className="history-row">
                    <span className="history-label">No. Of Vulnerability Detected:-</span>
                    <span className="history-value">{entry.vulnDetected ?? 0}</span>
                  </div>
                  <div className="history-row">
                    <span className="history-label">No. Of Vulnerability Solved:-</span>
                    <span className="history-value">{entry.vulnSolved ?? 0}</span>
                  </div>
                  <div className="history-row">
                    <span className="history-label">Level Of Scan:-</span>
                    <span className="history-value">{entry.scanLevel ? entry.scanLevel.toUpperCase() : 'BASIC'}</span>
                  </div>
                  <div className="history-row">
                    <span className="history-label">Level Of Risk:-</span>
                    <span className={`history-value history-risk-${(entry.riskLevel || 'low').toLowerCase()}`}>
                      {entry.riskLevel || 'LOW'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
