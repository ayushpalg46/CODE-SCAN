import React, { useState } from 'react';
import Navbar from '../components/Navbar';

export default function SolutionPage({ activeTab, setActiveTab, scanHistory }) {
  const [selectedProjectIndex, setSelectedProjectIndex] = useState(null);

  const handleBack = () => {
    setSelectedProjectIndex(null);
  };

  const getSeverityColor = (severity) => {
    switch ((severity || '').toLowerCase()) {
      case 'critical':
      case 'high':
        return '#ff3333';
      case 'medium':
        return '#ffaa00';
      case 'low':
      default:
        return '#44ff44';
    }
  };

  const selectedProject = selectedProjectIndex !== null ? scanHistory[selectedProjectIndex] : null;

  return (
    <div className="frame board-2ca2c79e627d solution-page">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={1} />

      <div className="solution-content">
        {!selectedProject ? (
          // Main Selection View
          <>
            <div className="solution-header-title">
              Select The Project To Discover Solutions
            </div>

            {(!scanHistory || scanHistory.length === 0) ? (
              <div className="solution-empty">
                <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3 }}>
                  <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                  <circle cx="12" cy="12" r="10" />
                </svg>
                <p className="solution-empty-text">No Projects Scanned Yet</p>
                <p className="solution-empty-sub">Complete a scan first to view solutions.</p>
              </div>
            ) : (
              <div className="solution-list">
                {scanHistory.map((entry, index) => (
                  <div
                    key={index}
                    className="solution-card"
                    onClick={() => setSelectedProjectIndex(index)}
                  >
                    <div className="solution-index">{index + 1}]</div>
                    <div className="solution-card-details">
                      <div className="solution-row">
                        <span className="solution-label">Project Name:-</span>
                        <span className="solution-value">{entry.projectName || 'N/A'}</span>
                      </div>
                      <div className="solution-row">
                        <span className="solution-label">Level Of Scan:-</span>
                        <span className="solution-value">{entry.scanLevel ? entry.scanLevel.toUpperCase() : 'BASIC'}</span>
                      </div>
                      <div className="solution-row">
                        <span className="solution-label">Level Of Risk:-</span>
                        <span className="solution-value" style={{ color: getSeverityColor(entry.riskLevel) }}>
                          {entry.riskLevel || 'LOW'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          // Solution Details View (Solution Second Page)
          <div className="solution-detail-container">
            <div className="solution-detail-header-nav">
              <button className="solution-back-btn" onClick={handleBack}>
                &larr; Back to Projects
              </button>
            </div>

            {/* Selected Project Card matching board-2ce48505f9a2 */}
            <div className="frame board-2ce48505f9a2">
              <div className="shape text c-1-2ce48505f9a6">
                {selectedProjectIndex + 1}]
              </div>
              <div className="project-details-grid">
                <div className="shape text project-na-2ce48505f9a3">
                  <span className="label">Project Name:-</span>
                  <span className="value"> {selectedProject.projectName || 'N/A'}</span>
                </div>
                <div className="shape text level-of-s-2ce48505f9a5">
                  <span className="label">Level Of Scan:-</span>
                  <span className="value"> {selectedProject.scanLevel ? selectedProject.scanLevel.toUpperCase() : 'BASIC'}</span>
                </div>
                <div className="shape text level-of-r-2ce48505f9a4">
                  <span className="label">Level Of Risk:-</span>
                  <span className="value" style={{ color: getSeverityColor(selectedProject.riskLevel) }}>
                    {selectedProject.riskLevel || 'LOW'}
                  </span>
                </div>
              </div>
            </div>

            {/* Fixes divider matching board-2ce48ecdab20 */}
            <div className="frame board-2ce48ecdab20">
              <div className="shape text fixs-of-t-2ce40157755f">
                Fix's Of The Vulnerability's
              </div>
            </div>

            {(!selectedProject.findings || selectedProject.findings.length === 0) ? (
              <div className="solution-clean-state">
                <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="#44ff44" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '15px' }}>
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                  <polyline points="22 4 12 14.01 9 11.01" />
                </svg>
                <p className="solution-clean-text">All Clear!</p>
                <p className="solution-clean-sub">No vulnerabilities detected for this project.</p>
              </div>
            ) : (
              <div className="solution-findings-list">
                {selectedProject.findings.map((finding, idx) => (
                  <div key={idx} className="finding-solution-card">
                    {/* Header */}
                    <div className="finding-header">
                      <div className="finding-title-row">
                        <span className="finding-number">{idx + 1}.</span>
                        <span className="finding-title">{finding.title}</span>
                      </div>
                      <span
                        className="finding-severity-badge"
                        style={{
                          borderColor: getSeverityColor(finding.severity),
                          color: getSeverityColor(finding.severity)
                        }}
                      >
                        {(finding.severity || 'low').toUpperCase()}
                      </span>
                    </div>

                    {/* Meta info (like file path if exists) */}
                    {finding.file && (
                      <div className="finding-meta">
                        <span className="meta-label">File:</span>
                        <span className="meta-value">{finding.file}</span>
                      </div>
                    )}

                    {/* Description */}
                    {finding.description && (
                      <div className="finding-body-section">
                        <div className="finding-section-label">Description:</div>
                        <div className="finding-section-desc">{finding.description}</div>
                      </div>
                    )}

                    {/* Remediation / Solution */}
                    <div className="finding-remediation-box">
                      <div className="remediation-header">
                        <div className="shape text solution-2ce40157755e">
                          Solution:
                        </div>
                        <span className="ai-generated-badge">
                          <span className="ai-sparkle-icon">✨</span> AI Generated
                        </span>
                      </div>
                      <div className="remediation-content">
                        {finding.remediation || 'Upgrade dependency or configure response headers properly.'}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

