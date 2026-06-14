import React, { useState } from 'react';
import Navbar from '../components/Navbar';

export default function ReportPage({ activeTab, setActiveTab, scanHistory }) {
  const [viewingReport, setViewingReport] = useState(null);

  const generateReportText = (entry) => {
    const lines = [
      `========================================`,
      `         CODE-SCAN REPORT`,
      `========================================`,
      ``,
      `Project Name:  ${entry.projectName || 'N/A'}`,
      `Scan Level:    ${entry.scanLevel ? entry.scanLevel.toUpperCase() : 'BASIC'}`,
      `Risk Level:    ${entry.riskLevel || 'LOW'}`,
      ``,
      `--- Vulnerability Summary ---`,
      `Detected:      ${entry.vulnDetected ?? 0}`,
      `Solved:        ${entry.vulnSolved ?? 0}`,
      ``,
    ];

    if (entry.findings && entry.findings.length > 0) {
      lines.push(`--- Findings ---`);
      entry.findings.forEach((f, i) => {
        lines.push(`${i + 1}] ${f.title} [${f.severity?.toUpperCase()}]${f.file ? ` (${f.file})` : ''}`);
      });
    } else {
      lines.push(`--- No detailed findings available ---`);
    }

    lines.push(``);
    lines.push(`Score:         ${entry.score ?? 'N/A'}/100`);
    lines.push(`Scan Date:     ${entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'N/A'}`);
    lines.push(`========================================`);

    return lines.join('\n');
  };

  const handleDownload = (entry, index) => {
    const text = generateReportText(entry);
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CODE-SCAN_Report_${(entry.projectName || 'Project').replace(/\s+/g, '_')}_${index + 1}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="frame board-2ca2c79e627d report-page">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={1} />

      <div className="report-content">
        {(!scanHistory || scanHistory.length === 0) ? (
          <div className="report-empty">
            <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3 }}>
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
            <p className="report-empty-text">No Reports Available</p>
            <p className="report-empty-sub">Complete a scan to generate a report.</p>
          </div>
        ) : (
          <>
            {/* Report viewer overlay */}
            {viewingReport !== null && (
              <div className="report-viewer-overlay" onClick={() => setViewingReport(null)}>
                <div className="report-viewer-modal" onClick={(e) => e.stopPropagation()}>
                  <button className="report-viewer-close" onClick={() => setViewingReport(null)}>&times;</button>
                  <pre className="report-viewer-content">
                    {generateReportText(scanHistory[viewingReport])}
                  </pre>
                </div>
              </div>
            )}

            <div className="report-list">
              {scanHistory.map((entry, index) => (
                <div key={index} className="report-card">
                  {/* Index */}
                  <div className="report-index">{index + 1}]</div>

                  {/* Project name */}
                  <div className="report-project-name">
                    <span className="report-label">Project Name:-</span>
                    <span className="report-value">{entry.projectName || 'N/A'}</span>
                  </div>

                  {/* Action buttons */}
                  <div className="report-actions">
                    <button
                      className="report-btn report-btn-view"
                      onClick={() => setViewingReport(index)}
                    >
                      View Report
                    </button>
                    <button
                      className="report-btn report-btn-download"
                      onClick={() => handleDownload(entry, index)}
                    >
                      Download Report
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
