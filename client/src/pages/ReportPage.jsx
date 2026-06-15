import React, { useState } from 'react';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import Navbar from '../components/Navbar';

export default function ReportPage({ activeTab, setActiveTab, scanHistory, defaultReportIndex, onClearDefault }) {
  const [viewingReport, setViewingReport] = useState(() => {
    if (defaultReportIndex !== null && defaultReportIndex !== undefined && scanHistory && scanHistory[defaultReportIndex]) {
      return defaultReportIndex;
    }
    return null;
  });

  const closeReport = () => {
    setViewingReport(null);
    if (onClearDefault) {
      onClearDefault();
    }
  };
  const [downloading, setDownloading] = useState(null);
  const [isExporting, setIsExporting] = useState(false);

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
    lines.push(`--- Code Scores ---`);
    lines.push(`Security Score:    ${entry.securityScore ?? 'N/A'}/100`);
    lines.push(`Quality Score:     ${entry.qualityScore ?? 'N/A'}/100`);
    lines.push(`Performance Score: ${entry.performanceScore ?? 'N/A'}/100`);
    lines.push(`Total Code-Score:  ${entry.score ?? 'N/A'}/100`);
    lines.push(``);
    lines.push(`Scan Date:     ${entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'N/A'}`);
    lines.push(`========================================`);

    return lines.join('\n');
  };

  const handleDownloadPdf = (entry, index) => {
    if (isExporting) return;
    setIsExporting(true);
    setDownloading({ entry, index });

    // Wait for the state to render the off-screen capture target in the DOM
    setTimeout(() => {
      const target = document.getElementById('pdf-download-capture-target');
      if (target) {
        html2canvas(target, {
          scale: 2.5, // High resolution
          useCORS: true,
          logging: false,
          backgroundColor: '#ffffff'
        }).then((canvas) => {
          const imgData = canvas.toDataURL('image/png');
          const pdf = new jsPDF('p', 'mm', 'a4');
          const pdfWidth = pdf.internal.pageSize.getWidth();
          const pdfHeight = pdf.internal.pageSize.getHeight();
          pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
          pdf.save(`CODE-SCAN_Report_${(entry.projectName || 'Project').replace(/\s+/g, '_')}_${index + 1}.pdf`);
          setDownloading(null);
          setIsExporting(false);
        }).catch((err) => {
          console.error("PDF generation failed:", err);
          setDownloading(null);
          setIsExporting(false);
        });
      } else {
        setDownloading(null);
        setIsExporting(false);
      }
    }, 150);
  };

  const handleDownloadFromViewer = () => {
    if (viewingReport === null || isExporting) return;
    setIsExporting(true);
    const entry = scanHistory[viewingReport];
    const target = document.getElementById('pdf-viewer-capture-target');
    if (target) {
      html2canvas(target, {
        scale: 2.5,
        useCORS: true,
        logging: false,
        backgroundColor: '#ffffff'
      }).then((canvas) => {
        const imgData = canvas.toDataURL('image/png');
        const pdf = new jsPDF('p', 'mm', 'a4');
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = pdf.internal.pageSize.getHeight();
        pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
        pdf.save(`CODE-SCAN_Report_${(entry.projectName || 'Project').replace(/\s+/g, '_')}_${viewingReport + 1}.pdf`);
        setIsExporting(false);
      }).catch((err) => {
        console.error("PDF generation failed from viewer:", err);
        setIsExporting(false);
      });
    } else {
      setIsExporting(false);
    }
  };

  const renderPdfTemplate = (entry, targetId) => {
    const findingsToShow = entry.findings || [];
    const listItems = findingsToShow.map((finding, i) => {
      let title = finding.title || 'Vulnerability detected';
      if (finding.file) {
        title += ` in ${finding.file}`;
      }
      if (finding.line) {
        title += `:${finding.line}`;
      }
      return `${i + 1}] ${title}`;
    });

    return (
      <div className="pdf-template-wrapper" id={targetId}>
        {/* Top Header */}
        <div>
          <div className="pdf-header">
            <span className="pdf-logo">&lt;/&gt; CODE-SCAN</span>
            <span className="pdf-title">ProjectReport</span>
          </div>
          <div className="pdf-thick-divider"></div>

          {/* Project Details */}
          <div className="pdf-box">
            <div className="pdf-box-title">Project Detail's:</div>
            <div className="pdf-box-content">
              <p>Project Name: <span className="pdf-value">{entry.projectName || 'N/A'}</span></p>
              <p>Project TechStack: <span className="pdf-value">{entry.techStack || 'N/A'}</span></p>
              <p>Project URL/.git Link: <span className="pdf-value">{entry.scanTarget || 'N/A'}</span></p>
            </div>
          </div>

          {/* Scanned Project Details */}
          <div className="pdf-box">
            <div className="pdf-box-title">Scanned Project Detail's:</div>
            <div className="pdf-box-content">
              <p>Level Of Project Scanned: <span className="pdf-value">{entry.scanLevel ? entry.scanLevel.toUpperCase() : 'BASIC'}</span></p>
              <p>No. Of Vulnerability Detected: <span className="pdf-value">{entry.vulnDetected ?? 0}</span></p>
              <p>Level Of Security Risk: <span className="pdf-value">{entry.riskLevel || 'LOW'}</span></p>
            </div>
          </div>

          {/* List Of Vulnerability */}
          {findingsToShow.length > 0 && (
            <div className="pdf-box">
              <div className="pdf-box-title">List Of Vulnerability:</div>
              <div className="pdf-box-content pdf-vuln-list">
                {listItems.map((item, idx) => (
                  <div key={idx} className="pdf-vuln-item">{item}</div>
                ))}
              </div>
            </div>
          )}

          {/* Code-Score */}
          <div className="pdf-box">
            <div className="pdf-box-title">Code-Score:</div>
            <div className="pdf-box-content">
              <p>Quality Score: <span className="pdf-value">{entry.qualityScore ?? 'N/A'}/100</span></p>
              <p>Security Score: <span className="pdf-value">{entry.securityScore ?? 'N/A'}/100</span></p>
              <p>Performance Score: <span className="pdf-value">{entry.performanceScore ?? 'N/A'}/100</span></p>
            </div>
          </div>

          {/* Total Code Score */}
          <div className="pdf-score-box">
            <h1 className="pdf-total-score-text">Total Code-Score:{entry.score ?? 'N/A'}/100</h1>
          </div>
        </div>

        {/* Footer */}
        <div className="pdf-footer-section">
          <div className="pdf-footer-title">Whole Report By:</div>
          <div className="pdf-footer-grid">
            <div className="pdf-footer-col left-col">
              <span>Check.</span>
              <span>Detect.</span>
              <span>Protect.</span>
            </div>
            <div className="pdf-footer-logo-box">
              CODE-SCAN
            </div>
            <div className="pdf-footer-col right-col">
              <span>Find.</span>
              <span>Fix.</span>
              <span>Fortify.</span>
            </div>
          </div>
        </div>
      </div>
    );
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
            {/* Visual Report Viewer Overlay */}
            {viewingReport !== null && (
              <div className="pdf-viewer-overlay" onClick={closeReport}>
                {/* Toolbar */}
                <div className="pdf-viewer-toolbar" onClick={(e) => e.stopPropagation()}>
                  <button 
                    className="pdf-toolbar-btn pdf-toolbar-btn-download" 
                    onClick={handleDownloadFromViewer}
                    disabled={isExporting}
                  >
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '4px' }}>
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                      <polyline points="7 10 12 15 17 10" />
                      <line x1="12" y1="15" x2="12" y2="3" />
                    </svg>
                    {isExporting ? 'Downloading...' : 'Download PDF'}
                  </button>
                  <button className="pdf-toolbar-btn pdf-toolbar-btn-close" onClick={closeReport}>
                    Close
                  </button>
                </div>

                {/* Preview Container */}
                <div className="pdf-preview-scroll-container" onClick={closeReport}>
                  <div onClick={(e) => e.stopPropagation()}>
                    {renderPdfTemplate(scanHistory[viewingReport], 'pdf-viewer-capture-target')}
                  </div>
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
                      onClick={() => handleDownloadPdf(entry, index)}
                      disabled={isExporting}
                    >
                      {isExporting && downloading?.index === index ? 'Downloading...' : 'Download Report'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Offscreen rendering container for direct downloads from list */}
      <div style={{ position: 'absolute', top: '-9999px', left: '-9999px', pointerEvents: 'none' }}>
        {downloading && renderPdfTemplate(downloading.entry, 'pdf-download-capture-target')}
      </div>
    </div>
  );
}
