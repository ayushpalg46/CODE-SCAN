import React from 'react';
import Navbar from '../components/Navbar';

export default function ResultsPage({
  activeTab,
  setActiveTab,
  projectName,
  scanType,
  scanTarget,
  scanLevel,
  techStack,
  scanResults,
  onNext
}) {
  // Extract project name from scanTarget (URL or GitHub repo)
  const getProjectName = (target) => {
    if (!target) return 'CODE-SCAN Project';
    try {
      if (target.includes('github.com')) {
        const parts = target.replace(/\/$/, '').split('/');
        if (parts.length >= 2) {
          return parts.slice(-2).join('/');
        }
      }
      const url = new URL(target);
      return url.hostname;
    } catch (e) {
      return target;
    }
  };

  const displayProjectName = projectName || getProjectName(scanTarget);
  const totalScore = scanResults?.score !== undefined ? scanResults.score : 80;
  
  const qualityScore = scanResults?.qualityScore !== undefined ? scanResults.qualityScore : 85;
  const securityScore = scanResults?.securityScore !== undefined ? scanResults.securityScore : 80;
  const performanceScore = scanResults?.performanceScore !== undefined ? scanResults.performanceScore : 90;

  const findingsCount = scanResults?.findings?.length || 0;
  
  // Determine risk level
  const getRiskLevel = () => {
    if (!scanResults || !scanResults.summary) return 'LOW';
    const { critical, high, medium } = scanResults.summary;
    if (critical > 0 || high > 0) return 'HIGH';
    if (medium > 0) return 'MEDIUM';
    return 'LOW';
  };

  const riskLevel = getRiskLevel();

  // Get top findings
  const topFindings = scanResults?.findings || [];

  return (
    <div className="frame board-2ca68a6dfdd3 scrollable-results-view">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {/* Scrollable Container for all Dashboard Blocks */}
      <div className="results-scroll-container">
        
        {/* Row 1: Project Info Card */}
        <div className="frame board-2cbe018bc9b6">
          <div className="shape text project-na-2cbf326a2ca1">
            <span className="label">Project Name:-</span>
            <span className="value"> {displayProjectName}</span>
          </div>
          <div className="shape text project-te-2cbf3fe5cdd0">
            <span className="label">Project TechStack:-</span>
            <span className="value"> {techStack || 'Not Specified'}</span>
          </div>
          <div className="shape text project-u-r-2cbf57435760">
            <span className="label">Project URL/.git Link::-</span>
            <span className="value"> {scanTarget || 'Not Specified'}</span>
          </div>
        </div>

        {/* Row 2: Scan Summary Card */}
        <div className="frame board-2cbe3af48662">
          <div className="shape text level-of-s-2cbf6c2346fd">
            <span className="label">Level Of Scan:-</span>
            <span className="value"> {scanLevel ? scanLevel.toUpperCase() : 'BASIC'}</span>
          </div>
          <div className="shape text no-of-vul-2cbf7dca8e62">
            <span className="label">No. Of Vulnerability Detected:-</span>
            <span className="value"> {findingsCount}</span>
          </div>
          <div className="shape text level-of-r-2cbf8d714e26">
            <span className="label">Level Of Risk:-</span>
            <span className={`value risk-${riskLevel.toLowerCase()}`}> {riskLevel}</span>
          </div>
        </div>

        {/* Row 3: Vulnerabilities List Card */}
        <div className="frame board-2cbe4f21a97d">
          <div className="shape text list-of-vu-2cbfaf04617f">
            List Of Vulnerability:
          </div>
          
          <div className="vul-list">
            {topFindings.length > 0 ? (
              topFindings.map((finding, index) => (
                <div key={index} className="vul-item">
                  <span className="index">{index + 1}]</span>
                  <span className="vul-details">
                    <span className="vul-title">{finding.title}</span>
                    <span className={`vul-badge badge-${finding.severity?.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                    {finding.file && <span className="vul-file">({finding.file})</span>}
                  </span>
                </div>
              ))
            ) : (
              <div className="no-vul-msg">No vulnerabilities detected! Your code is secure.</div>
            )}
          </div>
        </div>

        {/* Row 4: Detailed Scores Card */}
        <div className="frame board-2cbe62a42d25">
          <div className="shape text quality-sc-2cbff070c1a4">
            <span className="label">Quality Score:</span>
            <span className="value"> {qualityScore}/100</span>
          </div>
          <div className="shape text security-s-2cbffb3933bd">
            <span className="label">Security Score:</span>
            <span className="value"> {securityScore}/100</span>
          </div>
          <div className="shape text performanc-2cc00287c816">
            <span className="label">Performance Score:</span>
            <span className="value"> {performanceScore}/100</span>
          </div>
        </div>

        {/* Row 5: Total Score Card */}
        <div className="frame board-2cbe843bc927">
          <div className="shape text total-code-2cc01187bf6b">
            Total Code-Score: {totalScore}/100
          </div>
        </div>

        {/* Row 6: Fix & Solution Banner */}
        <div className="frame board-2cbeb90440b6" style={{ display: 'flex', flexDirection: 'column', gap: '20px', alignItems: 'center' }}>
          <div className="shape text want-to-fi-2cc01f521c45">
            Want To Fix Vulnerabilities or Export the PDF Report? GO To:
          </div>
          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap', justifyContent: 'center' }}>
            <button 
              key="results-solution-btn"
              type="button"
              className="shape text s-o-l-u-t-i-o-n-2cc02b687bba solution-nav-btn"
              onClick={() => setActiveTab('SOLUTION')}
            >
              SOLUTION
            </button>
            <button 
              key="results-report-btn"
              type="button"
              className="shape text s-o-l-u-t-i-o-n-2cc02b687bba solution-nav-btn"
              onClick={() => setActiveTab('REPORT')}
              style={{ background: 'linear-gradient(135deg, #ff3333 0%, #ff6600 100%)', boxShadow: '0 0 15px rgba(255, 51, 51, 0.4)' }}
            >
              REPORT
            </button>
          </div>
        </div>

        {/* Row 7: Feedback Banner */}
        <div className="frame board-2cbec277c866">
          <div className="shape text for-our-se-2cc0859baf81">
            For Our Services Please Rate Us And Give FeedBack
          </div>
        </div>

        {/* Row 8: Next Button */}
        <button 
          key="results-next-btn"
          type="button" 
          className="frame board-2cbed8327d44 next-btn-container" 
          onClick={onNext}
        >
          <div className="shape text next-2cbeee8dea86">
            Next--&gt;
          </div>
        </button>

      </div>
    </div>
  );
}
