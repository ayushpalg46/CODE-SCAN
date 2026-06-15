import React, { useState, useEffect, useRef } from 'react';
import Navbar from '../components/Navbar';

export default function LoadingPage({ activeTab, setActiveTab, scanType, scanTarget, scanLevel, onComplete }) {
  const [progress, setProgress] = useState(0); // Animated progress shown to user
  const targetProgressRef = useRef(0);
  const completionCalledRef = useRef(false);
  const latestResultsRef = useRef(null);

  const [statusMessage, setStatusMessage] = useState('Initializing Scan...');
  const [scanId, setScanId] = useState(null);
  const [error, setError] = useState(null);
  
  const pollIntervalRef = useRef(null);
  const simulationIntervalRef = useRef(null);
  const isMountedRef = useRef(true);

  // Helper to map scanLevel 'moderate' -> 'modrate', 'advance' -> 'advanced'
  const mapScanMode = (level) => {
    if (level === 'moderate') return 'modrate';
    if (level === 'advance') return 'advanced';
    return 'basic';
  };

  // Dynamic status text update
  function updateStatusText(progressPercent) {
    if (progressPercent < 25) {
      setStatusMessage('Analyzing The Code');
    } else if (progressPercent >= 25 && progressPercent < 50) {
      setStatusMessage('Detecting For Vulnerability’s');
    } else if (progressPercent >= 50 && progressPercent < 75) {
      setStatusMessage('Calculating Code-Score');
    } else if (progressPercent >= 75) {
      setStatusMessage('Finalizing And Polishing');
    }
  }

  // Animation/interpolation loop
  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev < targetProgressRef.current) {
          const diff = targetProgressRef.current - prev;
          // Smooth step: proportional to remaining distance, capped between 1 and 4
          const step = Math.max(1, Math.min(4, Math.ceil(diff / 6)));
          const next = prev + step;
          updateStatusText(next);
          return next;
        }
        
        // Trigger completion callback only when progress bar finishes filling to 100%
        if (prev >= 100 && targetProgressRef.current === 100 && !completionCalledRef.current) {
          completionCalledRef.current = true;
          clearInterval(interval);
          setTimeout(() => {
            if (isMountedRef.current && onComplete) {
              onComplete(latestResultsRef.current);
            }
          }, 800);
        }
        return prev;
      });
    }, 45); // ~22 frames per second for fluid rendering

    return () => clearInterval(interval);
  }, [onComplete]);

  // Real-time backend status polling
  function startPolling(id) {
    // Poll faster (every 350ms) to capture real-time subprocess stdout ticks
    pollIntervalRef.current = setInterval(async () => {
      try {
        const apiBase = import.meta.env.VITE_API_URL || (import.meta.env.MODE === 'production' ? window.location.origin : 'http://localhost:5000');
        const response = await fetch(`${apiBase}/api/scan/status/${id}`);
        if (!isMountedRef.current) {
          clearInterval(pollIntervalRef.current);
          return;
        }
        if (!response.ok) {
          throw new Error('Status poll request failed.');
        }
        
        const data = await response.json();
        if (!isMountedRef.current) {
          clearInterval(pollIntervalRef.current);
          return;
        }
        
        // Update target progress
        const nextProgress = data.progress || 0;
        targetProgressRef.current = nextProgress;

        if (data.status === 'completed' || data.progress === 100) {
          clearInterval(pollIntervalRef.current);
          latestResultsRef.current = data.results;
          targetProgressRef.current = 100;
          setStatusMessage('Scan completed successfully!');
        } else if (data.status === 'failed') {
          clearInterval(pollIntervalRef.current);
          setError(data.error || 'Scan process encountered a failure.');
        }
      } catch (err) {
        console.error('Error polling scan status:', err);
      }
    }, 350);
  }

  // Helper to get a stable hash code of a string
  const hashString = (str) => {
    let hash = 0;
    if (!str || str.length === 0) return hash;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    return Math.abs(hash);
  };

  // Fallback Simulation (if backend server is not running)
  function startSimulation() {
    const trimmed = (scanTarget || '').trim();
    if (scanType === 'github') {
      const httpsRegex = /^(https?:\/\/)?(www\.)?github\.com\/([a-zA-Z0-9-._]+)\/([a-zA-Z0-9-._]+)(\/.*)?$/;
      const sshRegex = /^git@github\.com:([a-zA-Z0-9-._]+)\/([a-zA-Z0-9-._]+)(\.git)?$/;
      if (!httpsRegex.test(trimmed) && !sshRegex.test(trimmed)) {
        setError('Invalid GitHub repository format (e.g., https://github.com/owner/repo)');
        setStatusMessage('Scan aborted.');
        return;
      }
    } else {
      let checkUrl = trimmed;
      if (!checkUrl.startsWith('http://') && !checkUrl.startsWith('https://')) {
        checkUrl = 'https://' + checkUrl;
      }
      try {
        const urlObj = new URL(checkUrl);
        if (!urlObj.hostname || !urlObj.hostname.includes('.')) {
          throw new Error();
        }
      } catch (e) {
        setError('Invalid website URL format (e.g., https://example.com)');
        setStatusMessage('Scan aborted.');
        return;
      }
    }

    let currentProgress = 0;
    simulationIntervalRef.current = setInterval(() => {
      if (!isMountedRef.current) {
        clearInterval(simulationIntervalRef.current);
        return;
      }
      currentProgress += Math.floor(Math.random() * 8) + 2; // progress 2% to 10%
      if (currentProgress >= 100) {
        currentProgress = 100;
        clearInterval(simulationIntervalRef.current);
        setStatusMessage('Scan completed successfully! (Simulated)');
        
        // Generate stable but target-specific scores
        const targetHash = hashString(scanTarget || 'default');
        const securityScore = 70 + (targetHash % 29);
        const qualityScore = 65 + ((targetHash >> 2) % 34);
        const performanceScore = 60 + ((targetHash >> 4) % 39);
        const score = Math.round((securityScore + qualityScore + performanceScore) / 3);

        const findings = [];
        if (securityScore < 85) {
          findings.push({ title: 'Insecure Connection Configuration', severity: 'medium', file: 'N/A' });
        }
        if (qualityScore < 80) {
          findings.push({ title: 'Missing Documentation and Readme', severity: 'low', file: 'README.md' });
        }
        if (securityScore < 75) {
          findings.push({ title: 'Potential Hardcoded Credentials Exposed', severity: 'critical', file: '.env' });
        }

        const summary = { critical: 0, high: 0, medium: 0, low: 0 };
        findings.forEach(f => {
          if (f.severity === 'critical') summary.critical++;
          else if (f.severity === 'high') summary.high++;
          else if (f.severity === 'medium') summary.medium++;
          else summary.low++;
        });

        latestResultsRef.current = {
          findings,
          score,
          securityScore,
          qualityScore,
          performanceScore,
          summary
        };
        targetProgressRef.current = 100;
      } else {
        targetProgressRef.current = currentProgress;
      }
    }, 350);
  }

  useEffect(() => {
    let active = true;
    isMountedRef.current = true;
    
    const startScanJob = async () => {
      let validationError = null;
      try {
        setStatusMessage('Connecting to scanner backend...');
        const apiBase = import.meta.env.VITE_API_URL || (import.meta.env.MODE === 'production' ? window.location.origin : 'http://localhost:5000');
        const response = await fetch(`${apiBase}/api/scan/start`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            targetType: scanType || 'url',
            targetValue: scanTarget || 'http://localhost',
            scanMode: mapScanMode(scanLevel),
          }),
        });

        if (!active) return;

        if (!response.ok) {
          if (response.status === 400) {
            try {
              const errData = await response.json();
              if (errData && errData.error) {
                validationError = errData.error;
              }
            } catch (e) {
              // Ignore JSON parse error
            }
          }
          throw new Error(validationError || `Server responded with status ${response.status}`);
        }

        const data = await response.json();
        if (!active) return;

        if (data.scanId) {
          setScanId(data.scanId);
          startPolling(data.scanId);
        } else {
          throw new Error('No scanId returned from backend.');
        }
      } catch (err) {
        if (!active) return;
        
        // If it's a known validation error from the backend, show it and abort
        if (validationError) {
          setError(validationError);
          setStatusMessage('Scan aborted.');
          return;
        }

        // Only fallback to simulation if the backend is actually unreachable/offline (network fetch error)
        if (err.message && (err.message.includes('Failed to fetch') || err.message.includes('fetch failed') || err.message.includes('NetworkError'))) {
          console.warn('Backend failed to start scan, starting simulated fallback scan:', err);
          startSimulation();
        } else {
          setError(err.message || 'Failed to start scan.');
          setStatusMessage('Scan aborted.');
        }
      }
    };

    startScanJob();

    return () => {
      active = false;
      isMountedRef.current = false;
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      if (simulationIntervalRef.current) clearInterval(simulationIntervalRef.current);
    };
  }, [scanType, scanTarget, scanLevel]);

  return (
    <div className="frame board-2ca68a6dfdd3">
      {/* Navbar instance for page 6 */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {/* text: !! Work In Progress !! */}
      <div className="shape text work-in-2caa500783cf">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa500783cf" data-x="2584.5" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">!! Work In Progress !!</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* text: Status Message */}
      <div className="shape text analyzing-2caa66aa075f">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa66aa075f" data-x="2573.5" data-y="990">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">
                  {error ? `Error: ${error}` : statusMessage}
                </span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* group: Group (Progress bar and numbers) */}
      <div className="group group-2cb901c7af66">
        {/* frame: Board (Progress Bar Container) */}
        <div className="frame board-2cb8855adb65">
          {/* frame: Board (Progress Bar Filler) */}
          <div 
            className="shape frame board-2cb8d7464aec" 
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* text: Progress Percentage */}
        <div className="shape text c-29-2cb88c2b9b76">
          <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb88c2b9b76" data-x="3371.5" data-y="1193">
            <div className="root rich-text root-0">
              <div className="paragraph-set root-0-paragraph-set-0">
                <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                  <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">{progress}%</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
