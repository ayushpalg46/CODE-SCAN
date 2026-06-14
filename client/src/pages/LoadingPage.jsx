import React, { useState, useEffect, useRef } from 'react';
import Navbar from '../components/Navbar';

export default function LoadingPage({ activeTab, setActiveTab, scanType, scanTarget, scanLevel, onComplete }) {
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('Initializing Scan...');
  const [scanId, setScanId] = useState(null);
  const [error, setError] = useState(null);
  
  const pollIntervalRef = useRef(null);
  const simulationIntervalRef = useRef(null);
  const isMountedRef = useRef(true);

  // Helper to map scanLevel 'moderate' -> 'medium', 'advance' -> 'advanced'
  const mapScanMode = (level) => {
    if (level === 'moderate') return 'medium';
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

  // Real-time backend status polling
  function startPolling(id) {
    pollIntervalRef.current = setInterval(async () => {
      try {
        const response = await fetch(`http://localhost:5000/api/scan/status/${id}`);
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
        
        // Update progress
        setProgress(data.progress || 0);
        
        // Map messages based on progress percentage
        updateStatusText(data.progress || 0);

        if (data.status === 'completed' || data.progress === 100) {
          clearInterval(pollIntervalRef.current);
          setStatusMessage('Scan completed successfully!');
          setTimeout(() => {
            if (isMountedRef.current && onComplete) onComplete(data.results);
          }, 1000);
        } else if (data.status === 'failed') {
          clearInterval(pollIntervalRef.current);
          setError(data.error || 'Scan process encountered a failure.');
        }
      } catch (err) {
        console.error('Error polling scan status:', err);
      }
    }, 800);
  }

  // Fallback Simulation (if backend server is not running)
  function startSimulation() {
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
        setProgress(100);
        setTimeout(() => {
          if (isMountedRef.current && onComplete) {
            // Mock scan results matching structure
            onComplete({
              findings: [
                { title: 'Insecure Dependency', severity: 'medium', file: 'package.json' },
                { title: 'Hardcoded API Key', severity: 'critical', file: 'config.js' }
              ],
              score: 75,
              summary: { critical: 1, high: 0, medium: 1, low: 0 }
            });
          }
        }, 1000);
      } else {
        setProgress(currentProgress);
        updateStatusText(currentProgress);
      }
    }, 400);
  }

  useEffect(() => {
    isMountedRef.current = true;
    
    // 1. Trigger scan request on mount
    const startScanJob = async () => {
      try {
        setStatusMessage('Connecting to scanner backend...');
        const response = await fetch('http://localhost:5000/api/scan/start', {
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

        if (!isMountedRef.current) return;

        if (!response.ok) {
          throw new Error(`Server responded with status ${response.status}`);
        }

        const data = await response.json();
        if (!isMountedRef.current) return;

        if (data.scanId) {
          setScanId(data.scanId);
          startPolling(data.scanId);
        } else {
          throw new Error('No scanId returned from backend.');
        }
      } catch (err) {
        if (!isMountedRef.current) return;
        console.warn('Backend failed to start scan, starting simulated fallback scan:', err);
        startSimulation();
      }
    };

    startScanJob();

    return () => {
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
