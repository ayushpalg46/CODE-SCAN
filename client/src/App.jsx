import React, { useState, useEffect } from 'react';
import HomePage from './pages/HomePage';
import Question1Page from './pages/Question1Page';
import Question2Page from './pages/Question2Page';
import Question3Page from './pages/Question3Page';
import Question4Page from './pages/Question4Page';
import Question5Page from './pages/Question5Page';
import LoadingPage from './pages/LoadingPage';
import ResultsPage from './pages/ResultsPage';
import FeedbackPage from './pages/FeedbackPage';
import Navbar from './components/Navbar';

function App() {
  const [activeTab, setActiveTab] = useState('HOME');
  const [scanStarted, setScanStarted] = useState(false);
  const [step, setStep] = useState(1);

  useEffect(() => {
    console.log('App State Log - activeTab:', activeTab, 'scanStarted:', scanStarted, 'step:', step);
  }, [activeTab, scanStarted, step]);
  const [projectName, setProjectName] = useState('');
  const [scanType, setScanType] = useState(null);
  const [scanTarget, setScanTarget] = useState('');
  const [techStack, setTechStack] = useState('');
  const [scanLevel, setScanLevel] = useState('');
  const [scanResults, setScanResults] = useState(null);

  const handleLetsGo = () => {
    setScanStarted(true);
    setStep(1);
  };

  const handleSubmitProjectName = (name) => {
    console.log('Submitted Project Name:', name);
    setProjectName(name);
    setStep(2);
  };

  const handleSelectOption = (option) => {
    console.log('Selected scanner option:', option);
    setScanType(option);
    setStep(3);
  };

  const handleSubmitUrl = (url) => {
    console.log('Submitted URL:', url);
    setScanTarget(url);
    setStep(4);
  };

  const handleSubmitTechStack = (tech) => {
    console.log('Submitted Tech Stack:', tech);
    setTechStack(tech);
    setStep(5);
  };

  const handleSelectLevel = (level) => {
    console.log('Selected Scan Level:', level);
    setScanLevel(level);
    setStep(6);
  };

  const handleScanComplete = (results) => {
    console.log('Scan completed with results:', results);
    setScanResults(results);
    setStep(7);
  };

  const handleTabChange = (tab) => {
    if (tab === 'HOME') {
      // Clicking HOME/logo resets the process back to the landing page
      setScanStarted(false);
      setStep(1);
    }
    setActiveTab(tab);
  };

  if (activeTab === 'HOME') {
    if (scanStarted) {
      if (step === 1) {
        return (
          <Question1Page 
            activeTab={activeTab} 
            setActiveTab={handleTabChange} 
            onSubmit={handleSubmitProjectName}
          />
        );
      } else if (step === 2) {
        return (
          <Question2Page 
            activeTab={activeTab} 
            setActiveTab={handleTabChange} 
            onSelect={handleSelectOption}
          />
        );
      } else if (step === 3) {
        return (
          <Question3Page 
            activeTab={activeTab} 
            setActiveTab={handleTabChange} 
            onSubmit={handleSubmitUrl}
          />
        );
      } else if (step === 4) {
        return (
          <Question4Page 
            activeTab={activeTab} 
            setActiveTab={handleTabChange} 
            onSubmit={handleSubmitTechStack}
          />
        );
      } else if (step === 5) {
        return (
          <Question5Page 
            activeTab={activeTab} 
            setActiveTab={handleTabChange} 
            onSelect={handleSelectLevel}
          />
        );
      } else if (step === 6) {
        return (
          <LoadingPage 
            activeTab={activeTab} 
            setActiveTab={handleTabChange} 
            scanType={scanType}
            scanTarget={scanTarget}
            scanLevel={scanLevel}
            onComplete={handleScanComplete}
          />
        );
      } else if (step === 7) {
        return (
          <ResultsPage
            activeTab={activeTab}
            setActiveTab={handleTabChange}
            projectName={projectName}
            scanType={scanType}
            scanTarget={scanTarget}
            scanLevel={scanLevel}
            techStack={techStack}
            scanResults={scanResults}
            onNext={() => {
              setTimeout(() => {
                setStep(8);
              }, 300);
            }}
          />
        );
      } else {
        return (
          <FeedbackPage
            activeTab={activeTab}
            setActiveTab={handleTabChange}
            onSubmit={(feedback) => {
              console.log('Feedback submitted:', feedback);
              // Reset scan wizard back to landing page
              setScanStarted(false);
              setStep(1);
            }}
          />
        );
      }
    } else {
      return (
        <HomePage 
          activeTab={activeTab} 
          setActiveTab={handleTabChange} 
          onLetsGo={handleLetsGo} 
        />
      );
    }
  } else {
    // Other tabs placeholders (e.g. HISTORY, REPORT, ABOUT US, SOLUTION)
    return (
      <div className="frame board-2ca2c79e627d">
        <Navbar activeTab={activeTab} setActiveTab={handleTabChange} page={1} />
        <div className="page-placeholder" style={{ gridRow: '2', gridColumn: '1 / span 3' }}>
          <h2 className="placeholder-title" style={{ fontFamily: "'Gugi', sans-serif", fontSize: '3rem', marginBottom: '20px', textAlign: 'center' }}>{activeTab}</h2>
          <p className="placeholder-text" style={{ fontSize: '1.2rem', opacity: 0.7, textAlign: 'center' }}>Content will be added based on upcoming screenshots.</p>
        </div>
      </div>
    );
  }
}

export default App;
