import React, { useState, useEffect } from 'react';
import Navbar from '../components/Navbar';

export default function Question3Page({ activeTab, setActiveTab, scanType, onSubmit }) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [touched, setTouched] = useState(false);

  // Validate the URL/Link whenever it or the scanType changes
  useEffect(() => {
    if (!touched) {
      setError('');
      return;
    }

    const trimmed = url.trim();
    if (!trimmed) {
      setError('Input cannot be empty');
      return;
    }

    if (scanType === 'github') {
      // GitHub repository URL regex
      // Matches https://github.com/owner/repo or github.com/owner/repo (allowing branches and paths)
      const httpsRegex = /^(https?:\/\/)?(www\.)?github\.com\/([a-zA-Z0-9-._]+)\/([a-zA-Z0-9-._]+)(\/.*)?$/;
      const sshRegex = /^git@github\.com:([a-zA-Z0-9-._]+)\/([a-zA-Z0-9-._]+)(\.git)?$/;

      if (httpsRegex.test(trimmed)) {
        const match = trimmed.match(httpsRegex);
        const owner = match[3];
        const repo = match[4];
        if (!owner || !repo) {
          setError('Invalid GitHub repository format (missing owner or repository)');
          return;
        }

        const reserved = ['features', 'pulls', 'issues', 'marketplace', 'explore', 'trending', 'pricing', 'login', 'join', 'contact', 'about', 'blog', 'notifications', 'settings', 'security', 'search', 'orgs'];
        if (reserved.includes(owner.toLowerCase())) {
          setError('Invalid repository link (detected GitHub system path)');
          return;
        }

        setError('');
      } else if (sshRegex.test(trimmed)) {
        setError('');
      } else {
        setError('Please enter a valid GitHub repository link (e.g., https://github.com/owner/repo)');
      }
    } else {
      // Website URL validation
      if (!/^https?:\/\//i.test(trimmed)) {
        setError('URL must start with http:// or https://');
        return;
      }
      try {
        const urlObj = new URL(trimmed);
        const hostname = urlObj.hostname;
        if (!hostname) {
          setError('Invalid URL hostname');
          return;
        }
        if (hostname === 'localhost') {
          setError('');
          return;
        }
        if (!hostname.includes('.')) {
          setError('Hostname must contain a domain extension (e.g., .com)');
          return;
        }

        const parts = hostname.split('.');
        if (parts.some(part => part.length === 0)) {
          setError('Hostname contains invalid dot placement');
          return;
        }

        if (parts[0] === 'www' && parts.length < 3) {
          setError('URL is incomplete (e.g., use www.example.com)');
          return;
        }

        const tld = parts[parts.length - 1];
        if (tld.length < 2) {
          setError('Domain extension must be at least 2 characters (e.g., .com)');
          return;
        }

        const validHostRegex = /^[a-zA-Z0-9.-]+$/;
        if (!validHostRegex.test(hostname)) {
          setError('Hostname contains invalid characters');
          return;
        }

        setError('');
      } catch (e) {
        setError('Please enter a valid website URL (e.g., https://example.com)');
      }
    }
  }, [url, scanType, touched]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim() && !error && onSubmit) {
      onSubmit(url.trim());
    }
  };

  const handleInputChange = (e) => {
    setUrl(e.target.value);
    setTouched(true);
  };

  const containerClass = `frame board-2cb1a85f7508 ${
    touched ? (error ? 'invalid-touched' : (url.trim() ? 'valid-touched' : '')) : ''
  }`;

  return (
    <div className="frame board-2ca68a6dfdd3">
      {/* Navbar instance for page 3 (reuses same styles as page 2 navbar) */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {/* text: Q.3 */}
      <div className="shape text q2-2caa500783cf">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa500783cf" data-x="2024" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Q.3</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* text: Enter The URL/Link !! */}
      <div className="shape text enter-the-2caa66aa075f">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa66aa075f" data-x="2563" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Enter The URL/Link !!</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Form container for URL input and submission */}
      <form onSubmit={handleSubmit} className="q2-form-container">
        {/* frame: Board (Input Box Box) */}
        <div className={containerClass}>
          <input
            type="text"
            className="shape text https-xy-2cb2336ee137 q2-text-input"
            value={url}
            onChange={handleInputChange}
            placeholder={scanType === 'github' ? "https://github.com/owner/repo" : "https://example.com"}
            autoFocus
            required
          />
        </div>

        {touched && error && (
          <div className="validation-message error">
            {error}
          </div>
        )}

        {touched && !error && url.trim() && (
          <div className="validation-message success">
            ✓ Valid {scanType === 'github' ? 'GitHub repository' : 'website URL'} format
          </div>
        )}

        {/* frame: Board (Submit Button Box) */}
        <button 
          type="submit" 
          className="frame board-2cb1e91ee621" 
          disabled={!!error || !url.trim()}
        >
          {/* text: SUBMIT */}
          <div className="shape text s-u-b-m-i-t-2cb1e91ee622">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb1e91ee622" data-x="2786" data-y="1061">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">SUBMIT</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </button>
      </form>
    </div>
  );
}
