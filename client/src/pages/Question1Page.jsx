import React, { useState } from 'react';
import Navbar from '../components/Navbar';

export default function Question1Page({ activeTab, setActiveTab, onSubmit }) {
  const [projectName, setProjectName] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (projectName.trim() && onSubmit) {
      onSubmit(projectName.trim());
    }
  };

  return (
    <div className="frame board-2ca68a6dfdd3">
      {/* Navbar instance for page 1 */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {/* text: Q.1 */}
      <div className="shape text q2-2caa500783cf">
        <div className="text-node-html" data-x="2024" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Q.1</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* text: Enter Project Name */}
      <div className="shape text enter-the-2caa66aa075f">
        <div className="text-node-html" data-x="2563" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Enter Project Name</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Form container for Project Name input and submission */}
      <form onSubmit={handleSubmit} className="q2-form-container">
        {/* frame: Board (Input Box Box) */}
        <div className="frame board-2cb1a85f7508">
          <input
            type="text"
            className="shape text https-xy-2cb2336ee137 q2-text-input"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            placeholder="Enter your project name..."
            autoFocus
            required
            style={{ width: '100%' }}
          />
        </div>

        {/* frame: Board (Submit Button Box) */}
        <button type="submit" className="frame board-2cb1e91ee621">
          {/* text: SUBMIT */}
          <div className="shape text s-u-b-m-i-t-2cb1e91ee622">
            <div className="text-node-html" data-x="2786" data-y="1061">
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
