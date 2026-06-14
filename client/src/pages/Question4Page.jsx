import React, { useState } from 'react';
import Navbar from '../components/Navbar';

export default function Question4Page({ activeTab, setActiveTab, onSubmit }) {
  const [techStack, setTechStack] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (techStack.trim() && onSubmit) {
      onSubmit(techStack.trim());
    }
  };

  return (
    <div className="frame board-2ca68a6dfdd3">
      {/* Navbar instance for page 4 (reuses same styles as page 2/3 navbar) */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {/* text: Q.4 */}
      <div className="shape text q3-2caa500783cf">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa500783cf" data-x="2024" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Q.4</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* text: Which Tech Stack Is Used ? */}
      <div className="shape text which-tech-2caa66aa075f">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa66aa075f" data-x="2451.5" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Which Tech Stack Is Used ?</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Form container for tech stack input and submission */}
      <form onSubmit={handleSubmit} className="q2-form-container">
        {/* frame: Board (Input Box Box) */}
        <div className="frame board-2cb1a85f7508">
          <input
            type="text"
            className="shape text m-e-r-n-stack-2cb2336ee137 q2-text-input"
            value={techStack}
            onChange={(e) => setTechStack(e.target.value)}
            placeholder="MERN Stack,Python,Java,ETC..."
            autoFocus
            required
          />
        </div>

        {/* frame: Board (Submit Button Box) */}
        <button type="submit" className="frame board-2cb1e91ee621">
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
