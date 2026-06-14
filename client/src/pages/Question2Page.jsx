import React from 'react';
import Navbar from '../components/Navbar';

export default function Question2Page({ activeTab, setActiveTab, onSelect }) {
  return (
    <div className="frame board-2ca68a6dfdd3">
      {/* Navbar instance for page 2 */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {/* text: Q.2 */}
      <div className="shape text q1-2caa500783cf">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa500783cf" data-x="2024" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Q.2</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* text: What Type Of Link It’s ? */}
      <div className="shape text what-type-2caa66aa075f">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa66aa075f" data-x="2509" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">What Type Of Link It’s ?</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Choices Container (Renders elements side by side responsively) */}
      <div className="q1-choices-layout">
        {/* frame: Board (Website URL Box) */}
        <div className="frame board-2caad517e2de" onClick={() => onSelect && onSelect('url')}>
          {/* rect: chain-link-icon-isolated-free-vector */}
          <div className="shape rect chainlink-2cac05b3e7e5">
            <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
          </div>
          
          {/* text: Website URL */}
          <div className="shape text website-2cab8b8a2d37">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cab8b8a2d37" data-x="2305" data-y="1182">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="auto">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Website</span>
                  </p>
                  <p className="paragraph root-0-paragraph-set-0-paragraph-1" dir="auto">
                    <span className="text-node root-0-paragraph-set-0-paragraph-1-text-0">URL</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* frame: Board (GitHub Repo Box) */}
        <div className="frame board-2cab11ca9821" onClick={() => onSelect && onSelect('github')}>
          {/* rect: brand-github */}
          <div className="shape rect brandgith-2cacf08b2019">
            <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
            </svg>
          </div>
          
          {/* text: GitHub Repo Link */}
          <div className="shape text website-2cac50b8e025">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cac50b8e025" data-x="3194" data-y="1182">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="auto">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">GitHub Repo</span>
                  </p>
                  <p className="paragraph root-0-paragraph-set-0-paragraph-1" dir="auto">
                    <span className="text-node root-0-paragraph-set-0-paragraph-1-text-0"> Link</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
          
          {/* text: (Recommend) */}
          <div className="shape text website-2cac4dbbac67">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cac4dbbac67" data-x="3151" data-y="1343">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p class="paragraph root-0-paragraph-set-0-paragraph-0" dir="auto">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">(Recommend)</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
