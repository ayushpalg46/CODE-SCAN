import React from 'react';
import Navbar from '../components/Navbar';

export default function HomePage({ activeTab, setActiveTab, onLetsGo }) {
  return (
    <div className="frame board-2ca2c79e627d">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={1} />

      {/* frame: Board (Let's GO button container) */}
      <div className="frame board-2ca37265594f" onClick={onLetsGo}>
        {/* text: Let's GO */}
        <div className="shape text lets-g-o-2ca352c074f4">
          <div className="text-node-html" id="html-text-node-5df3c6c9-739a-8010-8008-2ca352c074f4" data-x="812.5" data-y="1061">
            <div className="root rich-text root-0">
              <div className="paragraph-set root-0-paragraph-set-0">
                <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                  <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Let's GO</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* text: Check. Detect. Protect. */}
      <div className="shape text check-de-2ca3d1f97631">
        <div className="text-node-html" id="html-text-node-5df3c6c9-739a-8010-8008-2ca3d1f97631" data-x="221" data-y="974.5">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Check.</span>
              </p>
              <p className="paragraph root-0-paragraph-set-0-paragraph-1" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-1-text-0">Detect.</span>
              </p>
              <p className="paragraph root-0-paragraph-set-0-paragraph-2" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-2-text-0">Protect.</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* text: Find. Fix. Fortify. */}
      <div className="shape text find-fix-2ca456242cdf">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2ca456242cdf" data-x="1389" data-y="974.5">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Find.</span>
              </p>
              <p className="paragraph root-0-paragraph-set-0-paragraph-1" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-1-text-0">Fix.</span>
              </p>
              <p className="paragraph root-0-paragraph-set-0-paragraph-2" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-2-text-0">Fortify.</span>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
