import React from 'react';
import Navbar from '../components/Navbar';

export default function Question5Page({ activeTab, setActiveTab, onSelect }) {
  return (
    <div className="frame board-2ca68a6dfdd3">
      {/* Navbar instance for page 5 (reuses same styles as page 2/3/4 navbar) */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {/* text: Q.5 */}
      <div className="shape text q4-2caa500783cf">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa500783cf" data-x="2024" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Q.5</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* text: Level Of Security-SCAN ? */}
      <div className="shape text level-of-s-2caa66aa075f">
        <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2caa66aa075f" data-x="2476.5" data-y="746">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">Level Of Security-SCAN ?</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Choices Container (Renders 3 cards side by side) */}
      <div className="q4-choices-layout">
        {/* frame: Board (BASIC Scan Box) */}
        <div className="frame board-2cb5c121b7ae" onClick={() => onSelect && onSelect('basic')}>
          {/* text: BASIC */}
          <div className="shape text b-a-s-i-c-2cb6269dbe48">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb6269dbe48" data-x="2181" data-y="1187">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">BASIC</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
          {/* text: (Low-Medium) */}
          <div className="shape text low-mediu-2cb63dc57c77">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb63dc57c77" data-x="2031" data-y="1326">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">(Low-Medium)</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* frame: Board (MODERATE Scan Box) */}
        <div className="frame board-2cb5c61a2384" onClick={() => onSelect && onSelect('moderate')}>
          {/* text: MODERATE */}
          <div className="shape text m-o-d-e-r-a-t-e-2cb63d3389d0">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb63d3389d0" data-x="2725" data-y="1187">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">MODERATE</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
          {/* text: (Medium-High) */}
          <div className="shape text medium-hi-2cb63ea2336f">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb63ea2336f" data-x="2667" data-y="1329">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">(Medium-High)</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* frame: Board (ADVANCE Scan Box) */}
        <div className="frame board-2cb5c6783e74" onClick={() => onSelect && onSelect('advance')}>
          {/* text: ADVANCE */}
          <div className="shape text a-d-v-a-n-c-e-2cb63ef1488c">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb63ef1488c" data-x="3384.5" data-y="1187">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">ADVANCE</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
          {/* text: (High-Critical) */}
          <div className="shape text high-crit-2cb63e505c94">
            <div className="text-node-html" id="html-text-node-6f50eb22-f93b-80d8-8008-2cb63e505c94" data-x="3330" data-y="1328">
              <div className="root rich-text root-0">
                <div className="paragraph-set root-0-paragraph-set-0">
                  <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                    <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">(High-Critical)</span>
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
