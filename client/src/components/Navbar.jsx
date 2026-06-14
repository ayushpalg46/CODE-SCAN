import React, { useRef, useEffect, useState } from 'react';
import Logo from './Logo';

export default function Navbar({ activeTab, setActiveTab, page = 1 }) {
  const homeRef = useRef(null);
  const historyRef = useRef(null);
  const reportRef = useRef(null);
  const solutionRef = useRef(null);
  const aboutRef = useRef(null);

  const [barStyle, setBarStyle] = useState({});

  useEffect(() => {
    const tabRefs = {
      'HOME': homeRef,
      'HISTORY': historyRef,
      'REPORT': reportRef,
      'SOLUTION': solutionRef,
      'ABOUT US': aboutRef
    };
    const activeRef = tabRefs[activeTab];
    if (activeRef && activeRef.current) {
      const el = activeRef.current;
      setBarStyle({
        left: el.offsetLeft + 'px',
        width: el.offsetWidth + 'px'
      });
    }
  }, [activeTab]);

  const isPage2 = page === 2;
  const cls = {
    container: isPage2 ? 'board-2ca68a6dfdd4' : 'board-2ca2ff61ae5e',
    logo: isPage2 ? 'codinglog-2ca68a6dfdd8' : 'codinglog-2ca49eb0566e',
    brand: isPage2 ? 'c-o-d-e-s-c-a-n-2ca68a6dfdd9' : 'c-o-d-e-s-c-a-n-2ca4c61a866e',
    group: isPage2 ? 'group-2ca68a6dfdda' : 'group-2ca60a6ac516',
    home: isPage2 ? 'h-o-m-e-2ca68a6dfddc' : 'h-o-m-e-2ca5c45cb8bf',
    history: isPage2 ? 'h-i-s-t-o-r-y-2ca68a6dfddd' : 'h-i-s-t-o-r-y-2ca5c45cb8c0',
    report: isPage2 ? 'r-e-p-o-r-t-2ca68a6dfde0' : 'r-e-p-o-r-t-2ca5c45cb8c3',
    solution: isPage2 ? 's-o-l-u-t-i-o-n-2ca68a6dfddf' : 's-o-l-u-t-i-o-n-2ca5c45cb8c2',
    about: isPage2 ? 'a-b-o-u-t-u-s-2ca68a6dfdde' : 'a-b-o-u-t-u-s-2ca5c45cb8c1',
    indicator: isPage2 ? 'board-2ca68a6dfddb' : 'board-2ca64965910a'
  };

  const dataX = {
    brand: isPage2 ? '2063' : '93',
    home: isPage2 ? '2472.5' : '502.5000000000001',
    history: isPage2 ? '2608.5' : '638.5',
    report: isPage2 ? '2797.5' : '827.4999999999999',
    solution: isPage2 ? '2968.5' : '998.4999999999999',
    about: isPage2 ? '3188.5' : '1218.5'
  };

  return (
    <div className={`frame ${cls.container}`}>
      {/* rect: coding-logo */}
      <div 
        className={`shape rect ${cls.logo}`} 
        onClick={() => setActiveTab('HOME')} 
        style={{ cursor: 'pointer' }}
      >
        <Logo />
      </div>

      {/* text: CODE-SCAN */}
      <div 
        className={`shape text ${cls.brand}`} 
        onClick={() => setActiveTab('HOME')} 
        style={{ cursor: 'pointer' }}
      >
        <div className="text-node-html" id={`html-text-node-6f50eb22-f93b-80d8-8008-${isPage2 ? '2ca68a6dfdd9' : '2ca4c61a866e'}`} data-x={dataX.brand} data-y="637">
          <div className="root rich-text root-0">
            <div className="paragraph-set root-0-paragraph-set-0">
              <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">CODE-SCAN</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* group: Group */}
      <div className={cls.group}>
        {/* text: HOME */}
        <div 
          ref={homeRef}
          className={`shape text ${cls.home} ${activeTab === 'HOME' ? 'active' : ''}`}
          onClick={() => setActiveTab('HOME')}
        >
          <div className="text-node-html" id={`html-text-node-6f50eb22-f93b-80d8-8008-${isPage2 ? '2ca68a6dfddc' : '2ca5c45cb8bf'}`} data-x={dataX.home} data-y="637">
            <div className="root rich-text root-0">
              <div className="paragraph-set root-0-paragraph-set-0">
                <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                  <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">HOME</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* text: HISTORY */}
        <div 
          ref={historyRef}
          className={`shape text ${cls.history} ${activeTab === 'HISTORY' ? 'active' : ''}`}
          onClick={() => setActiveTab('HISTORY')}
        >
          <div className="text-node-html" id={`html-text-node-6f50eb22-f93b-80d8-8008-${isPage2 ? '2ca68a6dfddd' : '2ca5c45cb8c0'}`} data-x={dataX.history} data-y="637">
            <div className="root rich-text root-0">
              <div className="paragraph-set root-0-paragraph-set-0">
                <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                  <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">HISTORY</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* text: REPORT */}
        <div 
          ref={reportRef}
          className={`shape text ${cls.report} ${activeTab === 'REPORT' ? 'active' : ''}`}
          onClick={() => setActiveTab('REPORT')}
        >
          <div className="text-node-html" id={`html-text-node-6f50eb22-f93b-80d8-8008-${isPage2 ? '2ca68a6dfde0' : '2ca5c45cb8c3'}`} data-x={dataX.report} data-y="637">
            <div className="root rich-text root-0">
              <div className="paragraph-set root-0-paragraph-set-0">
                <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                  <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">REPORT</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* text: SOLUTION */}
        <div 
          ref={solutionRef}
          className={`shape text ${cls.solution} ${activeTab === 'SOLUTION' ? 'active' : ''}`}
          onClick={() => setActiveTab('SOLUTION')}
        >
          <div className="text-node-html" id={`html-text-node-6f50eb22-f93b-80d8-8008-${isPage2 ? '2ca68a6dfddf' : '2ca5c45cb8c2'}`} data-x={dataX.solution} data-y="637">
            <div className="root rich-text root-0">
              <div className="paragraph-set root-0-paragraph-set-0">
                <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                  <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">SOLUTION</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* text: ABOUT US */}
        <div 
          ref={aboutRef}
          className={`shape text ${cls.about} ${activeTab === 'ABOUT US' ? 'active' : ''}`}
          onClick={() => setActiveTab('ABOUT US')}
        >
          <div className="text-node-html" id={`html-text-node-6f50eb22-f93b-80d8-8008-${isPage2 ? '2ca68a6dfdde' : '2ca5c45cb8c1'}`} data-x={dataX.about} data-y="637">
            <div className="root rich-text root-0">
              <div className="paragraph-set root-0-paragraph-set-0">
                <p className="paragraph root-0-paragraph-set-0-paragraph-0" dir="ltr">
                  <span className="text-node root-0-paragraph-set-0-paragraph-0-text-0">ABOUT US</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* frame: Board (red indicator line) */}
      <div 
        className={`shape frame ${cls.indicator}`} 
        style={barStyle}
      ></div>
    </div>
  );
}
