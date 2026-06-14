import React from 'react';
import Navbar from '../components/Navbar';
import ayushImg from '../assets/ayush.jpg';
import tanishImg from '../assets/tanish.jpg';

const teamMembers = [
  {
    name: 'Ayush.G.Pal',
    role: 'Backend DEV',
    occupation: '1st Year I.T Engineering Student',
    skills: 'Python, C, GO, .....',
    email: 'ayushpal.g.46@gmail.com',
    github: 'https://github.com/ayushpalg46',
    linkedin: 'https://www.linkedin.com/in/ayush-pal-46apg/',
    image: ayushImg,
  },
  {
    name: 'Tanish Sunil Kotian',
    role: 'Frontend DEV',
    occupation: '1st Year C.E Engineering Student',
    skills: 'Html-CSS-JavaScript, React.js, .....',
    email: 'tanishkotian3101@gmail.com',
    github: 'https://github.com/Tanish210',
    linkedin: 'https://www.linkedin.com/in/tanish-kotian-0337a1394/',
    image: tanishImg,
  },
];

export default function AboutUsPage({ activeTab, setActiveTab }) {
  return (
    <div className="frame board-2ca2c79e627d about-us-page">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={1} />

      <div className="about-us-content">
        <div className="about-us-cards-container">
          {teamMembers.map((member, idx) => (
            <div key={idx} className="about-us-card">
              {/* Profile Image Box */}
              <div className="about-us-avatar-box">
                {member.image ? (
                  <img src={member.image} alt={member.name} className="about-us-avatar-img" />
                ) : (
                  <svg viewBox="0 0 24 24" width="60" height="60" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.4 }}>
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>
                )}
              </div>

              {/* Info */}
              <div className="about-us-info">
                <div className="about-us-info-row">
                  <span className="about-us-label">Name:-</span>
                  <span className="about-us-value">{member.name}</span>
                </div>
                <div className="about-us-info-row">
                  <span className="about-us-label">Role:-</span>
                  <span className="about-us-value">{member.role}</span>
                </div>
                <div className="about-us-info-row">
                  <span className="about-us-label">Occupation:-</span>
                  <span className="about-us-value">{member.occupation}</span>
                </div>
                <div className="about-us-info-row">
                  <span className="about-us-label">Skill:-</span>
                  <span className="about-us-value">{member.skills}</span>
                </div>
              </div>

              {/* Social Buttons */}
              <div className="about-us-socials">
                <a
                  href={member.linkedin}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="about-us-social-btn about-us-linkedin"
                >
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                    <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"/>
                    <rect x="2" y="9" width="4" height="12"/>
                    <circle cx="4" cy="4" r="2"/>
                  </svg>
                  LinkedIn
                </a>
                <a
                  href={`mailto:${member.email}`}
                  className="about-us-social-btn about-us-email"
                >
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="2" y="4" width="20" height="16" rx="2"/>
                    <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                  </svg>
                  E-Mail
                </a>
                <a
                  href={member.github}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="about-us-social-btn about-us-github"
                >
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                    <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
                  </svg>
                  GitHub
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
