import React, { useState } from 'react';
import Navbar from '../components/Navbar';

export default function FeedbackPage({ activeTab, setActiveTab, onSubmit }) {
  const [rating, setRating] = useState('xx');
  const [comment, setComment] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const isMountedRef = React.useRef(true);

  React.useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const handleRatingSelect = (score) => {
    setRating(score);
  };

  const handleSubmit = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (rating === 'xx') {
      alert('Please select a rating score first! (^_~)');
      return;
    }
    
    setSubmitted(true);
    setTimeout(() => {
      if (isMountedRef.current && onSubmit) {
        onSubmit({ rating, comment });
      }
    }, 2000);
  };

  return (
    <div className="frame board-2ca6cc08b1c0">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} page={2} />

      {submitted ? (
        <div className="feedback-success-container">
          <div className="success-emoji">(^_^)</div>
          <h2 className="success-title">THANK YOU!</h2>
          <p className="success-message">Your feedback has been submitted successfully.</p>
        </div>
      ) : (
        <div className="feedback-form-container">
          
          {/* Rate Section */}
          <div className="feedback-rate-section">
            <div className="shape text rate-our-s-2cc6fbba2f2b">
              Rate Our Services:
            </div>
            
            <div className="rating-score-display-group">
              {/* Rating box frame */}
              <div className="frame board-2cc71cb187fd">
                <div className="shape text xx-2cc75a88f6e9">
                  {rating}
                </div>
              </div>
              <div className="shape text c-10-2cc74a27d1d8">
                /10
              </div>
            </div>

            {/* Interactive Rating Selector */}
            <div className="rating-selector-bar">
              {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((num) => (
                <button
                  key={num}
                  type="button"
                  className={`rating-number-btn ${rating === num ? 'active' : ''}`}
                  onClick={() => handleRatingSelect(num)}
                >
                  {num}
                </button>
              ))}
            </div>
          </div>

          {/* Feedback Message Section */}
          <div className="feedback-message-section">
            <div className="shape text feed-back-m-2cc6bf0a110e">
              FeedBack Message:
            </div>

            {/* Textarea container frame */}
            <div className="frame board-2cc66c6a04c3">
              <textarea
                className="improvemen-2cc76a20e1af"
                placeholder="Improvement Suggestion"
                value={comment}
                onChange={(e) => setComment(e.target.value)}
              />
            </div>
          </div>

          {/* Submit Button frame */}
          <div 
            key="feedback-submit-btn"
            className="frame board-2cbed8327d44 submit-feedback-btn"
            onClick={handleSubmit}
            style={{ cursor: 'pointer', userSelect: 'none' }}
          >
            <div className="shape text s-u-b-m-i-t-2cbeee8dea86">
              SUBMIT(^_^)
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
