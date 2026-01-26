# Malicious URL Detector - Project Summary

## Project Overview
A machine learning-powered web application that detects malicious URLs using logistic regression. The system analyzes 39 URL features to classify URLs as benign or malicious with a tiered risk assessment system.

## Implementation

### 1. **Machine Learning Model**
- **Algorithm**: Logistic Regression with L2 regularization (C=0.01)
- **Training Data**: 126,664+ URLs (balanced 50/50 malicious/benign)
  - Malicious: PhishTank (63,279) + URLhaus (52)
  - Benign: Tranco top sites, whitelisted domains, platform hosts, 3,000+ long-path URLs from 18 documentation sources
- **Performance**: 99.40% accuracy on test set
- **Features**: 39 numerical features extracted from URL components

### 2. **Web Application**
- **Framework**: FastAPI with Jinja2 templating
- **Deployment**: Dockerized and deployed on Render (live web app)
- **UI Design**: Retro pixel aesthetic with Press Start 2P font
- **Features**:
  - Real-time URL risk assessment
  - Dynamic risk meter (0-100 scale)
  - Three-tier verdict system (LOW RISK, SUSPICIOUS, HIGH RISK)
  - Lottie animations for visual feedback
  - Responsive design with rounded inputs, gradient backgrounds, and overflow protection

### 3. **Feature Engineering** (39 Features)
**Basic Metrics:**
- `is_https`: HTTPS vs HTTP protocol
- `url_len`, `hostname_len`, `path_len`: Log-transformed lengths
- `query_len`: Query string length
- `is_ip`: IP address detection

**Character Analysis:**
- Special character counts: `-`, `@`, `?`, `%`, `.`, `=`, `_`, `&`
- `digit_ratio`: Proportion of digits in URL
- `alnum_ratio`: Proportion of alphanumeric characters

**Token Statistics:**
- `token_count`: Number of tokens in URL
- `avg_token_len`: Average token length
- `max_token_len`: Maximum token length
- `long_token_count`: Count of tokens ≥ 20 characters

**Query Parameters:**
- `query_param_count`: Number of query parameters
- `has_percent_encoding`: Presence of URL encoding

**Domain Analysis:**
- `subdomain_depth`: Number of subdomain levels
- `tld_is_common`: Check for common TLDs (com, org, net, edu, gov, io, sg, my, uk, us, au, ca, de, fr, jp, cn, in)

**Keyword Detection (14 keywords):**
verify, verification, secure, auth, authentication, token, password, support, update, billing, login, signin, bank, account, confirm, click

### 4. **Tiered Protection System**
**Tier 1 - Trusted Whitelist:**
- Hard-coded safe domains (google.com, github.com, microsoft.com, etc.)
- Returns fixed 1% risk score

**Tier 2 - Platform Hosts:**
- Domains like github.io, netlify.app, vercel.app
- Risk score reduced by cubing probability (p_mal³)

**Tier 3 - ML Classification:**
- All other URLs analyzed through logistic regression model
- Probability capped at 5-95% to prevent extreme predictions

## 🔍 Feature Importance (Top 10)
1. **path_len** (4.16) - Path length is the strongest predictor
2. **subdomain_depth** (2.91) - Deep subdomains often indicate phishing
3. **is_https** (1.49) - HTTP vs HTTPS protocol
4. **count_.** (0.97) - Number of dots in URL
5. **hostname_len** (0.63) - Length of hostname
6. **url_len** (0.61) - Total URL length
7. **token_count** (0.53) - Number of tokens
8. **avg_token_len** (0.26) - Average token length
9. **is_ip** (0.25) - IP address detection
10. **query_len** (0.20) - Query string length

## 🛠️ Technologies Used
- **Backend**: Python 3.14, FastAPI, scikit-learn, pandas, joblib
- **Frontend**: HTML5, CSS3, JavaScript, Jinja2
- **UI**: Google Fonts (Press Start 2P), dotlottie-wc web components
- **Data Sources**: PhishTank, URLhaus, Tranco, custom scraped documentation URLs
- **Version Control**: Git

## My Key Learnings 

### 1. **Training Data Bias**
**Problem**: Initial model flagged legitimate long-path URLs (e.g., `github.io/project/login.html`) as 100% malicious.

**Root Cause**: Training data contained mostly short-path benign URLs from Tranco (homepage URLs) but long-path malicious URLs from phishing datasets.

**Solution**: Created web scraper to collect 1,657 legitimate long-path URLs from:
- Python documentation
- MDN Web Docs
- GitHub Docs
- Node.js API docs
- Kubernetes documentation

**Result**: Model learned that long paths alone don't indicate malicious intent.

### 2. **Model Regularization**
**Problem**: Initial model showed overconfidence (probabilities at 0.0 or 1.0).

**Solution**: Added L2 regularization with C=0.01 to penalize large coefficients.

**Impact**: Reduced extreme predictions while maintaining 99.40% accuracy.

### 3. **TLD Expansion**
**Problem**: International domains (.sg, .uk, .au) flagged as suspicious.

**Solution**: Expanded `tld_is_common` check from 6 TLDs to 17 TLDs including major country codes.

**Impact**: Reduced false positives for legitimate international websites.

### 4. **Platform Host Handling**
**Problem**: User-generated content platforms (github.io, netlify.app) used by both legitimate users and phishers.

**Solution**: Created "Tier 2" classification with reduced risk (p_mal³ instead of p_mal).

**Impact**: Balanced protection without completely trusting user-generated content.

### 5. **Feature Selection**
**Discovery**: Path length (4.16) has 43% more importance than the second-highest feature (subdomain_depth at 2.91).

**Implication**: URL structure matters more than keyword matching for phishing detection.

**Insight**: Keyword features like "login", "verify", "secure" had lower importance (< 0.2) than expected.

## Front-end: UI/UX Design Decisions

### Visual Design
- **Color Coding**:
  - Green (#4ade80): Low risk (0-39%)
  - Orange (#fb923c): Suspicious (40-79%)
  - Red (#f87171): High risk (80-100%)

### User Experience
- **Instant Feedback**: Real-time risk assessment on form submission
- **Clear Communication**: Verdict messages explain risk level
- **Visual Hierarchy**: Large risk meter with percentage display
- **Accessibility**: High contrast colors, readable font sizes

## Deployment Workflow

### Data Pipeline
1. **scripts/build_dataset.py**: Downloads and combines datasets
2. **malicious-url-detector/src/model.py**: Trains and evaluates model
3. **malicious-url-detector/src/predict.py**: Loads model for inference

### Web Application
1. **webapp/app.py**: FastAPI server on localhost:8000
2. **webapp/templates/index.html**: User interface
3. **webapp/static/**: Static assets (Lottie animations)

### Model Retraining Process
```bash
# 1. Rebuild dataset with latest sources
python scripts/build_dataset.py

# 2. Retrain model
python malicious-url-detector/src/model.py

# 3. Start web server
uvicorn webapp.app:app --reload
```

### Deployment Workflow
```bash
# 1. Update code and test locally
uvicorn webapp.app:app --reload

# 2. Commit changes
git add .
git commit -m "feat: description of changes"

# 3. Push to GitHub (triggers auto-deploy on Render)
git push

# Render automatically:
# - Detects Dockerfile
# - Builds Docker image with Python 3.11-slim
# - Installs dependencies from requirements.txt
# - Runs uvicorn on 0.0.0.0:8000
# - Makes app live at https://[app-name].onrender.com
```

## Performance Metrics

### Test Set Results (25,333 URLs)
- **Accuracy**: 99.40%
- **Precision** (Benign): 98.91%
- **Precision** (Malicious): 99.91%
- **Recall** (Benign): 99.91%
- **Recall** (Malicious): 98.89%
- **F1-Score**: 99.40% (macro average)

### Confusion Matrix
```
                Predicted
                Benign  Malicious
Actual Benign   12,656  11
       Malicious  140   12,526
```

**False Positives**: 11 (0.09%)
**False Negatives**: 140 (1.11%)

## Technical Challenges & Solutions

### Challenge 1: Template Path Resolution
**Issue**: `TemplateNotFound` error when running FastAPI app.

**Solution**: Changed from relative paths to absolute paths using `Path(__file__).parent`.

**Code**:
```python
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
```

### Challenge 2: Lottie Animation CORS
**Issue**: lottie.host blocked embedding due to hotlinking protection.

**Solution**: Downloaded animation file locally and served via StaticFiles mount.

### Challenge 3: Feature Mismatch After Adding New Features
**Issue**: Model expected 37 features but received 39 after adding digit_ratio and alnum_ratio.

**Solution**: Retrained model with updated feature set, ensuring column alignment.

### Challenge 4: Long-Path False Positives
**Issue**: Legitimate documentation URLs scored 95-100% malicious due to training data bias.

**Solution**: Built web scraper (scripts/scrape_benign_urls.py) to collect 3,000+ long-path benign URLs from 18 trusted sources (Stack Overflow, Wikipedia, Microsoft Learn, AWS, Medium, etc.).

**Impact**: Reduced path_len importance from 4.38 to 4.16, significantly improved real-world accuracy.

### Challenge 5: UI Content Overflow
**Issue**: Long URLs broke out of the result card container, creating layout issues.

**Solution**: Added CSS word-wrapping (`word-wrap: break-word`, `overflow-wrap: break-word`), padding, and `box-sizing: border-box` to result-card class.

### Challenge 6: Production Deployment
**Issue**: Needed to deploy app for public access without local Docker setup.

**Solution**: Created Dockerfile with Python 3.11-slim, updated requirements.txt with web dependencies (FastAPI, uvicorn, jinja2), deployed to Render with auto-deploy on git push.

## Key Insights

1. **Data Quality > Algorithm Complexity**: A simple logistic regression with balanced, diverse training data is better than complex models with biased data.

2. **Feature Engineering Matters**: Log-transforming length features and creating ratio-based features (digit_ratio, alnum_ratio) improved model interpretability.

3. **Domain Knowledge is Critical**: Understanding that platforms like github.io host both legitimate and malicious content led to the tiered system design.

4. **Testing with Real Examples**: Testing with actual URLs (not just test sets) revealed training data bias that metrics alone couldn't detect.

5. **UI/UX Enhances Trust**: Clear visual feedback (risk meter, color coding, verdicts) makes ML predictions actionable for users.

6. **Deployment Enables Sharing**: Containerizing with Docker and deploying to Render makes the project accessible to anyone with a web browser.

## New Skills LEarnt 

### Machine Learning
- Feature engineering for URL analysis
- Binary classification with logistic regression
- Model evaluation (confusion matrix, classification reports)
- Regularization techniques (L2 penalty)
- Training data curation and bias mitigation

### Web Development
- FastAPI framework and routing
- Jinja2 templating
- Static file serving
- Form handling and POST requests
- CSS animations and responsive design
- Responsive word wrapping and overflow handling

### DevOps & Deployment
- Docker containerization
- Writing Dockerfiles with multi-stage builds
- Cloud platform deployment (Render)
- CI/CD with auto-deploy on git push
- Managing production vs development environments

### Data Engineering
- Web scraping with BeautifulSoup (18 sources)
- Dataset balancing and sampling
- CSV processing with pandas
- Data pipeline automation

### Software Engineering
- Git version control
- Project structure organization
- Path resolution and file I/O
- Error handling and debugging
- Documentation writing

## Some Possible Future Improvements

### Model Enhancements
1. **Additional Features**:
   - Domain age and WHOIS data
   - SSL certificate validity
   - Page content analysis
   - Redirect chain detection

2. **Advanced ML**:
   - Ensemble methods (Random Forest, Gradient Boosting)
   - Deep learning (LSTM for sequential URL patterns)
   - Real-time retraining with user feedback

3. **Dataset Expansion**:
   - Add more recent phishing URLs
   - Include multilingual phishing attempts
   - Expand to 500K+ URLs for better generalization

### Application Features
1. **Browser Extension**: Real-time protection while browsing
2. **API Endpoint**: Allow third-party integration
3. **Batch Analysis**: Upload CSV of URLs for bulk checking
4. **User Feedback**: Allow users to report false positives/negatives
5. **Historical Tracking**: Store and visualize threat trends

### Infrastructure
1. **Deployment**: Host on cloud platform (AWS, Azure, GCP)
2. **Database**: Store results for analytics
3. **Caching**: Redis for frequently checked URLs
4. **Monitoring**: Logging and performance metrics
5. **CI/CD**: Automated testing and deployment

## Project Files Structure
```
Malicious URL Detector/
├── config/
│   ├── whitelist.txt              # Trusted domains
│   ├── platform_hosts.txt         # User-generated content platforms
│   └── long_benign_url.txt        # Scraped documentation URLs (3,000+)
├── data/
│   ├── processed/
│   │   └── processed_dataset.csv  # Combined training data (126,664+ URLs)
│   └── top-1m.csv                 # Tranco top million domains
├── Dockerfile                     # Docker containerization config
├── malicious-url-detector/
│   ├── models/
│   │   └── logistic_regression_model.joblib  # Trained model
│   └── src/
│       ├── components.py          # Feature extraction (39 features)
│       ├── model.py               # Training pipeline
│       └── predict.py             # Inference logic with tiered system
├── scripts/
│   ├── build_dataset.py           # Data collection and balancing
│   └── scrape_benign_urls.py      # Documentation URL scraper
├── webapp/
│   ├── static/
│   │   └── animation.lottie       # Local Lottie animation
│   ├── templates/
│   │   └── index.html             # Main UI template
│   └── app.py                     # FastAPI server
└── requirements.txt               # Python dependencies
```

## Project Outcome

✅ Built end-to-end ML application from scratch
✅ Achieved 99.40% accuracy on balanced test set
✅ Designed and implemented production-ready web interface
✅ Deployed live web application using Docker and Render
✅ Identified and resolved training data bias through systematic debugging
✅ Created automated data collection pipeline scraping 18 documentation sources
✅ Implemented tiered protection system for nuanced risk assessment
✅ Fixed UI overflow issues with responsive word wrapping
✅ Learned to balance model performance with real-world applicability

---

**Total Development Time**: ~6-8 hours
**Lines of Code**: ~800 (Python) + ~150 (HTML/CSS/JS)
**Dataset Size**: 126,664 URLs
**Model Training Time**: ~5 seconds
**Inference Time**: <10ms per URL
