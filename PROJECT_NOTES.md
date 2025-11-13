# Project Notes & Architecture

## Core Concept

A hybrid malicious URL/domain scanner that combines:
1. External threat intelligence APIs
2. Machine learning feature extraction
3. Aggregated risk scoring

## Architecture Decisions

### Why Hybrid Approach?
- **APIs provide**: Real-time threat data, known malicious URLs, community intelligence
- **ML provides**: Pattern recognition, zero-day detection, works offline
- **Combined**: Best of both worlds with higher accuracy

### Technology Choices

**Backend: FastAPI**
- Modern, fast Python framework
- Auto-generated API documentation
- Type hints and validation built-in
- Async support for concurrent API calls

**Frontend: React**
- Component-based architecture
- Easy state management for search history
- Rich ecosystem for UI components
- Fast development

**ML: Feature Engineering + Rules**
- No deep learning needed (simpler, faster, explainable)
- Extract features from URL structure
- Train simple classifier (Random Forest/SVM)
- Easier to explain in presentation

## API Integration Strategy

### Primary APIs (Free Tier)
1. **Google Safe Browsing** (10k requests/day)
   - Check against Google's threat lists
   - Fast, reliable

2. **VirusTotal** (500 requests/day)
   - Multiple antivirus scans
   - Community intelligence

3. **URLhaus** (Unlimited)
   - Malware distribution URLs
   - Abuse.ch project

### API Call Pattern
```
User submits URL
    ↓
Validate URL format
    ↓
Parallel API calls (async)
    ↓
ML feature extraction
    ↓
Aggregate scores
    ↓
Return risk score + details
```

## ML Feature Engineering

### URL Features to Extract
- **Length-based**: Total length, domain length, path length
- **Character-based**: Special char count, digit count, entropy
- **Structure-based**: Subdomain count, path depth, query params
- **Domain-based**: TLD type, domain age (if available)
- **Pattern-based**: IP address in URL, suspicious keywords

### Training Data Sources
- **Malicious**: PhishTank, URLhaus, OpenPhish
- **Benign**: Tranco Top 1M, Alexa Top Sites

Target: ~20k-50k URLs (10k malicious, 10k benign)

## Scoring Algorithm

```python
# Pseudo-code
api_score = weighted_average([
    google_safe_browsing_score * 0.4,
    virustotal_score * 0.4,
    urlhaus_score * 0.2
])

ml_score = ml_model.predict_proba(features)

final_score = (api_score * 0.7) + (ml_score * 0.3)

# Scale to 0-100
risk_score = final_score * 100
```

## Risk Categories
- **Safe (0-30)**: Green, low risk
- **Suspicious (31-70)**: Yellow, investigate further
- **Malicious (71-100)**: Red, high risk

## Frontend State Management

### Session Storage (Browser Memory)
```javascript
recentSearches = [
  {
    url: "example.com",
    score: 25,
    category: "safe",
    timestamp: "2024-11-04T10:30:00"
  }
]
```

Stored in React state, cleared on page refresh.

## Error Handling

### API Failures
- If all APIs fail → rely on ML score only
- If ML fails → rely on API scores only
- If both fail → return error, suggest retry

### Rate Limiting
- Cache results for repeated URLs (1 hour)
- Display rate limit warnings
- Rotate API keys if needed

## Future Enhancements (Post-Capstone)
- User accounts with history
- Email alerts for domain monitoring
- Browser extension
- API for developers
- Enhanced ML with deep learning
- Real-time threat feed integration

## Presentation Points
1. Problem: Phishing and malicious URLs are everywhere
2. Solution: Hybrid detection system
3. Demo: Live URL scanning
4. Architecture: Show diagram
5. ML Component: Explain feature extraction
6. Results: Show accuracy metrics
7. Future: Discuss scalability and improvements
