# Development Checklist

## Week 1: Backend + ML

### Day 1-2: Backend Setup
- [ ] Set up FastAPI application structure
- [ ] Create URL validation utility
- [ ] Implement basic API endpoint for URL scanning
- [ ] Test endpoint with FastAPI docs

### Day 3-4: API Integration
- [ ] Integrate Google Safe Browsing API
- [ ] Integrate VirusTotal API
- [ ] Add URLhaus integration
- [ ] Create service layer for API calls
- [ ] Handle API errors and rate limits

### Day 5-6: ML Model
- [ ] Download malicious URL dataset (PhishTank, URLhaus)
- [ ] Download benign URL dataset (Tranco/Alexa)
- [ ] Extract URL features (length, special chars, domain age, etc.)
- [ ] Create feature engineering pipeline
- [ ] Train simple classification model
- [ ] Save trained model

### Day 7: Scoring Logic
- [ ] Create aggregation logic (combine API + ML scores)
- [ ] Implement risk score calculation (0-100)
- [ ] Add detailed breakdown response
- [ ] Test with various URLs

## Week 2: Frontend + Integration

### Day 8-9: React Setup
- [ ] Initialize React app
- [ ] Create SearchBar component
- [ ] Create RiskScore component (visual gauge)
- [ ] Create ResultsDisplay component
- [ ] Create Sidebar component

### Day 10-11: Integration
- [ ] Set up Axios for API calls
- [ ] Connect SearchBar to backend
- [ ] Display scan results
- [ ] Implement loading states
- [ ] Handle errors gracefully

### Day 12-13: Polish
- [ ] Add CSS styling (clean, modern look)
- [ ] Implement recent searches in sidebar (browser state)
- [ ] Add result breakdown visualization
- [ ] Mobile responsive design
- [ ] Add loading animations

### Day 14: Final Testing
- [ ] Test with various URLs
- [ ] Fix bugs
- [ ] Update README with screenshots
- [ ] Prepare demo script
- [ ] Test on fresh installation

## Optional Enhancements (If Time Permits)
- [ ] Add URL history export (CSV/JSON)
- [ ] Add "Scan Again" functionality
- [ ] Implement batch URL scanning
- [ ] Add more detailed threat information
- [ ] Create better data visualizations

## Presentation Prep
- [ ] Create demo script
- [ ] Prepare slides explaining architecture
- [ ] Document design decisions
- [ ] Prepare example URLs for demo
- [ ] Test demo flow multiple times
