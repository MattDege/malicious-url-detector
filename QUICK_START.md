# Quick Start Guide

## Download and Extract

1. Download `malicious-url-scanner.tar.gz`
2. Extract it:
   ```bash
   tar -xzf malicious-url-scanner.tar.gz
   cd malicious-url-scanner
   ```

## What's Inside

```
malicious-url-scanner/
├── README.md              # Main documentation
├── SETUP_GUIDE.md         # Detailed setup instructions
├── TODO.md                # Development checklist
├── PROJECT_NOTES.md       # Architecture and technical notes
├── backend/               # FastAPI backend (empty files ready for code)
├── frontend/              # React frontend (empty files ready for code)
└── ml_training/           # ML scripts (empty files ready for code)
```

## Important Files to Read First

1. **README.md** - Overview and basic setup
2. **SETUP_GUIDE.md** - Step-by-step setup instructions
3. **TODO.md** - Development task checklist
4. **PROJECT_NOTES.md** - Architecture decisions and technical details

## File Structure

All Python and JavaScript files are created but empty, ready for you to add code:

**Backend Files:**
- `backend/app/main.py` - FastAPI app entry point
- `backend/app/models/ml_model.py` - ML model code
- `backend/app/services/api_checker.py` - External API integration
- `backend/app/services/scorer.py` - Risk scoring logic
- `backend/app/utils/validators.py` - URL validation

**Frontend Files:**
- `frontend/src/App.jsx` - Main React component
- `frontend/src/components/SearchBar.jsx` - Search input
- `frontend/src/components/ResultsDisplay.jsx` - Show scan results
- `frontend/src/components/Sidebar.jsx` - Recent searches
- `frontend/src/components/RiskScore.jsx` - Risk score display
- `frontend/src/services/api.js` - Backend API calls

**ML Training Files:**
- `ml_training/prepare_dataset.py` - Download and prepare data
- `ml_training/train_model.py` - Train the model

## Configuration Files Included

✅ `backend/requirements.txt` - Python dependencies
✅ `frontend/package.json` - Node.js dependencies
✅ `backend/.env.example` - API key template
✅ `frontend/.env.example` - Frontend config template
✅ `.gitignore` - Git ignore rules
✅ `docker-compose.yml` - Optional Docker setup

## Next Steps

1. Read the documentation files
2. Follow SETUP_GUIDE.md to configure environment
3. Get API keys (Google Safe Browsing, VirusTotal)
4. Start with backend development (see TODO.md)
5. Build frontend
6. Integrate and test

## Getting API Keys

**Google Safe Browsing:**
https://developers.google.com/safe-browsing/v4/get-started

**VirusTotal:**
https://www.virustotal.com/gui/join-us

## Questions?

Refer to:
- SETUP_GUIDE.md for setup issues
- PROJECT_NOTES.md for technical details
- TODO.md for development order

Good luck with your capstone project! 🚀
