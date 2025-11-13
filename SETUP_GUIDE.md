# Detailed Setup Guide

## Step-by-Step Setup

### 1. Getting API Keys

#### Google Safe Browsing API
1. Go to https://console.cloud.google.com/
2. Create a new project or select existing
3. Enable "Safe Browsing API"
4. Go to "Credentials" → "Create Credentials" → "API Key"
5. Copy your API key - AIzaSyBL4b8zL66mGRYMLDPtha6m3cBc72lHnc8

#### VirusTotal API
1. Go to https://www.virustotal.com/gui/join-us
2. Sign up for a free account
3. Go to your profile → API Key
4. Copy your API key - 3dc43f9caff066c3e3a1df355138b67c5c3afeaec8da828565f5fd7a208f5d39

### 2. Backend Configuration

1. Create `.env` file in `backend/` directory:
```bash
cd backend
cp .env.example .env
```

2. Edit `.env` and add your keys:
```
GOOGLE_SAFE_BROWSING_API_KEY=your_actual_key_here
VIRUSTOTAL_API_KEY=your_actual_key_here
HOST=0.0.0.0
PORT=8000
```

### 3. Running the Application

#### Terminal 1 - Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

#### Terminal 2 - Frontend
```bash
cd frontend
npm install
npm start
```

### 4. Accessing the Application

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## Troubleshooting

### Backend won't start
- Check Python version: `python --version` (need 3.10+)
- Check if port 8000 is available
- Verify .env file exists with API keys

### Frontend won't start
- Check Node version: `node --version` (need 18+)
- Delete `node_modules` and run `npm install` again
- Check if port 3000 is available

### API Key Issues
- Verify keys are correct in .env file
- Check API quotas/limits haven't been exceeded
- Ensure APIs are enabled in your cloud console

## File Structure Overview

```
backend/
├── app/
│   ├── main.py              # FastAPI app entry point
│   ├── models/              # ML model code
│   ├── services/            # API integration & scoring
│   └── utils/               # Helper functions
├── data/                    # Trained models stored here
└── requirements.txt

frontend/
├── src/
│   ├── components/          # React components
│   ├── services/            # API calls to backend
│   └── App.jsx              # Main app component
└── package.json

ml_training/
├── prepare_dataset.py       # Download and prep data
├── train_model.py           # Train the ML model
└── requirements.txt
```

## Next Steps

1. Start with backend development (Week 1)
2. Test API endpoints using FastAPI docs
3. Train ML model
4. Build frontend (Week 2)
5. Integrate and test
6. Polish and prepare presentation
