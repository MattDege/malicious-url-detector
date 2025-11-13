# Malicious URL/Domain Scanner

A hybrid web application that detects malicious URLs and domains using threat intelligence APIs and machine learning feature extraction.

## Project Overview

This scanner combines multiple detection methods:
- **Threat Intelligence APIs**: Google Safe Browsing, VirusTotal, URLhaus
- **ML Feature Extraction**: URL structure analysis, domain characteristics
- **Aggregated Risk Scoring**: 0-100 scale (Safe/Suspicious/Malicious)

## Features

- Clean, intuitive web interface
- Real-time URL scanning
- Detailed risk breakdown
- Recent searches sidebar (session-based)
- No signup required

## Project Structure

```
malicious-url-scanner/
├── backend/          # FastAPI backend
├── frontend/         # React frontend
├── ml_training/      # ML model training scripts
└── README.md
```

## Setup Instructions

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure API keys:
```bash
cp .env.example .env
# Edit .env and add your API keys
```

5. Run the backend:
```bash
uvicorn app.main:app --reload
```

Backend will run on `http://localhost:8000`

### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment:
```bash
cp .env.example .env
```

4. Run the frontend:
```bash
npm start
```

Frontend will run on `http://localhost:3000`

### ML Model Training (Optional)

1. Navigate to ml_training directory:
```bash
cd ml_training
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Prepare dataset:
```bash
python prepare_dataset.py
```

4. Train model:
```bash
python train_model.py
```

## API Keys

You'll need to sign up for free API keys:

1. **Google Safe Browsing**: https://developers.google.com/safe-browsing/v4/get-started
2. **VirusTotal**: https://www.virustotal.com/gui/join-us

## Usage

1. Start both backend and frontend servers
2. Open browser to `http://localhost:3000`
3. Enter a URL or domain in the search bar
4. View the risk score and detailed analysis
5. Check recent searches in the sidebar

## Technology Stack

- **Backend**: FastAPI, Python
- **Frontend**: React, JavaScript
- **ML**: scikit-learn
- **APIs**: Google Safe Browsing, VirusTotal, URLhaus

## Development Timeline

- Week 1: Backend + ML model
- Week 2: Frontend + integration + polish

## License

Educational project for capstone coursework.
