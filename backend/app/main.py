from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import our modules
from app.utils.validators import validate_url
from app.services.api_checker import APIChecker
from app.models.url_features import analyze_url_features
from app.services.scorer import get_complete_analysis

# URLRequest model
class URLRequest(BaseModel):
    url: str

# Create app
app = FastAPI(
    title="Malicious URL Scanner API",
    description="Hybrid threat detection system for URLs and domains",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root endpoint
@app.get("/")
def root():
    return {"message": "Malicious URL Scanner API", "version": "1.0.0"}

# Health check
@app.get("/health")
def health_check():
    return {"status": "healthy"}

# MAIN SCANNING ENDPOINT - Complete integration!
@app.post("/scan")
async def scan_url(request: URLRequest):
    """
    Scan a URL for malicious content using hybrid detection.
    """
    # Step 1: Validate URL
    is_valid, normalized_url, error = validate_url(request.url)
    if not is_valid:
        return {"error": error}
    
    # Step 2: Check with threat intelligence APIs
    checker = APIChecker()
    api_results = await checker.check_all_apis(normalized_url)
    
    # Step 3: Extract ML features
    feature_results = analyze_url_features(normalized_url)
    
    # Step 4: Calculate final risk score
    complete_analysis = get_complete_analysis(
        normalized_url,
        api_results,
        feature_results
    )
    
    return complete_analysis