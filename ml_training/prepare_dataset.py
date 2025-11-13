"""
Dataset Preparation Script
Downloads and prepares malicious and benign URL datasets
"""
import pandas as pd
import requests
import os
from typing import List


def download_phishtank_data() -> List[str]:
    """
    Download malicious URLs from PhishTank
    Note: You may need to register at phishtank.com for full access
    """
    print("📥 Downloading PhishTank data...")
    
    # PhishTank provides a JSON feed
    # You'll need to register and get the URL for the feed
    # For now, this is a placeholder
    
    malicious_urls = [
        # Add sample malicious URLs for testing
        "http://malicious-example.com/phishing",
        "http://fake-bank-login.xyz/secure",
    ]
    
    print(f"✓ Loaded {len(malicious_urls)} malicious URLs from PhishTank")
    return malicious_urls


def download_urlhaus_data() -> List[str]:
    """Download malicious URLs from URLhaus"""
    print("📥 Downloading URLhaus data...")
    
    try:
        url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        response = requests.get(url)
        
        if response.status_code == 200:
            lines = response.text.split('\n')
            malicious_urls = []
            
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                
                parts = line.split(',')
                if len(parts) >= 3:
                    url = parts[2].strip('"')
                    if url.startswith('http'):
                        malicious_urls.append(url)
            
            print(f"✓ Loaded {len(malicious_urls)} malicious URLs from URLhaus")
            return malicious_urls
        else:
            print(f"⚠ Failed to download URLhaus data: {response.status_code}")
            return []
    
    except Exception as e:
        print(f"⚠ Error downloading URLhaus data: {e}")
        return []


def download_benign_urls() -> List[str]:
    """
    Download benign URLs from Alexa/Tranco top sites
    """
    print("📥 Downloading benign URLs...")
    
    try:
        # Using Tranco list (replacement for Alexa Top Sites)
        url = "https://tranco-list.eu/top-1m.csv.zip"
        
        print("ℹ For this demo, using sample benign URLs")
        print("ℹ To get real data, download from: https://tranco-list.eu/")
        
        # Sample benign URLs
        benign_urls = [
            "https://google.com",
            "https://youtube.com",
            "https://facebook.com",
            "https://amazon.com",
            "https://wikipedia.org",
            "https://twitter.com",
            "https://instagram.com",
            "https://linkedin.com",
            "https://reddit.com",
            "https://netflix.com",
        ]
        
        print(f"✓ Loaded {len(benign_urls)} benign URLs")
        return benign_urls
    
    except Exception as e:
        print(f"⚠ Error downloading benign URLs: {e}")
        return []


def create_dataset(output_file: str = "url_dataset.csv"):
    """
    Create combined dataset of malicious and benign URLs
    """
    print("\n🔧 Creating dataset...\n")
    
    # Collect URLs
    malicious_urls = []
    malicious_urls.extend(download_phishtank_data())
    malicious_urls.extend(download_urlhaus_data())
    
    benign_urls = download_benign_urls()
    
    # Create DataFrame
    data = []
    
    for url in malicious_urls[:1000]:  # Limit to 1000 each
        data.append({"url": url, "label": 1})
    
    for url in benign_urls[:1000]:
        data.append({"url": url, "label": 0})
    
    df = pd.DataFrame(data)
    
    # Shuffle
    df = df.sample(frac=1).reset_index(drop=True)
    
    # Save
    os.makedirs("data", exist_ok=True)
    output_path = os.path.join("data", output_file)
    df.to_csv(output_path, index=False)
    
    print(f"\n✅ Dataset created: {output_path}")
    print(f"   Total URLs: {len(df)}")
    print(f"   Malicious: {sum(df['label'] == 1)}")
    print(f"   Benign: {sum(df['label'] == 0)}")
    
    return df


if __name__ == "__main__":
    print("=" * 60)
    print("URL Dataset Preparation")
    print("=" * 60)
    
    dataset = create_dataset()
    
    print("\n✅ Dataset preparation complete!")
    print("\nNext steps:")
    print("1. Review the dataset in ml_training/data/url_dataset.csv")
    print("2. Run train_model.py to train the ML model")
