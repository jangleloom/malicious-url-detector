# scripts/build_dataset.py
import pandas as pd
import requests
import os
from io import StringIO, BytesIO
from zipfile import ZipFile

def load_phishtank_csv():
    url = "https://data.phishtank.com/data/online-valid.csv"
    text = requests.get(url, timeout=10).text
    df = pd.read_csv(StringIO(text)) # StringIO converts string to file-like object
    return df["url"].dropna().astype(str) # Return URL column as strings 

def load_urlhaus_csv(): 
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    text = requests.get(url, timeout=10).text
    # Header is commented out, so specify column names explicitly
    columns = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
    df = pd.read_csv(StringIO(text), comment='#', names=columns, skipinitialspace=True)
    return df["url"].dropna().astype(str) # Return URL column as strings

def load_tranco_csv():
    url = "https://tranco-list.eu/top-1m.csv.zip"
    response = requests.get(url, timeout=10)
    # Extract CSV from ZIP file, use BytesIO to wrap raw bytes in file-like object for ZipFile
    with ZipFile(BytesIO(response.content)) as zip_file:
        # Get the (first and only) CSV file in the ZIP
        csv_filename = zip_file.namelist()[0]
        with zip_file.open(csv_filename) as csv_file:
            df = pd.read_csv(csv_file, header=None, names=["rank", "domain"])
    return df["domain"].dropna().drop_duplicates().astype(str) # Return domain column as strings

# Make sure all URLs have same scheme format for PhishTank and URLHaus
def normalize_urls(u: str) -> str:
    u = u.strip().lower()
    if "://" not in u:
        u = "https://" + u
    return u

# For Tranco csv which only has domains, so need to convert to URLs
def domain_to_url(domain: str) -> str:
    d = domain.strip().lower()
    return "https://" + d

def main():
    # Load datasets 
    phishtank_urls = load_phishtank_csv().apply(normalize_urls)
    urlhaus_urls = load_urlhaus_csv().apply(normalize_urls)
    tranco_urls = load_tranco_csv().apply(domain_to_url)
    
    # Load whitelist and platform hosts as additional benign samples
    whitelist_path = "config/whitelist.txt"
    with open(whitelist_path, 'r') as f:
        whitelist_domains = pd.Series([
            f"https://{line.strip().lower()}" 
            for line in f 
            if line.strip() and not line.strip().startswith("#")
        ])
    
    platform_path = "config/platform_hosts.txt"
    with open(platform_path, 'r') as f:
        platform_domains = pd.Series([
            f"https://{line.strip().lower()}" 
            for line in f 
            if line.strip() and not line.strip().startswith("#")
        ])

    long_benign_path = "config/long_benign_url.txt"
    with open(long_benign_path, 'r') as f:
        long_benign_urls = pd.Series([
            line.strip().lower()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ])
    benign_long_df = pd.DataFrame({"url": long_benign_urls, "label": 0, "source": "long_benign"})

    # Create labeled DataFrames; mark 1 for malicious, 0 for benign
    # Headers: url, label, source
    phish_df = pd.DataFrame({"url": phishtank_urls, "label": 1, "source": "phishtank"})
    urlhaus_df = pd.DataFrame({"url": urlhaus_urls, "label": 1, "source": "urlhaus"})
    benign_tranco_df = pd.DataFrame({"url": tranco_urls, "label": 0, "source": "tranco"})
    benign_whitelist_df = pd.DataFrame({"url": whitelist_domains, "label": 0, "source": "whitelist"})
    benign_platform_df = pd.DataFrame({"url": platform_domains, "label": 0, "source": "platform"})
    benign_long_df = pd.DataFrame({"url": long_benign_urls, "label": 0, "source": "long_benign"})
    
    # Balance dataset: sample benign URLs to match malicious count
    # .sample randomly selects rows from DataFrame, n specifies number of rows
    # random_state = 42 seeds the random number generator, ensure get same random URL sample each run
    malicious_count = len(phish_df) + len(urlhaus_df)
    
    # Use mix of curated sources (whitelist, platform, long benign) and Tranco
    # Take all curated sources first, fill remaining with Tranco
    curated_benign = pd.concat([benign_whitelist_df, benign_platform_df, benign_long_df], ignore_index=True)
    remaining = max(0, malicious_count - len(curated_benign))
    benign_tranco_sample = benign_tranco_df.sample(n=min(remaining, len(benign_tranco_df)), random_state=42)
    benign_df = pd.concat([curated_benign, benign_tranco_sample], ignore_index=True)
    
    # Combine all datasets
    all_df = pd.concat([phish_df, urlhaus_df, benign_df], ignore_index=True)
    
    # Clean and filter -- make sure no empty or duplicate URLs and all in lower case 
    all_df["url"] = all_df["url"].astype(str).str.strip().str.lower()
    all_df = all_df[all_df["url"].str.len() > 0]
    all_df = all_df.drop_duplicates(subset="url", keep="first")
    
    # Save to CSV
    output_path = "data/processed/processed_dataset.csv"
    # Check if directory exists, create if not
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    all_df.to_csv(output_path, index=False)
    print(f"Dataset saved to {output_path}")
    print(f"Total URLs: {len(all_df)}")
    print(f"Malicious: {len(all_df[all_df['label'] == 1])}")
    print(f"Benign: {len(all_df[all_df['label'] == 0])}")

if __name__ == "__main__":
    main()