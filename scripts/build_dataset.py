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

    # Create labeled DataFrames; mark 1 for malicious, 0 for benign
    phish_df = pd.DataFrame({"url": phishtank_urls, "label": 1, "source": "phishtank"})
    urlhaus_df = pd.DataFrame({"url": urlhaus_urls, "label": 1, "source": "urlhaus"})
    benign_df = pd.DataFrame({"url": tranco_urls, "label": 0, "source": "tranco"})
    
    # Balance dataset: sample benign URLs to match malicious count
    malicious_count = len(phish_df) + len(urlhaus_df)
    benign_df = benign_df.sample(n=min(malicious_count, len(benign_df)), random_state=42)
    
    # Combine all datasets
    all_df = pd.concat([phish_df, urlhaus_df, benign_df], ignore_index=True)
    
    # Clean and filter -- make sure no empty or duplicate URLs and all in lower case 
    all_df["url"] = all_df["url"].astype(str).str.strip().str.lower()
    all_df = all_df[all_df["url"].str.len() > 0]
    all_df = all_df.drop_duplicates(subset="url", keep="first")
    
    # Save to CSV
    output_path = "data/processed/processed_dataset.csv"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    all_df.to_csv(output_path, index=False)
    print(f"Dataset saved to {output_path}")
    print(f"Total URLs: {len(all_df)}")
    print(f"Malicious: {len(all_df[all_df['label'] == 1])}")
    print(f"Benign: {len(all_df[all_df['label'] == 0])}")

if __name__ == "__main__":
    main()