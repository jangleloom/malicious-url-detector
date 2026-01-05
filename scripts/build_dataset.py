# scripts/build_dataset.py
import pandas as pd
import requests
from io import StringIO

def load_phishtank_csv():
    url = "https://data.phishtank.com/data/online-valid.csv"
    text = requests.get(url, timeout=10).text
    df = pd.read_csv(StringIO(text)) # StringIO converts string to file-like object
    return df["url"].dropna().astype(str) # Return URL column as strings 

def load_urlhaus_csv(): 
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    text = requests.get(url, timeout=10).text
    # Header is commented out, so specify column names manually
    columns = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
    df = pd.read_csv(StringIO(text), comment='#', names=columns, skipinitialspace=True)
    return df["url"].dropna().astype(str) # Return URL column as strings

def load_tranco_csv():
    url = "https://tranco-list.eu/download/LATEST"
    text = requests.get(url, timeout=10).text
    df = pd.read_csv(StringIO(text), header=None, names=["rank", "domain"])
    return df["domain"].dropna().astype(str) # Return domain column as strings



