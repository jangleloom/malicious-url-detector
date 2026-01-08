# scripts/scrape_benign_urls.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

def scrape_site(base_url, max_urls=100, min_path_length=20):
    """
    Scrape URLs from a documentation site.
    
    Args:
        base_url: Starting URL to scrape
        max_urls: Maximum number of URLs to collect
        min_path_length: Minimum path length to filter for long URLs
    
    Returns:
        Set of URLs with paths longer than min_path_length
    """
    visited = set()
    to_visit = [base_url]
    long_urls = set()
    
    print(f"\nScraping {base_url}...")
    
    while to_visit and len(long_urls) < max_urls:
        url = to_visit.pop(0)
        
        if url in visited:
            continue
            
        visited.add(url)
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                continue
                
            # Parse the page
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                # Only keep URLs from same domain
                if urlparse(full_url).netloc != urlparse(base_url).netloc:
                    continue
                
                # Remove fragments and queries for cleaner URLs
                parsed = urlparse(full_url)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                # Check if path is long enough
                if len(parsed.path) >= min_path_length:
                    long_urls.add(clean_url)
                    print(f"  Found: {clean_url} (path length: {len(parsed.path)})")
                
                # Add to visit queue if from same domain
                if full_url not in visited and len(to_visit) < 50:
                    to_visit.append(full_url)
            
            # Be polite - don't hammer the server
            time.sleep(0.5)
            
        except Exception as e:
            print(f"  Error scraping {url}: {e}")
            continue
    
    print(f"  Collected {len(long_urls)} URLs from {base_url}")
    return long_urls


def main():
    # List of trusted documentation sites to scrape
    sites = [
        ("https://docs.python.org/3/library/", 150),
        ("https://developer.mozilla.org/en-US/docs/Web/JavaScript", 150),
        ("https://docs.github.com/en", 100),
        ("https://reactjs.org/docs/", 100),
        ("https://nodejs.org/api/", 100),
        ("https://kubernetes.io/docs/", 100),
        ("https://fastapi.tiangolo.com/tutorial/", 100),
        ("https://scikit-learn.org/stable/modules/", 100),
        ("https://medium.com/tag/programming", 150),
        ("https://towardsdatascience.com/", 150),
        ("https://stackoverflow.com/questions/tagged/python", 200),
        ("https://en.wikipedia.org/wiki/Python_(programming_language)", 100),
        ("https://learn.microsoft.com/en-us/docs/", 150),
        ("https://docs.aws.amazon.com/", 100),
        ("https://www.w3schools.com/python/", 100),
        ("https://www.freecodecamp.org/news/tag/python/", 100),
        ("https://docs.docker.com/", 100),
        ("https://cloud.google.com/docs/", 100),
    ]
    
    all_urls = set()
    
    for base_url, max_urls in sites:
        urls = scrape_site(base_url, max_urls=max_urls, min_path_length=25)
        all_urls.update(urls)
        
        if len(all_urls) >= 3000:
            print(f"\nReached target of 3000+ URLs. Stopping.")
            break
    
    # Save to file
    output_file = "config/long_benign_url.txt"
    with open(output_file, 'w') as f:
        f.write("# Scraped benign URLs with long paths\n")
        f.write(f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total URLs: {len(all_urls)}\n\n")
        
        for url in sorted(all_urls):
            f.write(f"{url}\n")
    
    print(f"\n{'='*60}")
    print(f"Saved {len(all_urls)} URLs to {output_file}")
    print(f"{'='*60}")
    
    # Show statistics
    path_lengths = [len(urlparse(url).path) for url in all_urls]
    print(f"\nPath length statistics:")
    print(f"  Min: {min(path_lengths)}")
    print(f"  Max: {max(path_lengths)}")
    print(f"  Average: {sum(path_lengths) / len(path_lengths):.1f}")


if __name__ == "__main__":
    main()
