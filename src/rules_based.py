from urllib.parse import urlparse

def simple_url_rule_check(url: str) -> bool:
    """
    Return True if suspicious, False if likely safe.
    Very simple rules for Day 1 baseline.
    """
    url = url.strip()
    if '@' in url:
        return True
    if url.count('.') > 5:  # too many dots
        return True
    parsed = urlparse(url)
    # IP address in netloc -> suspicious
    netloc = parsed.netloc
    if netloc.replace(':','').replace('.','').isdigit():
        return True
    if parsed.scheme not in ('http', 'https'):
        return True
    return False

if __name__ == "__main__":
    sample = [
        "http://example.com",
        "http://user@malicious.example",
        "http://192.168.0.1/login",
        "https://safe-site.org"
    ]
    for u in sample:
        print(u, "->", "SUSPICIOUS" if simple_url_rule_check(u) else "SAFE")
