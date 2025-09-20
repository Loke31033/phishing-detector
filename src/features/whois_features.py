# src/features/whois_features.py
import os
import json
from datetime import datetime
import tldextract
import whois
from dateutil import parser as dateparser

CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "cache", "whois_cache.json")
# normalize path above: results will be in project_root/cache/whois_cache.json
# ensure cache directory exists
os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)

def _load_cache():
    try:
        with open(CACHE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_cache(cache):
    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2, default=str)

def _safe_parse_date(d):
    if d is None:
        return None
    try:
        # whois returns datetime or string or list
        if isinstance(d, list):
            d = d[0]
        return dateparser.parse(str(d))
    except Exception:
        return None

def whois_lookup(domain):
    """
    Lookup WHOIS for a domain, with local json cache.
    Returns dict with creation_date, expiration_date, registrar, raw (cached raw data summary)
    """
    cache = _load_cache()
    if domain in cache:
        return cache[domain]

    info = {"creation_date": None, "expiration_date": None, "registrar": None, "raw": None}
    try:
        w = whois.whois(domain)
        cd = _safe_parse_date(w.creation_date)
        ed = _safe_parse_date(w.expiration_date)
        registrar = w.registrar if hasattr(w, "registrar") else None
        info["creation_date"] = cd.isoformat() if cd else None
        info["expiration_date"] = ed.isoformat() if ed else None
        info["registrar"] = registrar
        # store a small raw summary (avoid saving huge objects)
        info["raw"] = {
            "domain_name": w.domain_name if hasattr(w, "domain_name") else None,
            "name_servers": w.name_servers if hasattr(w, "name_servers") else None
        }
    except Exception as e:
        info["error"] = str(e)

    # save to cache
    cache[domain] = info
    _save_cache(cache)
    return info

def whois_features_from_url(url):
    """
    Accepts full URL (http[s]://...) or domain. Returns numeric features usable for ML.
    """
    # normalize input to registered domain
    ext = tldextract.extract(url)
    domain = ".".join([part for part in (ext.domain, ext.suffix) if part])
    res = whois_lookup(domain)

    now = datetime.utcnow()
    creation = dateparser.parse(res["creation_date"]) if res.get("creation_date") else None
    expiration = dateparser.parse(res["expiration_date"]) if res.get("expiration_date") else None

    domain_age_days = (now - creation).days if creation else -1
    days_to_expiry = (expiration - now).days if expiration else -1
    registrar_present = 1 if res.get("registrar") else 0

    return {
        "whois_domain": domain,
        "whois_domain_age_days": domain_age_days,
        "whois_days_to_expiry": days_to_expiry,
        "whois_has_registrar": registrar_present,
    }

# quick CLI test
if __name__ == "__main__":
    test = "http://login-paypal.com@malicious.com"
    print("WHOIS features for:", test)
    print(whois_features_from_url(test))
