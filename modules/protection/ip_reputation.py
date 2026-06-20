"""
IP Reputation check using AbuseIPDB.
If an IP has a high abuse confidence score, it gets pre-emptively banned
before it even makes an auth attempt.

Get a free API key at https://www.abuseipdb.com/register
"""

import json
import urllib.request
import urllib.error
import time
import threading
from datetime import datetime, timedelta


class IPReputationChecker:

    def __init__(self, cfg):
        rep = cfg.section("ip_reputation")
        self.enabled = rep.get("enabled", False)
        self.api_key = rep.get("abuseipdb_api_key", "")
        self.block_threshold = rep.get("block_threshold", 80)  # 0-100 confidence score
        self.cache_ttl = rep.get("cache_ttl_hours", 24) * 3600
        self.check_on_connect = rep.get("check_on_connect", True)

        # simple in-memory cache: ip -> (score, timestamp, is_whitelisted)
        self._cache = {}
        self._lock = threading.Lock()

        # background thread to pre-check IPs from a block list feed
        self._block_list = set()

    def check(self, ip):
        """
        Returns (is_malicious, score, country).
        is_malicious = True means ban this IP.
        Cached for cache_ttl seconds.
        """
        if not self.enabled or not self.api_key:
            return False, 0, "N/A"

        if self._is_private(ip):
            return False, 0, "private"

        with self._lock:
            cached = self._cache.get(ip)
            if cached:
                score, ts, country = cached
                if time.time() - ts < self.cache_ttl:
                    return score >= self.block_threshold, score, country

        score, country = self._query_abuseipdb(ip)

        with self._lock:
            self._cache[ip] = (score, time.time(), country)

        is_bad = score >= self.block_threshold
        if is_bad:
            print(f"[IPReputation] {ip} has score {score} — marking as malicious (country: {country})")

        return is_bad, score, country

    def _query_abuseipdb(self, ip):
        """Returns (confidence_score 0-100, country_code)."""
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": self.api_key,
            "Accept": "application/json"
        })
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            d = data.get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            country = d.get("countryCode", "N/A")
            return score, country
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # rate limited — return 0 so we don't block anything by accident
                print("[IPReputation] Rate limited by AbuseIPDB")
            return 0, "N/A"
        except Exception as e:
            print(f"[IPReputation] Query failed for {ip}: {e}")
            return 0, "N/A"

    def cache_size(self):
        with self._lock:
            return len(self._cache)

    def clear_cache(self):
        with self._lock:
            self._cache.clear()

    @staticmethod
    def _is_private(ip):
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
