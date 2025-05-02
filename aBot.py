import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import csv
import os
import re
import random
import time
import argparse
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self, root=None):
        self.root = root
        if self.root:
            self.setup_gui()

        self.loop = asyncio.get_event_loop()
        self.tasks = []
        self.paused = False
        self.total_urls = 0
        self.processed_urls = 0
        self.proxies = []
        self.headers = {}
        self.cookies = {}
        self.proxy_index = 0
        self.results = []

    def setup_gui(self):
        self.root.title("Async Vulnerability Scanner")

        ttk.Label(self.root, text="Target URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(self.root, width=50)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W)

        ttk.Label(self.root, text="Proxies (comma-separated):").grid(row=1, column=0, sticky=tk.W)
        self.proxy_entry = ttk.Entry(self.root, width=50)
        self.proxy_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W)

        ttk.Label(self.root, text="Headers (key:value, comma-separated):").grid(row=2, column=0, sticky=tk.W)
        self.header_entry = ttk.Entry(self.root, width=50)
        self.header_entry.grid(row=2, column=1, columnspan=2, sticky=tk.W)

        ttk.Label(self.root, text="Cookies (key=value, comma-separated):").grid(row=3, column=0, sticky=tk.W)
        self.cookie_entry = ttk.Entry(self.root, width=50)
        self.cookie_entry.grid(row=3, column=1, columnspan=2, sticky=tk.W)

        self.start_button = ttk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=4, column=0)
        self.pause_button = ttk.Button(self.root, text="Pause", command=self.pause_scan, state=tk.DISABLED)
        self.pause_button.grid(row=4, column=1)
        self.resume_button = ttk.Button(self.root, text="Resume", command=self.resume_scan, state=tk.DISABLED)
        self.resume_button.grid(row=4, column=2)

        self.progress_label = ttk.Label(self.root, text="Progress:")
        self.progress_label.grid(row=5, column=0, sticky=tk.W)
        self.progress_bar = ttk.Progressbar(self.root, length=400, mode='determinate')
        self.progress_bar.grid(row=5, column=1, columnspan=2, sticky=tk.W)

        self.log_text = tk.Text(self.root, height=15, width=80)
        self.log_text.grid(row=6, column=0, columnspan=3)

    def log(self, message):
        if self.root:
            self.root.after(0, self._append_log, message)
        else:
            print(message)

    def _append_log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def get_headers(self):
        if self.root:
            raw_headers = self.header_entry.get()
            headers = {}
            for pair in raw_headers.split(','):
                if ':' in pair:
                    k, v = pair.split(':', 1)
                    headers[k.strip()] = v.strip()
            return headers
        return self.headers

    def get_cookies(self):
        if self.root:
            raw_cookies = self.cookie_entry.get()
            cookies = {}
            for pair in raw_cookies.split(','):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    cookies[k.strip()] = v.strip()
            return cookies
        return self.cookies

    def get_proxies(self):
        if self.root:
            raw = self.proxy_entry.get()
            return [p.strip() for p in raw.split(',') if p.strip()]
        return self.proxies

    def get_next_proxy(self):
        if not self.proxies:
            return None
        proxy = self.proxies[self.proxy_index % len(self.proxies)]
        self.proxy_index += 1
        return proxy

    def pause_scan(self):
        self.paused = True
        if self.root:
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.NORMAL)
        self.log("Scan paused.")

    def resume_scan(self):
        self.paused = False
        if self.root:
            self.pause_button.config(state=tk.NORMAL)
            self.resume_button.config(state=tk.DISABLED)
        self.log("Scan resumed.")

    def start_scan(self):
        if self.root:
            self.start_button.config(state=tk.DISABLED)
            self.pause_button.config(state=tk.NORMAL)
            self.resume_button.config(state=tk.DISABLED)
        url = self.url_entry.get().strip()
        if not url:
            if self.root:
                messagebox.showerror("Error", "Please enter a target URL")
            return

        self.proxies = self.get_proxies()
        self.headers = self.get_headers()
        self.cookies = self.get_cookies()
        self.loop.create_task(self.scan(url))

    async def fetch(self, session, url):
        while self.paused:
            await asyncio.sleep(0.5)
        tries = 3
        for attempt in range(tries):
            try:
                proxy = self.get_next_proxy()
                kwargs = {"headers": self.headers, "cookies": self.cookies}
                if proxy:
                    kwargs["proxy"] = f"http://{proxy}"
                async with session.get(url, timeout=10, **kwargs) as response:
                    return await response.text()
            except Exception as e:
                self.log(f"Attempt {attempt + 1}/{tries} failed for {url}: {e}")
                await asyncio.sleep(1)
        return ""

    async def crawl(self, url):
        urls = set()
        try:
            async with aiohttp.ClientSession() as session:
                html = await self.fetch(session, url)
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup.find_all(['a', 'form', 'script']):
                    href = tag.get('href') or tag.get('action') or tag.get('src')
                    if href:
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == urlparse(url).netloc:
                            urls.add(full_url)
        except Exception as e:
            self.log(f"Crawl error: {e}")
        return list(urls)

    def _inject_payload(self, url, payload):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if not query:
            return url
        for key in query:
            query[key] = [payload]
        new_query = urlencode(query, doseq=True)
        return parsed._replace(query=new_query).geturl()

    async def test_xss(self, session, url):
        payload = "<script>alert('xss')</script>"
        test_url = self._inject_payload(url, payload)
        content = await self.fetch(session, test_url)
        if payload in content:
            self.log(f"[XSS] Found at {test_url}")
            self._save_result("XSS", test_url, "High")

    async def test_cmd_injection(self, session, url):
        payload = ";echo vulncmd"
        test_url = self._inject_payload(url, payload)
        content = await self.fetch(session, test_url)
        if "vulncmd" in content:
            self.log(f"[CMD Injection] Found at {test_url}")
            self._save_result("Command Injection", test_url, "High")

    def _save_result(self, vuln_type, url, severity):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.results.append((timestamp, vuln_type, severity, url))
        with open("results.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, vuln_type, severity, url])

    def generate_html_report(self):
        html = """<html><head><title>Vulnerability Report</title>
        <style>
        body { font-family: Arial; margin: 40px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f4f4f4; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        </style></head><body>
        <h1>Vulnerability Scan Report</h1>
        <table><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>URL</th></tr>
        """
        for row in self.results:
            html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>"
        html += "</table></body></html>"
        with open("report.html", "w") as f:
            f.write(html)

    async def scan(self, base_url):
        urls = await self.crawl(base_url)
        self.total_urls = len(urls)
        self.processed_urls = 0
        if self.root:
            self.progress_bar["maximum"] = self.total_urls

        async with aiohttp.ClientSession() as session:
            for url in urls:
                if self.paused:
                    while self.paused:
                        await asyncio.sleep(0.5)
                await asyncio.gather(
                    self.test_xss(session, url),
                    self.test_cmd_injection(session, url),
                )
                self.processed_urls += 1
                if self.root:
                    self.progress_bar["value"] = self.processed_urls
                self.log(f"Processed {self.processed_urls}/{self.total_urls}: {url}")

        self.generate_html_report()
        self.log("Scan complete. HTML report generated as 'report.html'.")
        if self.root:
            self.start_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--headers", help="Headers (key:value, comma-separated)")
    parser.add_argument("--cookies", help="Cookies (key=value, comma-separated)")
    parser.add_argument("--proxies", help="Proxies (comma-separated)")
    args = parser.parse_args()

    if args.url:
        scanner = VulnerabilityScanner()
        scanner.headers = {k.strip(): v.strip() for k, v in
                           [h.split(":") for h in args.headers.split(",")]} if args.headers else {}
        scanner.cookies = {k.strip(): v.strip() for k, v in
                           [c.split("=") for c in args.cookies.split(",")]} if args.cookies else {}
        scanner.proxies = [p.strip() for p in args.proxies.split(",")] if args.proxies else []

        async def run_scan():
            await scanner.scan(args.url)

        try:
            asyncio.run(run_scan())
        except RuntimeError as e:
            if "already running" in str(e):
                loop = asyncio.get_event_loop()
                loop.create_task(run_scan())
                loop.run_forever()
            else:
                raise
    else:
        root = tk.Tk()
        app = VulnerabilityScanner(root)
        root.mainloop()
