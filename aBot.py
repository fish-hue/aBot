import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin, urlunparse
import csv
import os
import time
import argparse
import json
from bs4 import BeautifulSoup

SQLI_PAYLOADS = ["' OR '1'='1", "';--", "\" OR \"1\"=\"1", "admin' --"]

class VulnerabilityScanner:
    def __init__(self, root=None, url=None, proxies=None, headers=None, cookies=None):
        self.root = root
        self.url = url
        self.proxies = proxies or []
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.loop = asyncio.get_event_loop()
        self.paused = False
        self.total_urls = 0
        self.processed_urls = 0
        self.proxy_index = 0
        self.results = []
        self.semaphore = asyncio.Semaphore(10)

        if self.root:
            self.setup_gui()

    def setup_gui(self):
        self.root.title("Async Vulnerability Scanner")

        entries = [
            ("Target URL:", 0),
            ("Proxies (comma-separated):", 1),
            ("Headers (key:value, comma-separated):", 2),
            ("Cookies (key=value, comma-separated):", 3)
        ]
        self.entries = {}
        for label, row in entries:
            ttk.Label(self.root, text=label).grid(row=row, column=0, sticky=tk.W)
            entry = ttk.Entry(self.root, width=50)
            entry.grid(row=row, column=1, columnspan=2, sticky=tk.W)
            self.entries[label] = entry

        self.start_button = ttk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=4, column=0)
        self.pause_button = ttk.Button(self.root, text="Pause", command=self.pause_scan, state=tk.DISABLED)
        self.pause_button.grid(row=4, column=1)
        self.resume_button = ttk.Button(self.root, text="Resume", command=self.resume_scan, state=tk.DISABLED)
        self.resume_button.grid(row=4, column=2)

        self.progress_bar = ttk.Progressbar(self.root, length=400, mode='determinate')
        self.progress_bar.grid(row=5, column=0, columnspan=3, sticky=tk.W)
        self.log_text = tk.Text(self.root, height=15, width=80)
        self.log_text.grid(row=6, column=0, columnspan=3)

        self.save_button = ttk.Button(self.root, text="Save Config", command=self.save_config)
        self.save_button.grid(row=7, column=0)
        self.load_button = ttk.Button(self.root, text="Load Config", command=self.load_config)
        self.load_button.grid(row=7, column=1)

    def log(self, message):
        if self.root:
            self.root.after(0, self._append_log, message)
        else:
            print(message)

    def _append_log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def get_entry_data(self, label):
        return self.entries[label].get().strip()

    def parse_headers(self, raw):
        return self._parse_pairs(raw, ":", "header")

    def parse_cookies(self, raw):
        return self._parse_pairs(raw, "=", "cookie")

    def _parse_pairs(self, raw, delimiter, pair_type):
        result = {}
        for pair in raw.split(","):
            if delimiter in pair:
                key, value = pair.split(delimiter, 1)
                result[key.strip()] = value.strip()
            elif pair.strip():
                self.log(f"Invalid {pair_type} format: '{pair}'. Expected 'Key{delimiter}Value'. Skipping.")
        return result

    def parse_proxies(self, raw):
        return [proxy.strip() for proxy in raw.split(",") if proxy.strip()]

    def get_next_proxy(self):
        if not self.proxies:
            return None
        proxy = self.proxies[self.proxy_index % len(self.proxies)]
        self.proxy_index += 1
        return proxy

    def pause_scan(self):
        self.paused = True
        self.pause_button.config(state=tk.DISABLED)
        self.resume_button.config(state=tk.NORMAL)
        self.log("Scan paused.")

    def resume_scan(self):
        self.paused = False
        self.pause_button.config(state=tk.NORMAL)
        self.resume_button.config(state=tk.DISABLED)
        self.log("Scan resumed.")

    def start_scan(self):
        self.url = self.get_entry_data("Target URL:")
        if not self.url:
            messagebox.showerror("Error", "Please enter a target URL")
            return

        self.proxies = self.parse_proxies(self.get_entry_data("Proxies (comma-separated):"))
        self.headers = self.parse_headers(self.get_entry_data("Headers (key:value, comma-separated):"))
        self.cookies = self.parse_cookies(self.get_entry_data("Cookies (key=value, comma-separated):"))

        self.start_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.NORMAL)
        self.resume_button.config(state=tk.DISABLED)

        asyncio.ensure_future(self.scan(self.url))

    def normalize_url(self, url):
        parsed = urlparse(url)._replace(fragment='')
        path = parsed.path or '/'
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        parsed = parsed._replace(path=path)
        return urlunparse(parsed)

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
                        normalized_url = self.normalize_url(full_url)
                        if urlparse(normalized_url).netloc == urlparse(url).netloc:
                            urls.add(normalized_url)
        except Exception as e:
            self.log(f"Crawl error: {e}")
        return list(urls)

    async def fetch(self, session, url):
        for attempt in range(3):
            try:
                proxy = self.get_next_proxy()
                kwargs = {"headers": self.headers, "cookies": self.cookies}
                if proxy:
                    kwargs["proxy"] = f"http://{proxy}"
                async with session.get(url, timeout=10, **kwargs) as response:
                    return await response.text()
            except Exception as e:
                self.log(f"Attempt {attempt + 1}/3 failed for {url}: {e}")
                await asyncio.sleep(1)
        return ""

    async def _test_payload(self, session, url, payload, vuln_type, check):
        test_url = url + payload
        content = await self.fetch(session, test_url)
        if check(content):
            self.log(f"[{vuln_type}] Found at {test_url}")
            self._save_result(vuln_type, test_url, "High")

    async def test_xss(self, session, url):
        payload = "<script>alert('xss')</script>"
        await self._test_payload(session, url, payload, "XSS", lambda c: payload in c)

    async def test_sqli(self, session, url):
        for payload in SQLI_PAYLOADS:
            await self._test_payload(session, url, payload, "SQL Injection", 
                lambda c: any(err in c.lower() for err in ["sql syntax", "mysql", "sqlite", "pg_query", "unexpected end of sql", "unclosed quotation mark"]))

    async def test_cmd_injection(self, session, url):
        payload = ";echo vulncmd"
        await self._test_payload(session, url, payload, "Command Injection", lambda c: "vulncmd" in c)

    async def scan(self, base_url):
        urls = list(set(self.normalize_url(u) for u in await self.crawl(base_url)))
        self.total_urls = len(urls)
        self.progress_bar["maximum"] = self.total_urls

        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in urls:
                tasks.extend([
                    self.test_xss(session, url),
                    self.test_sqli(session, url),
                    self.test_cmd_injection(session, url)
                ])
            await asyncio.gather(*tasks)

        self.generate_html_report()
        self.log("Scan complete. HTML report generated as 'report.html'.")
        self.start_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.DISABLED)
        self.resume_button.config(state=tk.DISABLED)

    def _save_result(self, vuln_type, url, severity):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.results.append((timestamp, vuln_type, severity, url))
        with open("results.csv", "a", newline="") as f:
            csv.writer(f).writerow([timestamp, vuln_type, severity, url])

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
        <table><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>URL</th></tr>"""
        for row in self.results:
            html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>"
        html += "</table></body></html>"
        with open("report.html", "w") as f:
            f.write(html)

    def save_config(self):
        config = {
            "url": self.get_entry_data("Target URL:"),
            "proxies": self.parse_proxies(self.get_entry_data("Proxies (comma-separated):")),
            "headers": self.parse_headers(self.get_entry_data("Headers (key:value, comma-separated):")),
            "cookies": self.parse_cookies(self.get_entry_data("Cookies (key=value, comma-separated):"))
        }
        with open("config.json", "w") as f:
            json.dump(config, f, indent=4)
        self.log("Configuration saved to config.json")

    def load_config(self):
        if os.path.exists("config.json"):
            with open("config.json", "r") as f:
                config = json.load(f)
            self.entries["Target URL:"].delete(0, tk.END)
            self.entries["Target URL:"].insert(0, config.get("url", ""))
            self.entries["Proxies (comma-separated):"].delete(0, tk.END)
            self.entries["Proxies (comma-separated):"].insert(0, ",".join(config.get("proxies", [])))
            self.entries["Headers (key:value, comma-separated):"].delete(0, tk.END)
            self.entries["Headers (key:value, comma-separated):"].insert(0, ",".join(f"{k}:{v}" for k, v in config.get("headers", {}).items()))
            self.entries["Cookies (key=value, comma-separated):"].delete(0, tk.END)
            self.entries["Cookies (key=value, comma-separated):"].insert(0, ",".join(f"{k}={v}" for k, v in config.get("cookies", {}).items()))
            self.log("Configuration loaded from config.json")
        else:
            self.log("No configuration file found.")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScanner(root)
    root.mainloop()
