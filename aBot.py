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
from pyppeteer import launch

SQLI_PAYLOADS = ["' OR '1'='1", "';--", "\" OR \"1\"=\"1", "admin' --"]

class VulnerabilityScanner:
    def __init__(self, root=None, url=None, proxies=None, headers=None, cookies=None):
        self.root = root
        self.url = url
        self.proxies = proxies or []
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.loop = asyncio.get_event_loop()
        self.tasks = []
        self.paused = False
        self.total_urls = 0
        self.processed_urls = 0
        self.proxy_index = 0
        self.results = []
        self.semaphore = asyncio.Semaphore(10)  # Limit concurrency to 10 requests

        if self.root:
            self.setup_gui()

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

        # Add Save and Load buttons
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

    def get_headers(self):
        raw_headers = self.header_entry.get()
        if raw_headers:
            return {k.strip(): v.strip() for k, v in (pair.split(":") for pair in raw_headers.split(","))}
        return self.headers

    def get_cookies(self):
        raw_cookies = self.cookie_entry.get()
        if raw_cookies:
            return {k.strip(): v.strip() for k, v in (pair.split("=") for pair in raw_cookies.split(","))}
        return self.cookies

    def get_proxies(self):
        raw = self.proxy_entry.get()
        if raw:
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
        self.update_ui_on_pause()
        self.log("Scan paused.")

    def resume_scan(self):
        self.paused = False
        self.update_ui_on_resume()
        self.log("Scan resumed.")

    def update_ui_on_pause(self):
        if self.root:
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.NORMAL)

    def update_ui_on_resume(self):
        if self.root:
            self.pause_button.config(state=tk.NORMAL)
            self.resume_button.config(state=tk.DISABLED)

    def start_scan(self):
        if self.root:
            self.start_button.config(state=tk.DISABLED)
            self.pause_button.config(state=tk.NORMAL)
            self.resume_button.config(state=tk.DISABLED)
        
        self.url = self.url_entry.get().strip()
        if not self.url:
            if self.root:
                messagebox.showerror("Error", "Please enter a target URL")
            return

        self.proxies = self.get_proxies()
        self.headers = self.get_headers()
        self.cookies = self.get_cookies()
        self.loop.create_task(self.scan(self.url))

    def normalize_url(self, url):
        parsed = urlparse(url)
        parsed = parsed._replace(fragment='')
        path = parsed.path
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        elif not path:
            path = '/'
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

    async def test_xss(self, session, url):
        payload = "<script>alert('xss')</script>"
        test_url = self._inject_payload(url, payload)
        content = await self.fetch(session, test_url)
        if payload in content:
            self.log(f"[XSS] Found at {test_url}")
            self._save_result("XSS", test_url, "High")

    async def test_sqli(self, session, url):
        for payload in SQLI_PAYLOADS:
            test_url = self._inject_payload(url, payload)
            content = await self.fetch(session, test_url)
            if any(err in content.lower() for err in ["sql syntax", "mysql", "sqlite", "pg_query", "unexpected end of SQL", "unclosed quotation mark"]):
                self.log(f"[SQL Injection] Found at {test_url} with payload: {payload}")
                self._save_result("SQL Injection", test_url, "High")
                break

    async def test_cmd_injection(self, session, url):
        payload = ";echo vulncmd"
        test_url = self._inject_payload(url, payload)
        content = await self.fetch(session, test_url)
        if "vulncmd" in content:
            self.log(f"[CMD Injection] Found at {test_url}")
            self._save_result("Command Injection", test_url, "High")

    async def scan(self, base_url):
        urls = await self.crawl(base_url)
        unique_urls = set(self.normalize_url(u) for u in urls)
        urls = list(unique_urls)

        self.total_urls = len(urls)
        self.processed_urls = 0
        if self.root:
            self.progress_bar["maximum"] = self.total_urls

        async with aiohttp.ClientSession() as session:
            tasks = [
                self.test_xss(session, url) for url in urls
            ] + [
                self.test_sqli(session, url) for url in urls
            ] + [
                self.test_cmd_injection(session, url) for url in urls
            ]
            await asyncio.gather(*tasks)

        self.generate_html_report()
        self.log("Scan complete. HTML report generated as 'report.html'.")
        if self.root:
            self.start_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.DISABLED)

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

    def save_config(self):
        config = {
            "url": self.url_entry.get().strip(),
            "proxies": self.get_proxies(),
            "headers": self.get_headers(),
            "cookies": self.get_cookies()
        }
        with open("config.json", "w") as f:
            json.dump(config, f, indent=4)
        self.log("Configuration saved to config.json")

    def load_config(self):
        if os.path.exists("config.json"):
            with open("config.json", "r") as f:
                config = json.load(f)
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, config.get("url", ""))
                self.proxy_entry.delete(0, tk.END)
                self.proxy_entry.insert(0, ",".join(config.get("proxies", [])))
                self.header_entry.delete(0, tk.END)
                self.header_entry.insert(0, ",".join(f"{k}:{v}" for k, v in config.get("headers", {}).items()))
                self.cookie_entry.delete(0, tk.END)
                self.cookie_entry.insert(0, ",".join(f"{k}={v}" for k, v in config.get("cookies", {}).items()))
            self.log("Configuration loaded from config.json")
        else:
            self.log("No configuration file found.")
            
# -- Main execution block --
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--headers", help="Headers (key:value, comma-separated)")
    parser.add_argument("--cookies", help="Cookies (key=value, comma-separated)")
    parser.add_argument("--proxies", help="Proxies (comma-separated)")
    args = parser.parse_args()

    if args.url:
        scanner = VulnerabilityScanner(url=args.url, headers={k.strip(): v.strip() for k, v in (pair.split(":") for pair in args.headers.split(","))}, cookies={k.strip(): v.strip() for k, v in (pair.split("=") for pair in args.cookies.split(","))}, proxies=[p.strip() for p in args.proxies.split(",")])
        asyncio.run(scanner.scan(args.url))
    else:
        root = tk.Tk()
        scanner = VulnerabilityScanner(root=root)
        root.mainloop()
