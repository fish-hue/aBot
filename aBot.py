import asyncio
import aiohttp
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import re

# Vulnerability scanning functions
async def scan_sql_injection(session, url, results, proxy):
    test_payloads = ["'", "' OR '1'='1"]
    for payload in test_payloads:
        test_url = f"{url}?test={payload}"
        try:
            async with session.get(test_url, proxy=proxy, timeout=10) as response:
                text = await response.text()
                if "sql" in text.lower() or "syntax" in text.lower():
                    results.append(f"[SQLi] {test_url} may be vulnerable.")
        except Exception as e:
            results.append(f"[SQLi ERROR] {test_url} - {e}")

async def scan_xss(session, url, results, proxy):
    payload = "<script>alert(1)</script>"
    test_url = f"{url}?q={payload}"
    try:
        async with session.get(test_url, proxy=proxy, timeout=10) as response:
            text = await response.text()
            if payload in text:
                results.append(f"[XSS] {test_url} may be vulnerable.")
    except Exception as e:
        results.append(f"[XSS ERROR] {test_url} - {e}")

async def scan_command_injection(session, url, results, proxy):
    payloads = [';id', '&& whoami']
    for payload in payloads:
        test_url = f"{url}?cmd={payload}"
        try:
            async with session.get(test_url, proxy=proxy, timeout=10) as response:
                text = await response.text()
                if "uid=" in text or "root" in text or "whoami" in text:
                    results.append(f"[CMDi] {test_url} may be vulnerable.")
        except Exception as e:
            results.append(f"[CMDi ERROR] {test_url} - {e}")

async def scan_open_redirect(session, url, results, proxy):
    payload = "http://evil.com"
    test_url = f"{url}?redirect={payload}"
    try:
        async with session.get(test_url, allow_redirects=False, proxy=proxy, timeout=10) as response:
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                if payload in location:
                    results.append(f"[Redirect] {test_url} may be vulnerable to open redirect.")
    except Exception as e:
        results.append(f"[Redirect ERROR] {test_url} - {e}")

async def scan_directory_traversal(session, url, results, proxy):
    payloads = ["../../etc/passwd", "..%2F..%2Fetc%2Fpasswd"]
    for payload in payloads:
        test_url = f"{url}?file={payload}"
        try:
            async with session.get(test_url, proxy=proxy, timeout=10) as response:
                text = await response.text()
                if "root:x:" in text:
                    results.append(f"[DirTraversal] {test_url} may be vulnerable.")
        except Exception as e:
            results.append(f"[DirTraversal ERROR] {test_url} - {e}")

async def run_scans(url, headers, cookies, proxy, enable_sql, enable_xss, enable_cmdi, enable_redirect, enable_traversal, results_callback):
    results = []

    if not any([enable_sql, enable_xss, enable_cmdi, enable_redirect, enable_traversal]):
        results_callback(["Please select at least one scan module."] )
        return

    try:
        if not url.startswith("http"):
            url = "http://" + url

        timeout = aiohttp.ClientTimeout(total=15)
        conn = aiohttp.TCPConnector(ssl=False)
        session_headers = {}
        session_cookies = {}

        if headers:
            try:
                session_headers = dict([line.split(":", 1) for line in headers.split("\n") if ":" in line])
            except:
                results.append("[ERROR] Invalid headers format.")
        if cookies:
            try:
                session_cookies = dict([cookie.strip().split("=", 1) for cookie in cookies.split(";") if "=" in cookie])
            except:
                results.append("[ERROR] Invalid cookies format.")

        # Proxy validation
        if proxy:
            try:
                async with aiohttp.ClientSession(connector=conn) as test_sess:
                    async with test_sess.get("http://httpbin.org/ip", proxy=proxy, timeout=5) as resp:
                        if resp.status != 200:
                            raise Exception("Proxy not working")
            except Exception as e:
                results_callback([f"[PROXY ERROR] Failed to use proxy: {e}"])
                return

        async with aiohttp.ClientSession(headers=session_headers, cookies=session_cookies, connector=conn, timeout=timeout) as session:
            tasks = []
            if enable_sql:
                tasks.append(scan_sql_injection(session, url, results, proxy))
            if enable_xss:
                tasks.append(scan_xss(session, url, results, proxy))
            if enable_cmdi:
                tasks.append(scan_command_injection(session, url, results, proxy))
            if enable_redirect:
                tasks.append(scan_open_redirect(session, url, results, proxy))
            if enable_traversal:
                tasks.append(scan_directory_traversal(session, url, results, proxy))

            await asyncio.gather(*tasks)

    except Exception as e:
        results.append(f"[ERROR] {e}")

    results_callback(results)

# GUI setup
def start_scan():
    url = url_entry.get().strip()
    headers = headers_text.get("1.0", tk.END).strip()
    cookies = cookies_text.get("1.0", tk.END).strip()
    proxy = proxy_entry.get().strip()
    enable_sql = sql_var.get()
    enable_xss = xss_var.get()
    enable_cmdi = cmdi_var.get()
    enable_redirect = redirect_var.get()
    enable_traversal = traversal_var.get()

    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return

    scan_button.config(state=tk.DISABLED)
    results_box.delete("1.0", tk.END)
    results_box.insert(tk.END, "Scanning...\n")

    def thread_target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_scans(
            url, headers, cookies, proxy, enable_sql, enable_xss, enable_cmdi, enable_redirect, enable_traversal,
            lambda results: update_results(results)
        ))
        scan_button.config(state=tk.NORMAL)

    threading.Thread(target=thread_target).start()

def update_results(results):
    results_box.delete("1.0", tk.END)
    for line in results:
        results_box.insert(tk.END, line + "\n")

# GUI
root = tk.Tk()
root.title("aBot Vulnerability Scanner")
root.geometry("700x650")

url_label = tk.Label(root, text="Target URL:")
url_label.pack()
url_entry = tk.Entry(root, width=80)
url_entry.pack()

proxy_label = tk.Label(root, text="Proxy (optional, format http://ip:port):")
proxy_label.pack()
proxy_entry = tk.Entry(root, width=80)
proxy_entry.pack()

headers_label = tk.Label(root, text="Custom Headers (one per line, format: Key: Value):")
headers_label.pack()
headers_text = scrolledtext.ScrolledText(root, height=4, width=80)
headers_text.pack()

cookies_label = tk.Label(root, text="Cookies (format: key=value; key2=value2):")
cookies_label.pack()
cookies_text = scrolledtext.ScrolledText(root, height=2, width=80)
cookies_text.pack()

# Module selection
sql_var = tk.BooleanVar()
xss_var = tk.BooleanVar()
cmdi_var = tk.BooleanVar()
redirect_var = tk.BooleanVar()
traversal_var = tk.BooleanVar()

sql_check = tk.Checkbutton(root, text="SQL Injection", variable=sql_var)
sql_check.pack(anchor='w')
xss_check = tk.Checkbutton(root, text="XSS", variable=xss_var)
xss_check.pack(anchor='w')
cmdi_check = tk.Checkbutton(root, text="Command Injection", variable=cmdi_var)
cmdi_check.pack(anchor='w')
redirect_check = tk.Checkbutton(root, text="Open Redirect", variable=redirect_var)
redirect_check.pack(anchor='w')
traversal_check = tk.Checkbutton(root, text="Directory Traversal", variable=traversal_var)
traversal_check.pack(anchor='w')

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=10)

results_box = scrolledtext.ScrolledText(root, height=15, width=80)
results_box.pack()

root.mainloop()
