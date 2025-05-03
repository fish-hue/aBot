# cli_scanner.py - CLI entry point for modular scanner
import asyncio
import argparse
import aiohttp
import os
from scanner import run_scans

async def main():
    parser = argparse.ArgumentParser(description="Async Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--headers", help="Custom headers in 'Key: Value' format separated by '\n'")
    parser.add_argument("--cookies", help="Cookies in 'key=value; key2=value2' format")
    parser.add_argument("--sql", action="store_true", help="Enable SQL injection scan")
    parser.add_argument("--xss", action="store_true", help="Enable XSS scan")
    parser.add_argument("--cmdi", action="store_true", help="Enable Command Injection scan")
    parser.add_argument("--redirect", action="store_true", help="Enable Open Redirect scan")
    parser.add_argument("--traversal", action="store_true", help="Enable Directory Traversal scan")

    args = parser.parse_args()

    proxy = args.proxy or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""

    def print_results(results):
        for r in results:
            print(r)

    await run_scans(
        args.url,
        args.headers or "",
        args.cookies or "",
        proxy,
        args.sql,
        args.xss,
        args.cmdi,
        args.redirect,
        args.traversal,
        print_results
    )

if __name__ == "__main__":
    asyncio.run(main())
