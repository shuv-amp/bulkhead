#!/usr/bin/env python3
"""
Colosseum Copilot Standalone CLI
─────────────────────────────────
Query 5,400+ Solana hackathon projects, 84,000+ curated crypto archives,
and hackathon analytics directly from terminal without Claude Code.

Usage:
  python3 scripts/copilot.py "circuit breaker"                  # Search projects
  python3 scripts/copilot.py --archives "rate limit"            # Search archives
  python3 scripts/copilot.py --project sentinel                 # Get project details
  python3 scripts/copilot.py --status                           # Check auth & status
"""

import sys
import os
import json
import urllib.request
import argparse
from pathlib import Path

# Load .env
env_file = Path(__file__).resolve().parent.parent / ".env"
env_vars = {}
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip('"').strip("'")

API_BASE = os.getenv("COLOSSEUM_COPILOT_API_BASE", env_vars.get("COLOSSEUM_COPILOT_API_BASE", "https://copilot.colosseum.com/api/v1"))
PAT = os.getenv("COLOSSEUM_COPILOT_PAT", env_vars.get("COLOSSEUM_COPILOT_PAT"))

if not PAT:
    print("❌ Error: COLOSSEUM_COPILOT_PAT is missing from .env or environment.")
    print("Generate your PAT at: https://colosseum.com/arena/copilot")
    sys.exit(1)


def api_request(endpoint: str, method: str = "GET", data: dict = None):
    url = f"{API_BASE}{endpoint}"
    headers = {
        "Authorization": f"Bearer {PAT}",
        "Content-Type": "application/json",
        "User-Agent": "Bulkhead-Copilot-CLI"
    }
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        print(f"❌ HTTP Error {e.code}: {err}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Request failed: {e}")
        sys.exit(1)


def check_status():
    res = api_request("/status")
    print("\n🟢 Colosseum Copilot Authentication Status:")
    print(json.dumps(res, indent=2))


def search_projects(query: str, limit: int = 5):
    res = api_request("/search/projects", method="POST", data={"query": query, "limit": limit})
    print(f"\n🔎 Projects matching '{query}' (Found {res.get('totalFound', 0)}):\n" + "─" * 60)
    projects = res.get("results", []) if isinstance(res, dict) else res
    if not projects:
        print("No matching projects found.")
        return
    for idx, p in enumerate(projects, 1):
        name = p.get("name", p.get("title", "Unknown"))
        slug = p.get("slug", "")
        desc = p.get("tagline", p.get("description", p.get("summary", "")))
        hackathon = p.get("hackathon", {}).get("name", "") if isinstance(p.get("hackathon"), dict) else p.get("hackathon", "")
        print(f"{idx}. {name} ({slug}) [{hackathon}]")
        if desc:
            print(f"   {desc}")
        print()


def search_archives(query: str, limit: int = 5):
    res = api_request("/search/archives", method="POST", data={"query": query, "limit": limit})
    print(f"\n📚 Archive docs matching '{query}' (Found {res.get('totalFound', 0)}):\n" + "─" * 60)
    archives = res.get("results", []) if isinstance(res, dict) else res
    if not archives:
        print("No matching archive documents found.")
        return
    for idx, a in enumerate(archives, 1):
        title = a.get("title", "Untitled")
        src = a.get("source", a.get("author", ""))
        snippet = a.get("snippet", a.get("excerpt", a.get("content", "")))
        print(f"{idx}. {title} [{src}]")
        if snippet:
            print(f"   {snippet[:160]}...")
        print()


def get_project(slug: str):
    res = api_request(f"/projects/by-slug/{slug}")
    print(f"\n📋 Project Details: {slug}\n" + "─" * 60)
    print(json.dumps(res, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Colosseum Copilot Standalone CLI")
    parser.add_argument("query", nargs="?", help="Search query for projects")
    parser.add_argument("--archives", "-a", help="Search curated crypto archives")
    parser.add_argument("--project", "-p", help="Get project details by slug")
    parser.add_argument("--status", "-s", action="store_true", help="Check auth & status")
    parser.add_argument("--limit", "-l", type=int, default=5, help="Number of results (default: 5)")

    args = parser.parse_args()

    if args.status or (not args.query and not args.archives and not args.project):
        check_status()
        if not args.query and not args.archives and not args.project:
            print("\nTip: Run `python3 scripts/copilot.py 'circuit breaker'` to search hackathon projects.")
        return

    if args.archives:
        search_archives(args.archives, args.limit)
    elif args.project:
        get_project(args.project)
    elif args.query:
        search_projects(args.query, args.limit)


if __name__ == "__main__":
    main()
