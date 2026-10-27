import asyncio
import json
import statistics
import sys
import time
from typing import Dict, List, Any
import httpx


TARGET_BASE_URL = "http://localhost:3000"


class StressBenchmark:
    def __init__(self, base_url: str = TARGET_BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.auth_token: str = ""

    async def login_admin(self) -> str:
        """Authenticate as admin to acquire a valid Bearer token."""
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10.0) as client:
            res = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
            if res.status_code != 200:
                raise RuntimeError(f"Admin login failed: {res.status_code} {res.text}")
            self.auth_token = res.json()["access_token"]
            return self.auth_token

    async def benchmark_endpoint(
        self,
        name: str,
        method: str,
        path: str,
        concurrency: int,
        total_requests: int,
        json_body: Dict[str, Any] = None,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        headers = {}
        if use_auth and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        sem = asyncio.Semaphore(concurrency)
        latencies_ms: List[float] = []
        status_codes: Dict[int, int] = {}
        error_count = 0

        limits = httpx.Limits(max_keepalive_connections=concurrency * 2, max_connections=concurrency * 4)

        async with httpx.AsyncClient(base_url=self.base_url, timeout=30.0, limits=limits) as client:
            async def worker():
                nonlocal error_count
                async with sem:
                    t0 = time.perf_counter()
                    try:
                        if method.upper() == "GET":
                            resp = await client.get(path, headers=headers)
                        elif method.upper() == "POST":
                            resp = await client.post(path, headers=headers, json=json_body)
                        else:
                            raise ValueError(f"Unsupported method: {method}")
                        
                        latency = (time.perf_counter() - t0) * 1000.0
                        latencies_ms.append(latency)
                        status_codes[resp.status_code] = status_codes.get(resp.status_code, 0) + 1
                        if resp.status_code >= 400:
                            error_count += 1
                    except Exception as e:
                        latency = (time.perf_counter() - t0) * 1000.0
                        latencies_ms.append(latency)
                        error_count += 1
                        status_codes[599] = status_codes.get(599, 0) + 1

            start_time = time.perf_counter()
            tasks = [asyncio.create_task(worker()) for _ in range(total_requests)]
            await asyncio.gather(*tasks)
            total_duration = time.perf_counter() - start_time

        rps = total_requests / total_duration if total_duration > 0 else 0
        sorted_latencies = sorted(latencies_ms) if latencies_ms else [0]
        n = len(sorted_latencies)

        p50 = sorted_latencies[int(n * 0.50)] if n else 0
        p95 = sorted_latencies[min(int(n * 0.95), n - 1)] if n else 0
        p99 = sorted_latencies[min(int(n * 0.99), n - 1)] if n else 0
        mean = statistics.mean(sorted_latencies) if sorted_latencies else 0

        return {
            "endpoint": name,
            "method": method,
            "path": path,
            "concurrency": concurrency,
            "total_requests": total_requests,
            "duration_sec": round(total_duration, 2),
            "rps": round(rps, 1),
            "mean_ms": round(mean, 1),
            "p50_ms": round(p50, 1),
            "p95_ms": round(p95, 1),
            "p99_ms": round(p99, 1),
            "errors": error_count,
            "error_rate_pct": round((error_count / total_requests) * 100.0, 2),
            "status_distribution": status_codes,
        }


async def run_tiered_stress_suite(base_url: str = TARGET_BASE_URL):
    bench = StressBenchmark(base_url=base_url)
    print(f"\n=======================================================")
    print(f"🚀 Risk Alert Dashboard: Concurrency Stress Test Suite")
    print(f"Target: {base_url}")
    print(f"=======================================================\n")

    print("[*] Authenticating admin user...")
    await bench.login_admin()
    print("    Authenticated successfully.")

    endpoints = [
        ("Dashboard Summary", "GET", "/api/v1/dashboard/summary", None, True),
        ("Paginated Assets (50/p)", "GET", "/api/v1/assets?page=1&page_size=50", None, True),
        ("Alerts Feed (50/p)", "GET", "/api/v1/alerts?page=1&page_size=50", None, True),
        ("Threat Intel Feed", "GET", "/api/v1/misp/feed?page=1&page_size=50", None, True),
    ]

    tiers = [
        ("Tier 1: Baseline Load", 10, 100),
        ("Tier 2: Peak Concurrency", 50, 250),
        ("Tier 3: Stress / Saturation", 100, 500),
    ]

    all_results = []

    for tier_name, concurrency, requests_per_endpoint in tiers:
        print(f"\n-------------------------------------------------------")
        print(f"▶ {tier_name} ({concurrency} concurrent workers, {requests_per_endpoint} reqs/ep)")
        print(f"-------------------------------------------------------")

        for name, method, path, body, auth in endpoints:
            print(f"  Testing {name} ...", end="", flush=True)
            res = await bench.benchmark_endpoint(
                name=name,
                method=method,
                path=path,
                concurrency=concurrency,
                total_requests=requests_per_endpoint,
                json_body=body,
                use_auth=auth,
            )
            all_results.append({**res, "tier": tier_name})
            print(f" Done! RPS: {res['rps']} | p50: {res['p50_ms']}ms | p95: {res['p95_ms']}ms | Errors: {res['errors']} ({res['error_rate_pct']}%)")

    # Output JSON summary
    summary_path = "/tmp/stress_test_results.json"
    with open(summary_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[+] Full benchmark results saved to: {summary_path}")
    return all_results


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_BASE_URL
    asyncio.run(run_tiered_stress_suite(target))
