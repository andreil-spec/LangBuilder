#!/usr/bin/env python3
"""Production RBAC Load Testing Framework.

This module provides comprehensive load testing for RBAC components in production
environment, focusing on performance, scalability, and security under load.
"""

import asyncio
import json
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

import aiohttp
import psutil
from loguru import logger


@dataclass
class LoadTestResult:
    """Load test result data structure."""

    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_response_time: float
    p95_response_time: float
    p99_response_time: float
    requests_per_second: float
    error_rate: float
    memory_usage_mb: float
    cpu_usage_percent: float
    start_time: datetime
    end_time: datetime
    errors: List[str]


class ProductionRBACLoadTester:
    """Production-grade RBAC load testing framework."""

    def __init__(self, base_url: str = "http://localhost:7860", max_concurrent: int = 50):
        self.base_url = base_url
        self.max_concurrent = max_concurrent
        self.session: Optional[aiohttp.ClientSession] = None
        self.test_results: List[LoadTestResult] = []

        # Test users and tokens (these should be configured for production)
        self.test_tokens = []
        self.workspace_ids = []
        self.project_ids = []

    async def setup_session(self):
        """Setup HTTP session with proper configuration."""
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent * 2,
            limit_per_host=self.max_concurrent,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "LangFlow-LoadTest/1.0"
            }
        )

    async def cleanup_session(self):
        """Cleanup HTTP session."""
        if self.session:
            await self.session.close()

    async def authenticate_test_user(self, username: str, password: str) -> Optional[str]:
        """Authenticate test user and return access token."""
        try:
            async with self.session.post(
                f"{self.base_url}/api/v1/login",
                json={"username": username, "password": password}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("access_token")
                else:
                    logger.error(f"Authentication failed: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    async def make_authenticated_request(self, method: str, endpoint: str, token: str, **kwargs) -> Dict:
        """Make authenticated request with token."""
        headers = {"Authorization": f"Bearer {token}"}
        if "headers" in kwargs:
            kwargs["headers"].update(headers)
        else:
            kwargs["headers"] = headers

        try:
            start_time = time.time()
            async with self.session.request(method, f"{self.base_url}{endpoint}", **kwargs) as response:
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # milliseconds

                try:
                    data = await response.json()
                except:
                    data = await response.text()

                return {
                    "status": response.status,
                    "response_time": response_time,
                    "data": data,
                    "success": 200 <= response.status < 400
                }
        except Exception as e:
            return {
                "status": 0,
                "response_time": 0,
                "data": str(e),
                "success": False,
                "error": str(e)
            }

    async def load_test_workspace_listing(self, num_requests: int = 1000, concurrent_users: int = 20) -> LoadTestResult:
        """Load test workspace listing endpoint."""
        test_name = "Workspace Listing"
        logger.info(f"Starting {test_name} load test: {num_requests} requests, {concurrent_users} concurrent users")

        start_time = datetime.now(timezone.utc)
        start_memory = psutil.virtual_memory().used / 1024 / 1024  # MB
        start_cpu = psutil.cpu_percent(interval=1)

        results = []
        errors = []

        # Create semaphore for concurrent requests
        semaphore = asyncio.Semaphore(concurrent_users)

        async def single_request(token: str):
            async with semaphore:
                result = await self.make_authenticated_request(
                    "GET", "/api/v1/rbac/workspaces/", token
                )
                results.append(result)
                if not result["success"]:
                    errors.append(f"Status {result['status']}: {result.get('error', 'Unknown error')}")
                return result

        # Generate test requests
        tasks = []
        for i in range(num_requests):
            # Rotate through available tokens
            token = self.test_tokens[i % len(self.test_tokens)] if self.test_tokens else "dummy-token"
            tasks.append(single_request(token))

        # Execute all requests
        await asyncio.gather(*tasks)

        end_time = datetime.now(timezone.utc)
        end_memory = psutil.virtual_memory().used / 1024 / 1024  # MB
        end_cpu = psutil.cpu_percent(interval=1)

        # Calculate metrics
        successful_requests = sum(1 for r in results if r["success"])
        failed_requests = len(results) - successful_requests
        response_times = [r["response_time"] for r in results if r["response_time"] > 0]

        duration = (end_time - start_time).total_seconds()
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else 0
        requests_per_second = len(results) / duration if duration > 0 else 0
        error_rate = (failed_requests / len(results)) * 100 if results else 0

        return LoadTestResult(
            test_name=test_name,
            total_requests=len(results),
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=(end_cpu + start_cpu) / 2,
            start_time=start_time,
            end_time=end_time,
            errors=errors[:10]  # Keep only first 10 errors
        )

    async def load_test_permission_checking(self, num_requests: int = 2000, concurrent_users: int = 30) -> LoadTestResult:
        """Load test permission checking endpoints."""
        test_name = "Permission Checking"
        logger.info(f"Starting {test_name} load test: {num_requests} requests, {concurrent_users} concurrent users")

        start_time = datetime.now(timezone.utc)
        start_memory = psutil.virtual_memory().used / 1024 / 1024
        start_cpu = psutil.cpu_percent(interval=1)

        results = []
        errors = []

        semaphore = asyncio.Semaphore(concurrent_users)

        async def single_permission_check(token: str, workspace_id: str):
            async with semaphore:
                # Test different permission check endpoints
                endpoints = [
                    f"/api/v1/rbac/workspaces/{workspace_id}/projects",
                    f"/api/v1/rbac/permissions/",
                    f"/api/v1/rbac/roles/",
                ]

                endpoint = endpoints[hash(token) % len(endpoints)]
                result = await self.make_authenticated_request("GET", endpoint, token)
                results.append(result)
                if not result["success"]:
                    errors.append(f"Endpoint {endpoint} - Status {result['status']}: {result.get('error', 'Unknown')}")
                return result

        # Generate test requests
        tasks = []
        for i in range(num_requests):
            token = self.test_tokens[i % len(self.test_tokens)] if self.test_tokens else "dummy-token"
            workspace_id = self.workspace_ids[i % len(self.workspace_ids)] if self.workspace_ids else str(uuid4())
            tasks.append(single_permission_check(token, workspace_id))

        await asyncio.gather(*tasks)

        end_time = datetime.now(timezone.utc)
        end_memory = psutil.virtual_memory().used / 1024 / 1024
        end_cpu = psutil.cpu_percent(interval=1)

        # Calculate metrics
        successful_requests = sum(1 for r in results if r["success"])
        failed_requests = len(results) - successful_requests
        response_times = [r["response_time"] for r in results if r["response_time"] > 0]

        duration = (end_time - start_time).total_seconds()
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else 0
        requests_per_second = len(results) / duration if duration > 0 else 0
        error_rate = (failed_requests / len(results)) * 100 if results else 0

        return LoadTestResult(
            test_name=test_name,
            total_requests=len(results),
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=(end_cpu + start_cpu) / 2,
            start_time=start_time,
            end_time=end_time,
            errors=errors[:10]
        )

    async def load_test_flow_access(self, num_requests: int = 1500, concurrent_users: int = 25) -> LoadTestResult:
        """Load test flow access endpoints with RBAC security."""
        test_name = "Flow Access with RBAC"
        logger.info(f"Starting {test_name} load test: {num_requests} requests, {concurrent_users} concurrent users")

        start_time = datetime.now(timezone.utc)
        start_memory = psutil.virtual_memory().used / 1024 / 1024
        start_cpu = psutil.cpu_percent(interval=1)

        results = []
        errors = []

        semaphore = asyncio.Semaphore(concurrent_users)

        async def single_flow_request(token: str):
            async with semaphore:
                # Test flow-related endpoints
                endpoints = [
                    "/api/v1/flows/",
                    "/api/v1/folders/",
                    "/api/v1/flows/?components_only=true",
                ]

                endpoint = endpoints[hash(token) % len(endpoints)]
                result = await self.make_authenticated_request("GET", endpoint, token)
                results.append(result)
                if not result["success"]:
                    errors.append(f"Flow endpoint {endpoint} - Status {result['status']}: {result.get('error', 'Unknown')}")
                return result

        # Generate test requests
        tasks = []
        for i in range(num_requests):
            token = self.test_tokens[i % len(self.test_tokens)] if self.test_tokens else "dummy-token"
            tasks.append(single_flow_request(token))

        await asyncio.gather(*tasks)

        end_time = datetime.now(timezone.utc)
        end_memory = psutil.virtual_memory().used / 1024 / 1024
        end_cpu = psutil.cpu_percent(interval=1)

        # Calculate metrics
        successful_requests = sum(1 for r in results if r["success"])
        failed_requests = len(results) - successful_requests
        response_times = [r["response_time"] for r in results if r["response_time"] > 0]

        duration = (end_time - start_time).total_seconds()
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else 0
        requests_per_second = len(results) / duration if duration > 0 else 0
        error_rate = (failed_requests / len(results)) * 100 if results else 0

        return LoadTestResult(
            test_name=test_name,
            total_requests=len(results),
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=(end_cpu + start_cpu) / 2,
            start_time=start_time,
            end_time=end_time,
            errors=errors[:10]
        )

    async def run_comprehensive_load_test(self) -> Dict:
        """Run comprehensive load test suite."""
        logger.info("🚀 Starting Comprehensive Production RBAC Load Test...")
        logger.info("=" * 80)

        await self.setup_session()

        try:
            # Initialize test data (in production, these would be real test accounts)
            self.test_tokens = ["token1", "token2", "token3", "token4", "token5"]  # Dummy tokens for simulation
            self.workspace_ids = [str(uuid4()) for _ in range(5)]
            self.project_ids = [str(uuid4()) for _ in range(10)]

            # Run load tests sequentially to avoid resource conflicts
            tests = [
                ("workspace_listing", self.load_test_workspace_listing, {"num_requests": 500, "concurrent_users": 10}),
                ("permission_checking", self.load_test_permission_checking, {"num_requests": 800, "concurrent_users": 15}),
                ("flow_access", self.load_test_flow_access, {"num_requests": 600, "concurrent_users": 12}),
            ]

            results = {}
            for test_name, test_func, params in tests:
                logger.info(f"\n📊 Running {test_name} load test...")
                result = await test_func(**params)
                results[test_name] = result
                self.test_results.append(result)

                # Brief pause between tests
                await asyncio.sleep(2)

            # Generate comprehensive report
            self.generate_load_test_report()

            return results

        finally:
            await self.cleanup_session()

    def generate_load_test_report(self):
        """Generate comprehensive load test report."""
        print("\n" + "=" * 80)
        print("📊 PRODUCTION RBAC LOAD TEST REPORT")
        print("=" * 80)

        total_requests = sum(r.total_requests for r in self.test_results)
        total_successful = sum(r.successful_requests for r in self.test_results)
        total_failed = sum(r.failed_requests for r in self.test_results)
        overall_success_rate = (total_successful / total_requests) * 100 if total_requests > 0 else 0

        print(f"\n📈 OVERALL SUMMARY:")
        print(f"   Total Requests: {total_requests:,}")
        print(f"   Successful: {total_successful:,} ({overall_success_rate:.1f}%)")
        print(f"   Failed: {total_failed:,}")

        if self.test_results:
            avg_rps = statistics.mean([r.requests_per_second for r in self.test_results])
            avg_response_time = statistics.mean([r.average_response_time for r in self.test_results])
            print(f"   Average RPS: {avg_rps:.1f}")
            print(f"   Average Response Time: {avg_response_time:.1f}ms")

        print(f"\n🔍 DETAILED TEST RESULTS:")
        print("-" * 80)

        for result in self.test_results:
            status_icon = "✅" if result.error_rate < 5 else "⚠️" if result.error_rate < 15 else "❌"

            print(f"\n{status_icon} {result.test_name}:")
            print(f"   Requests: {result.total_requests:,} (Success: {result.successful_requests:,}, Failed: {result.failed_requests:,})")
            print(f"   Success Rate: {100 - result.error_rate:.1f}%")
            print(f"   RPS: {result.requests_per_second:.1f}")
            print(f"   Response Times: Avg {result.average_response_time:.1f}ms, P95 {result.p95_response_time:.1f}ms, P99 {result.p99_response_time:.1f}ms")
            print(f"   Resource Usage: CPU {result.cpu_usage_percent:.1f}%, Memory {result.memory_usage_mb:+.1f}MB")
            print(f"   Duration: {(result.end_time - result.start_time).total_seconds():.1f}s")

            if result.errors:
                print(f"   Sample Errors: {result.errors[:3]}")

        # Performance assessment
        print(f"\n🎯 PERFORMANCE ASSESSMENT:")
        print("-" * 40)

        if overall_success_rate >= 95:
            assessment = "✅ EXCELLENT"
            message = "System performs excellently under load!"
        elif overall_success_rate >= 90:
            assessment = "⚠️ GOOD"
            message = "System performs well with minor issues under load."
        elif overall_success_rate >= 80:
            assessment = "⚠️ NEEDS IMPROVEMENT"
            message = "System shows performance issues under load."
        else:
            assessment = "❌ POOR"
            message = "System fails significantly under load - requires optimization!"

        print(f"Overall Status: {assessment}")
        print(f"Assessment: {message}")

        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        print("-" * 40)

        high_error_tests = [r for r in self.test_results if r.error_rate > 10]
        slow_tests = [r for r in self.test_results if r.average_response_time > 1000]

        if high_error_tests:
            print(f"🔴 High Error Rate Issues:")
            for test in high_error_tests:
                print(f"   - {test.test_name}: {test.error_rate:.1f}% error rate")

        if slow_tests:
            print(f"🟡 Performance Issues:")
            for test in slow_tests:
                print(f"   - {test.test_name}: {test.average_response_time:.1f}ms avg response time")

        if not high_error_tests and not slow_tests:
            print("✅ No critical issues detected - system performs well under load!")

        print("\n" + "=" * 80)

    def save_results_to_file(self, filename: str = "load_test_results.json"):
        """Save load test results to JSON file."""
        results_data = []
        for result in self.test_results:
            results_data.append({
                "test_name": result.test_name,
                "total_requests": result.total_requests,
                "successful_requests": result.successful_requests,
                "failed_requests": result.failed_requests,
                "average_response_time": result.average_response_time,
                "p95_response_time": result.p95_response_time,
                "p99_response_time": result.p99_response_time,
                "requests_per_second": result.requests_per_second,
                "error_rate": result.error_rate,
                "memory_usage_mb": result.memory_usage_mb,
                "cpu_usage_percent": result.cpu_usage_percent,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat(),
                "errors": result.errors
            })

        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)

        logger.info(f"Load test results saved to {filename}")


async def main():
    """Run production load test."""
    # Configure for your production environment
    tester = ProductionRBACLoadTester(
        base_url="http://localhost:7860",  # Update for production
        max_concurrent=50
    )

    try:
        results = await tester.run_comprehensive_load_test()
        tester.save_results_to_file("production_load_test_results.json")

        # Return overall success
        total_requests = sum(r.total_requests for r in tester.test_results)
        total_successful = sum(r.successful_requests for r in tester.test_results)
        success_rate = (total_successful / total_requests) * 100 if total_requests > 0 else 0

        return success_rate >= 90  # 90% success rate threshold

    except Exception as e:
        logger.error(f"Load test failed: {e}")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
