#!/usr/bin/env python3
"""
Base POC Framework for Vulhub Vulnerability Verification

This module provides a standardized base class for all vulnerability POCs,
including common functionality for:
- Target environment detection
- HTTP request handling with retry logic
- Vulnerability exploitation
- Result verification and reporting
- Logging and error handling

Usage:
    class MyPOC(BasePOC):
        def check_vulnerability(self):
            # Implement detection logic
            pass
        
        def exploit(self):
            # Implement exploitation logic
            pass
        
        def verify(self):
            # Implement verification logic
            pass
"""

import sys
import time
import logging
import argparse
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from enum import Enum


class VulnerabilityStatus(Enum):
    """Vulnerability verification status"""
    UNKNOWN = "unknown"
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"


@dataclass
class POCResult:
    """Standardized POC execution result"""
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN
    target: str = ""
    vulnerability_name: str = ""
    cve_id: str = ""
    details: str = ""
    evidence: str = ""
    exploit_output: str = ""
    error: str = ""
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "target": self.target,
            "vulnerability_name": self.vulnerability_name,
            "cve_id": self.cve_id,
            "details": self.details,
            "evidence": self.evidence,
            "exploit_output": self.exploit_output,
            "error": self.error,
            "timestamp": self.timestamp
        }
    
    def __str__(self) -> str:
        status_icon = {
            VulnerabilityStatus.VULNERABLE: "[+]",
            VulnerabilityStatus.NOT_VULNERABLE: "[-]",
            VulnerabilityStatus.ERROR: "[!]",
            VulnerabilityStatus.UNKNOWN: "[?]"
        }.get(self.status, "[?]")
        
        lines = [
            f"{status_icon} {self.vulnerability_name} ({self.cve_id})",
            f"    Target: {self.target}",
            f"    Status: {self.status.value}",
            f"    Details: {self.details}"
        ]
        if self.evidence:
            lines.append(f"    Evidence: {self.evidence}")
        if self.exploit_output:
            lines.append(f"    Output: {self.exploit_output}")
        if self.error:
            lines.append(f"    Error: {self.error}")
        return "\n".join(lines)


class BasePOC(ABC):
    """
    Abstract base class for all vulnerability POCs.
    
    Subclasses must implement:
    - check_vulnerability(): Detect if target is vulnerable
    - exploit(): Execute the exploit
    - verify(): Verify exploit success
    
    Optional overrides:
    - get_default_ports(): Default ports to check
    - get_headers(): Custom headers
    - get_timeout(): Request timeout
    """
    
    # Vulnerability metadata (must be set by subclass)
    VULN_NAME: str = ""
    CVE_ID: str = ""
    AFFECTED_VERSIONS: str = ""
    VULN_TYPE: str = ""
    DESCRIPTION: str = ""
    REFERENCES: List[str] = []
    
    # Default configuration
    DEFAULT_TIMEOUT: int = 10
    DEFAULT_PORTS: List[int] = [80, 443, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011, 9012, 9013, 9014, 9015, 9016, 9017, 9018, 9019, 9020, 9021, 9022, 9023, 9024, 9025, 9026, 9027, 9028, 9029, 9030, 9031, 9032, 9033, 9034, 9035, 9036, 9037, 9038, 9039, 9040, 9041, 9042, 9043, 9044, 9045, 9046, 9047, 9048, 9049, 9050, 9051, 9052, 9053, 9054, 9055, 9056, 9057, 9058, 9059, 9060, 9061, 9062, 9063, 9064, 9065, 9066, 9067, 9068, 9069, 9070, 9071, 9072, 9073, 9074, 9075, 9076, 9077, 9078, 9079, 9080, 9081, 9082, 9083, 9084, 9085, 9086, 9087, 9088, 9089, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9108, 9109, 9110, 9111, 9112, 9113, 9114, 9115, 9116, 9117, 9118, 9119, 9120, 9121, 9122, 9123, 9124, 9125, 9126, 9127, 9128, 9129, 9130, 9131, 9132, 9133, 9134, 9135, 9136, 9137, 9138, 9139, 9140, 9141, 9142, 9143, 9144, 9145, 9146, 9147, 9148, 9149, 9150, 9151, 9152, 9153, 9154, 9155, 9156, 9157, 9158, 9159, 9160, 9161, 9162, 9163, 9164, 9165, 9166, 9167, 9168, 9169, 9170, 9171, 9172, 9173, 9174, 9176, 9177, 9178, 9179, 9180, 9181, 9182, 9183, 9184, 9185, 9186, 9187, 9188, 9189, 9190, 9191, 9192, 9193, 9194, 9195, 9196, 9197, 9198, 9199, 9200]
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 1.0
    
    def __init__(
        self,
        target: str,
        timeout: int = None,
        proxy: str = None,
        verify_ssl: bool = False,
        headers: Dict[str, str] = None,
        logger: logging.Logger = None
    ):
        """
        Initialize POC with target configuration.
        
        Args:
            target: Target URL (e.g., http://example.com:8080)
            timeout: Request timeout in seconds
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            verify_ssl: Whether to verify SSL certificates
            headers: Custom HTTP headers
            logger: Custom logger instance
        """
        self.target = target.rstrip('/')
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.custom_headers = headers or {}
        self.logger = logger or self._setup_logger()
        self.session = self._create_session()
        self.result = POCResult(
            target=self.target,
            vulnerability_name=self.VULN_NAME,
            cve_id=self.CVE_ID
        )
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logger for this POC"""
        logger = logging.getLogger(f"poc.{self.VULN_NAME}")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        
        # Default headers
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        default_headers.update(self.custom_headers)
        session.headers.update(default_headers)
        
        # Disable SSL warnings if not verifying
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        return session
    
    def request(
        self,
        method: str,
        path: str = "/",
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Make HTTP request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: URL path to append to target
            **kwargs: Additional arguments passed to requests.request()
            
        Returns:
            Response object or None on failure
        """
        url = urljoin(self.target, path)
        
        for attempt in range(self.MAX_RETRIES):
            try:
                self.logger.debug(f"[{attempt+1}/{self.MAX_RETRIES}] {method} {url}")
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    timeout=self.timeout,
                    **kwargs
                )
                return resp
            except requests.exceptions.Timeout:
                self.logger.warning(f"Request timeout (attempt {attempt+1}/{self.MAX_RETRIES})")
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Connection error (attempt {attempt+1}/{self.MAX_RETRIES}): {e}")
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {e}")
                break
            
            if attempt < self.MAX_RETRIES - 1:
                time.sleep(self.RETRY_DELAY * (attempt + 1))
        
        return None
    
    def get(self, path: str = "/", **kwargs) -> Optional[requests.Response]:
        """Convenience method for GET requests"""
        return self.request("GET", path, **kwargs)
    
    def post(self, path: str = "/", **kwargs) -> Optional[requests.Response]:
        """Convenience method for POST requests"""
        return self.request("POST", path, **kwargs)
    
    def put(self, path: str = "/", **kwargs) -> Optional[requests.Response]:
        """Convenience method for PUT requests"""
        return self.request("PUT", path, **kwargs)
    
    def delete(self, path: str = "/", **kwargs) -> Optional[requests.Response]:
        """Convenience method for DELETE requests"""
        return self.request("DELETE", path, **kwargs)
    
    def check_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a TCP port is open"""
        import socket
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
    
    def parse_target(self) -> Tuple[str, int, bool]:
        """Parse target URL into host, port, and SSL flag"""
        parsed = urlparse(self.target if self.target.startswith(('http://', 'https://')) else f"http://{self.target}")
        host = parsed.hostname or parsed.path
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        is_ssl = parsed.scheme == 'https'
        return host, port, is_ssl
    
    @abstractmethod
    def check_vulnerability(self) -> POCResult:
        """
        Check if the target is vulnerable.
        
        Returns:
            POCResult with status and details
        """
        pass
    
    @abstractmethod
    def exploit(self, command: str = "id") -> POCResult:
        """
        Execute the vulnerability exploit.
        
        Args:
            command: Command to execute on target
            
        Returns:
            POCResult with exploit output
        """
        pass
    
    @abstractmethod
    def verify(self, exploit_result: POCResult) -> bool:
        """
        Verify if exploit was successful.
        
        Args:
            exploit_result: Result from exploit()
            
        Returns:
            True if exploit successful, False otherwise
        """
        pass
    
    def run(self, command: str = "id") -> POCResult:
        """
        Run full POC workflow: check -> exploit -> verify.
        
        Args:
            command: Command to execute during exploit
            
        Returns:
            Final POCResult
        """
        self.logger.info(f"Starting POC for {self.VULN_NAME} ({self.CVE_ID})")
        self.logger.info(f"Target: {self.target}")
        
        # Step 1: Check vulnerability
        self.logger.info("Step 1: Checking vulnerability...")
        check_result = self.check_vulnerability()
        
        if check_result.status != VulnerabilityStatus.VULNERABLE:
            self.logger.info(f"Target not vulnerable: {check_result.details}")
            return check_result
        
        self.logger.info("Target appears vulnerable, proceeding to exploit...")
        
        # Step 2: Exploit
        self.logger.info("Step 2: Executing exploit...")
        exploit_result = self.exploit(command)
        
        # Step 3: Verify
        self.logger.info("Step 3: Verifying exploit...")
        if self.verify(exploit_result):
            exploit_result.status = VulnerabilityStatus.VULNERABLE
            self.logger.info("Exploit verified successfully!")
        else:
            exploit_result.status = VulnerabilityStatus.NOT_VULNERABLE
            self.logger.warning("Exploit verification failed")
        
        self.result = exploit_result
        return exploit_result
    
    def print_result(self):
        """Print formatted result"""
        print(str(self.result))
    
    def get_result_dict(self) -> Dict[str, Any]:
        """Get result as dictionary"""
        return self.result.to_dict()


def create_argument_parser(poc_class: type) -> argparse.ArgumentParser:
    """Create standard argument parser for POC"""
    parser = argparse.ArgumentParser(
        description=f"{poc_class.VULN_NAME} ({poc_class.CVE_ID}) POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python {poc_class.__name__.lower()}.py http://target:8080
  python {poc_class.__name__.lower()}.py http://target:8080 --command "whoami"
  python {poc_class.__name__.lower()}.py http://target:8080 --proxy http://127.0.0.1:8080 --timeout 30
        """
    )
    
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://example.com:8080)"
    )
    parser.add_argument(
        "-c", "--command",
        default="id",
        help="Command to execute (default: id)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=poc_class.DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {poc_class.DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "-p", "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "-k", "--insecure",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only check vulnerability, don't exploit"
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    return parser


def run_poc_from_cli(poc_class: type):
    """Run POC from command line arguments"""
    parser = create_argument_parser(poc_class)
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create POC instance
    poc = poc_class(
        target=args.target,
        timeout=args.timeout,
        proxy=args.proxy,
        verify_ssl=not args.insecure
    )
    
    # Run check or full exploit
    if args.check_only:
        result = poc.check_vulnerability()
    else:
        result = poc.run(args.command)
    
    # Output result
    if args.output == "json":
        import json
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result)
    
    # Exit code based on result
    if result.status == VulnerabilityStatus.VULNERABLE:
        sys.exit(0)
    elif result.status == VulnerabilityStatus.NOT_VULNERABLE:
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    # Example usage
    print("Base POC Framework - Import this module in your POC scripts")
    print("Example:")
    print("  from base_poc import BasePOC, run_poc_from_cli")
    print("  class MyPOC(BasePOC): ...")
    print("  if __name__ == '__main__': run_poc_from_cli(MyPOC)")