import asyncio
import nmap
import socket
import ssl
import subprocess
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
from sqlalchemy.orm import Session
from celery import shared_task
import logging

from models.models import Asset, Vulnerability, SecurityScan, ScanResult, AlertSeverity, ScanStatus
from core.database import get_db
from services.alert_service import AlertService
from services.notification_service import NotificationService

logger = logging.getLogger(__name__)

class SecurityScanner:
    """
    Comprehensive security scanning service for vulnerability assessment,
    port scanning, SSL certificate validation, and compliance checking.
    """
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.alert_service = AlertService()
        self.notification_service = NotificationService()
        self.is_running = False
        self.scan_tasks = []
        
    async def start_continuous_scanning(self):
        """Start continuous background scanning"""
        self.is_running = True
        logger.info("Starting continuous security scanning service")
        
        while self.is_running:
            try:
                # Run different scan types on different schedules
                await asyncio.gather(
                    self._scheduled_vulnerability_scan(),
                    self._scheduled_port_scan(),
                    self._scheduled_ssl_check(),
                    return_exceptions=True
                )
                
                # Wait before next scan cycle (6 hours)
                await asyncio.sleep(21600)
                
            except Exception as e:
                logger.error(f"Error in continuous scanning: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
    
    async def shutdown(self):
        """Gracefully shutdown the scanner"""
        logger.info("Shutting down security scanner")
        self.is_running = False
        
        # Cancel all running scan tasks
        for task in self.scan_tasks:
            if not task.done():
                task.cancel()
        
        if self.scan_tasks:
            await asyncio.gather(*self.scan_tasks, return_exceptions=True)
    
    def get_status(self) -> str:
        """Get current scanner status"""
        active_scans = sum(1 for task in self.scan_tasks if not task.done())
        return f"running ({active_scans} active scans)" if self.is_running else "stopped"
    
    async def trigger_scan(self, scan_type: str, targets: List[str], initiated_by: int) -> str:
        """
        Trigger a manual security scan
        
        Args:
            scan_type: Type of scan (vulnerability, compliance, full)
            targets: List of targets to scan
            initiated_by: User ID who initiated the scan
            
        Returns:
            Scan ID
        """
        db = next(get_db())
        
        # Create scan record
        scan = SecurityScan(
            scan_type=scan_type,
            status=ScanStatus.PENDING,
            targets=targets,
            initiated_by_id=initiated_by
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Start async scan task
        if scan_type == "vulnerability":
            task = asyncio.create_task(self._run_vulnerability_scan(scan.id, targets))
        elif scan_type == "compliance":
            task = asyncio.create_task(self._run_compliance_scan(scan.id, targets))
        else:  # full scan
            task = asyncio.create_task(self._run_full_scan(scan.id, targets))
        
        self.scan_tasks.append(task)
        
        return scan.uid
    
    async def _run_vulnerability_scan(self, scan_id: int, targets: List[str]):
        """Run vulnerability scan on specified targets"""
        db = next(get_db())
        scan = db.query(SecurityScan).filter(SecurityScan.id == scan_id).first()
        
        try:
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            db.commit()
            
            total_vulns = 0
            critical_vulns = 0
            
            for i, target in enumerate(targets):
                # Update progress
                scan.progress = int((i / len(targets)) * 100)
                db.commit()
                
                # Get or create asset
                asset = self._get_or_create_asset(db, target)
                
                # Run various vulnerability checks
                vulns = []
                
                # Port scan for common vulnerable services
                port_vulns = await self._scan_ports_for_vulnerabilities(target)
                vulns.extend(port_vulns)
                
                # Check for outdated SSL/TLS
                ssl_vulns = await self._check_ssl_vulnerabilities(target)
                vulns.extend(ssl_vulns)
                
                # Check for common web vulnerabilities
                if self._is_web_target(target):
                    web_vulns = await self._scan_web_vulnerabilities(target)
                    vulns.extend(web_vulns)
                
                # Save vulnerabilities
                for vuln_data in vulns:
                    vuln = Vulnerability(
                        asset_id=asset.id,
                        scan_id=scan_id,
                        **vuln_data
                    )
                    db.add(vuln)
                    
                    total_vulns += 1
                    if vuln_data.get('severity') == AlertSeverity.CRITICAL:
                        critical_vulns += 1
                
                # Create scan result
                result = ScanResult(
                    scan_id=scan_id,
                    asset_id=asset.id,
                    result_type='vulnerability',
                    findings={'vulnerabilities': vulns},
                    score=self._calculate_vulnerability_score(vulns)
                )
                db.add(result)
            
            # Update scan completion
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.progress = 100
            scan.results_summary = {
                'total_vulnerabilities': total_vulns,
                'critical': critical_vulns,
                'targets_scanned': len(targets)
            }
            db.commit()
            
            # Send notifications if critical vulnerabilities found
            if critical_vulns > 0:
                await self.notification_service.send_critical_vulnerability_alert(
                    scan_id=scan.uid,
                    critical_count=critical_vulns
                )
            
        except Exception as e:
            logger.error(f"Error in vulnerability scan {scan_id}: {e}")
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            db.commit()
    
    async def _scan_ports_for_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """Scan ports and identify potential vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Common vulnerable ports to check
            vulnerable_ports = {
                21: ("FTP", "Unencrypted FTP service"),
                23: ("Telnet", "Unencrypted Telnet service"),
                445: ("SMB", "Exposed SMB service"),
                1433: ("MSSQL", "Exposed MS SQL Server"),
                3306: ("MySQL", "Exposed MySQL database"),
                3389: ("RDP", "Exposed Remote Desktop"),
                5432: ("PostgreSQL", "Exposed PostgreSQL database"),
                5900: ("VNC", "Exposed VNC service"),
                6379: ("Redis", "Exposed Redis server"),
                9200: ("Elasticsearch", "Exposed Elasticsearch"),
                27017: ("MongoDB", "Exposed MongoDB")
            }
            
            # Quick port scan
            for port, (service, description) in vulnerable_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:  # Port is open
                    vulnerabilities.append({
                        'title': f'Open {service} Port ({port})',
                        'description': f'{description} on port {port}',
                        'severity': AlertSeverity.HIGH if port in [445, 3389] else AlertSeverity.MEDIUM,
                        'cve_id': None,
                        'cvss_score': 7.5 if port in [445, 3389] else 5.0,
                        'references': [f'https://www.speedguide.net/port.php?port={port}']
                    })
            
        except Exception as e:
            logger.error(f"Error scanning ports for {target}: {e}")
        
        return vulnerabilities
    
    async def _check_ssl_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """Check for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check HTTPS port
            context = ssl.create_default_context()
            
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.utcnow()).days
                    
                    if days_until_expiry < 30:
                        vulnerabilities.append({
                            'title': 'SSL Certificate Expiring Soon',
                            'description': f'SSL certificate expires in {days_until_expiry} days',
                            'severity': AlertSeverity.HIGH if days_until_expiry < 7 else AlertSeverity.MEDIUM,
                            'cvss_score': 4.0,
                            'references': ['https://www.ssl.com/faqs/what-happens-when-an-ssl-certificate-expires/']
                        })
                    
                    # Check for weak TLS versions
                    if version in ['TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'title': 'Outdated TLS Version',
                            'description': f'Server supports {version} which is deprecated',
                            'severity': AlertSeverity.HIGH,
                            'cve_id': 'CVE-2014-3566',  # POODLE
                            'cvss_score': 6.8,
                            'references': ['https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/']
                        })
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                    if cipher and any(weak in cipher[0] for weak in weak_ciphers):
                        vulnerabilities.append({
                            'title': 'Weak SSL Cipher Suite',
                            'description': f'Server supports weak cipher: {cipher[0]}',
                            'severity': AlertSeverity.MEDIUM,
                            'cvss_score': 5.3,
                            'references': ['https://www.acunetix.com/vulnerabilities/web/weak-ssl-cipher-suites/']
                        })
                        
        except socket.timeout:
            logger.info(f"No HTTPS service on {target}")
        except Exception as e:
            logger.error(f"Error checking SSL for {target}: {e}")
        
        return vulnerabilities
    
    async def _scan_web_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """Scan for common web application vulnerabilities"""
        vulnerabilities = []
        
        try:
            base_url = f"http://{target}" if not target.startswith('http') else target
            
            async with aiohttp.ClientSession() as session:
                # Check security headers
                async with session.get(base_url, timeout=10) as response:
                    headers = response.headers
                    
                    # Check for missing security headers
                    security_headers = {
                        'X-Frame-Options': ('Missing X-Frame-Options Header', 'Clickjacking'),
                        'X-Content-Type-Options': ('Missing X-Content-Type-Options Header', 'MIME Sniffing'),
                        'X-XSS-Protection': ('Missing X-XSS-Protection Header', 'XSS Attacks'),
                        'Strict-Transport-Security': ('Missing HSTS Header', 'Protocol Downgrade Attacks'),
                        'Content-Security-Policy': ('Missing CSP Header', 'XSS and Injection Attacks')
                    }
                    
                    for header, (title, risk) in security_headers.items():
                        if header not in headers:
                            vulnerabilities.append({
                                'title': title,
                                'description': f'The application is missing {header} header, making it vulnerable to {risk}',
                                'severity': AlertSeverity.MEDIUM,
                                'cvss_score': 4.3,
                                'references': [f'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}']
                            })
                    
                    # Check for server information disclosure
                    if 'Server' in headers:
                        server_info = headers['Server']
                        if any(version in server_info.lower() for version in ['apache/', 'nginx/', 'iis/']):
                            vulnerabilities.append({
                                'title': 'Server Version Disclosure',
                                'description': f'Server header reveals version information: {server_info}',
                                'severity': AlertSeverity.LOW,
                                'cvss_score': 2.5,
                                'references': ['https://www.acunetix.com/vulnerabilities/web/server-version-disclosure/']
                            })
                
                # Check for common vulnerable paths
                vulnerable_paths = [
                    ('/.git/config', 'Git Repository Exposed'),
                    ('/.env', 'Environment File Exposed'),
                    ('/wp-admin/', 'WordPress Admin Panel'),
                    ('/phpmyadmin/', 'phpMyAdmin Interface'),
                    ('/.svn/', 'SVN Repository Exposed')
                ]
                
                for path, issue in vulnerable_paths:
                    try:
                        async with session.get(base_url + path, timeout=5) as resp:
                            if resp.status == 200:
                                vulnerabilities.append({
                                    'title': issue,
                                    'description': f'Sensitive path {path} is publicly accessible',
                                    'severity': AlertSeverity.HIGH,
                                    'cvss_score': 7.5,
                                    'references': ['https://owasp.org/www-project-top-ten/']
                                })
                    except:
                        pass
                        
        except Exception as e:
            logger.error(f"Error scanning web vulnerabilities for {target}: {e}")
        
        return vulnerabilities
    
    def _calculate_vulnerability_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall vulnerability score (0-100, where 100 is most secure)"""
        if not vulnerabilities:
            return 100.0
        
        severity_weights = {
            AlertSeverity.CRITICAL: 25,
            AlertSeverity.HIGH: 15,
            AlertSeverity.MEDIUM: 8,
            AlertSeverity.LOW: 3,
            AlertSeverity.INFO: 1
        }
        
        total_penalty = sum(
            severity_weights.get(vuln.get('severity', AlertSeverity.LOW), 3)
            for vuln in vulnerabilities
        )
        
        # Cap the penalty at 100
        score = max(0, 100 - min(total_penalty, 100))
        return round(score, 2)
    
    def _get_or_create_asset(self, db: Session, target: str) -> Asset:
        """Get existing asset or create new one"""
        # Try to find by IP or hostname
        asset = db.query(Asset).filter(
            (Asset.ip_address == target) | (Asset.hostname == target)
        ).first()
        
        if not asset:
            # Determine asset type
            from models.models import AssetType
            asset_type = AssetType.SERVER  # Default
            
            asset = Asset(
                name=target,
                asset_type=asset_type,
                ip_address=target if self._is_ip(target) else None,
                hostname=target if not self._is_ip(target) else None,
                is_monitored=True
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
        
        return asset
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except:
            return False
    
    def _is_web_target(self, target: str) -> bool:
        """Check if target is likely a web application"""
        if target.startswith(('http://', 'https://')):
            return True
        
        # Check if port 80 or 443 is open
        for port in [80, 443]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return True
        
        return False
    
    async def _scheduled_vulnerability_scan(self):
        """Run scheduled vulnerability scan on all monitored assets"""
        logger.info("Starting scheduled vulnerability scan")
        
        db = next(get_db())
        monitored_assets = db.query(Asset).filter(Asset.is_monitored == True).all()
        
        if monitored_assets:
            targets = []
            for asset in monitored_assets:
                if asset.ip_address:
                    targets.append(asset.ip_address)
                elif asset.hostname:
                    targets.append(asset.hostname)
            
            if targets:
                await self.trigger_scan('vulnerability', targets[:50], initiated_by=1)  # System user
    
    async def _scheduled_port_scan(self):
        """Run scheduled port scan"""
        logger.info("Starting scheduled port scan")
        # Implementation for scheduled port scanning
        pass
    
    async def _scheduled_ssl_check(self):
        """Run scheduled SSL certificate check"""
        logger.info("Starting scheduled SSL check")
        # Implementation for scheduled SSL checking
        pass
    
    async def _run_compliance_scan(self, scan_id: int, targets: List[str]):
        """Run compliance scan"""
        logger.info(f"Running compliance scan {scan_id}")
        # Implementation for compliance scanning
        pass
    
    async def _run_full_scan(self, scan_id: int, targets: List[str]):
        """Run full comprehensive scan"""
        logger.info(f"Running full scan {scan_id}")
        # Run all scan types
        await self._run_vulnerability_scan(scan_id, targets)
        await self._run_compliance_scan(scan_id, targets)

# Celery tasks for async scanning
@shared_task
def run_vulnerability_scan_task(scan_id: int, targets: List[str]):
    """Celery task for running vulnerability scan"""
    scanner = SecurityScanner()
    asyncio.run(scanner._run_vulnerability_scan(scan_id, targets))