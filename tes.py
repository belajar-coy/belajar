#!/usr/bin/env python3
"""
Advanced TOR IP Rotation Tool
Professional-grade IP rotation with comprehensive monitoring and control
For authorized security testing and research purposes only
"""

import argparse
import asyncio
import json
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List
import subprocess
import time

try:
    import aiohttp
    import stem
    from stem import Signal
    from stem.control import Controller
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.layout import Layout
    from rich import box
except ImportError:
    print("Installing required dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                          "aiohttp", "stem", "rich"])
    import aiohttp
    import stem
    from stem import Signal
    from stem.control import Controller
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.layout import Layout
    from rich import box

# Configuration
CONFIG = {
    "tor_control_host": "127.0.0.1",
    "tor_control_port": 9051,
    "tor_socks_port": 9050,
    "control_password": "",
    "default_interval": 5,
    "max_retries": 3,
    "timeout": 10,
    "log_file": "tor_rotation.log"
}

# Global state
console = Console()
stats = {
    "total_rotations": 0,
    "successful_rotations": 0,
    "failed_rotations": 0,
    "unique_ips": set(),
    "start_time": None,
    "current_ip": None,
    "current_location": {},
    "last_rotation": None
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG["log_file"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class TorRotator:
    """Advanced TOR IP Rotation Manager"""
    
    def __init__(self, interval: int = 5, max_rotations: int = 0, 
                 password: str = "", country_codes: List[str] = None):
        self.interval = interval
        self.max_rotations = max_rotations
        self.password = password
        self.country_codes = country_codes
        self.running = False
        self.controller = None
        self.session = None
        
    async def __aenter__(self):
        await self.initialize()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
        
    async def initialize(self):
        """Initialize TOR connection and session"""
        try:
            # Connect to TOR control port
            self.controller = Controller.from_port(
                address=CONFIG["tor_control_host"],
                port=CONFIG["tor_control_port"]
            )
            self.controller.authenticate(password=self.password)
            
            # Create aiohttp session with TOR proxy
            connector = aiohttp.TCPConnector()
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])
            )
            
            console.print("[green]✓[/green] Connected to TOR network")
            logger.info("TOR connection initialized successfully")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to connect to TOR: {e}")
            logger.error(f"TOR initialization failed: {e}")
            raise
            
    async def cleanup(self):
        """Cleanup connections"""
        if self.session:
            await self.session.close()
        if self.controller:
            self.controller.close()
        console.print("[yellow]![/yellow] Cleaned up connections")
        
    async def get_ip_info(self) -> Optional[Dict]:
        """Fetch current IP and geolocation info"""
        try:
            proxy = f"socks5://127.0.0.1:{CONFIG['tor_socks_port']}"
            
            # Get IP address
            async with self.session.get(
                "https://api.ipify.org?format=json",
                proxy=proxy
            ) as response:
                ip_data = await response.json()
                ip = ip_data.get("ip")
                
            if not ip:
                return None
                
            # Get geolocation
            async with self.session.get(
                f"http://ip-api.com/json/{ip}",
                proxy=proxy
            ) as response:
                geo_data = await response.json()
                
            return {
                "ip": ip,
                "country": geo_data.get("country", "Unknown"),
                "region": geo_data.get("regionName", "Unknown"),
                "city": geo_data.get("city", "Unknown"),
                "isp": geo_data.get("isp", "Unknown"),
                "lat": geo_data.get("lat", 0),
                "lon": geo_data.get("lon", 0),
                "timezone": geo_data.get("timezone", "Unknown")
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch IP info: {e}")
            return None
            
    async def rotate_ip(self) -> bool:
        """Rotate to new TOR identity"""
        try:
            # Send NEWNYM signal
            self.controller.signal(Signal.NEWNYM)
            
            # Wait for new circuit
            await asyncio.sleep(2)
            
            stats["total_rotations"] += 1
            stats["last_rotation"] = datetime.now()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate IP: {e}")
            stats["failed_rotations"] += 1
            return False
            
    def create_dashboard(self) -> Layout:
        """Create rich dashboard layout"""
        layout = Layout()
        
        # Header
        header = Panel(
            "[bold cyan]🔄 Advanced TOR IP Rotation Tool[/bold cyan]\n"
            "[dim]Professional-grade IP rotation for authorized testing[/dim]",
            box=box.DOUBLE,
            style="cyan"
        )
        
        # Stats table
        stats_table = Table(box=box.ROUNDED, show_header=False)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        runtime = (datetime.now() - stats["start_time"]).total_seconds() if stats["start_time"] else 0
        success_rate = (stats["successful_rotations"] / stats["total_rotations"] * 100) if stats["total_rotations"] > 0 else 0
        
        stats_table.add_row("🔄 Total Rotations", str(stats["total_rotations"]))
        stats_table.add_row("✓ Successful", str(stats["successful_rotations"]))
        stats_table.add_row("✗ Failed", str(stats["failed_rotations"]))
        stats_table.add_row("📊 Success Rate", f"{success_rate:.1f}%")
        stats_table.add_row("🌐 Unique IPs", str(len(stats["unique_ips"])))
        stats_table.add_row("⏱️ Runtime", f"{runtime:.0f}s")
        
        # Current IP info
        ip_table = Table(box=box.ROUNDED, show_header=False)
        ip_table.add_column("Field", style="cyan")
        ip_table.add_column("Value", style="yellow")
        
        if stats["current_ip"]:
            ip_table.add_row("IP Address", stats["current_ip"])
            ip_table.add_row("Country", stats["current_location"].get("country", "N/A"))
            ip_table.add_row("Region", stats["current_location"].get("region", "N/A"))
            ip_table.add_row("City", stats["current_location"].get("city", "N/A"))
            ip_table.add_row("ISP", stats["current_location"].get("isp", "N/A"))
            ip_table.add_row("Timezone", stats["current_location"].get("timezone", "N/A"))
        else:
            ip_table.add_row("Status", "Fetching...")
            
        layout.split_column(
            Layout(header, size=5),
            Layout(Panel(stats_table, title="📊 Statistics", border_style="green")),
            Layout(Panel(ip_table, title="🌍 Current Identity", border_style="yellow"))
        )
        
        return layout
        
    async def run(self):
        """Main rotation loop"""
        self.running = True
        stats["start_time"] = datetime.now()
        rotation_count = 0
        
        console.print(Panel.fit(
            "[bold green]Starting IP Rotation[/bold green]\n"
            f"Interval: {self.interval}s | "
            f"Max Rotations: {'∞' if self.max_rotations == 0 else self.max_rotations}",
            border_style="green"
        ))
        
        with Live(self.create_dashboard(), refresh_per_second=1, console=console) as live:
            while self.running:
                try:
                    # Rotate IP
                    if await self.rotate_ip():
                        # Get new IP info
                        ip_info = await self.get_ip_info()
                        
                        if ip_info:
                            stats["successful_rotations"] += 1
                            stats["current_ip"] = ip_info["ip"]
                            stats["current_location"] = ip_info
                            stats["unique_ips"].add(ip_info["ip"])
                            
                            logger.info(f"Rotated to {ip_info['ip']} - {ip_info['city']}, {ip_info['country']}")
                        else:
                            stats["failed_rotations"] += 1
                            logger.warning("Failed to fetch new IP info")
                    
                    # Update dashboard
                    live.update(self.create_dashboard())
                    
                    rotation_count += 1
                    
                    # Check if max rotations reached
                    if self.max_rotations > 0 and rotation_count >= self.max_rotations:
                        console.print("\n[green]✓[/green] Max rotations reached")
                        break
                        
                    # Wait for next rotation
                    await asyncio.sleep(self.interval)
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error in rotation loop: {e}")
                    stats["failed_rotations"] += 1
                    await asyncio.sleep(self.interval)
                    
        self.running = False
        
        # Print final summary
        self.print_summary()
        
    def print_summary(self):
        """Print final summary"""
        console.print("\n")
        summary = Table(title="📊 Rotation Summary", box=box.DOUBLE_EDGE, style="cyan")
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="green", justify="right")
        
        runtime = (datetime.now() - stats["start_time"]).total_seconds()
        success_rate = (stats["successful_rotations"] / stats["total_rotations"] * 100) if stats["total_rotations"] > 0 else 0
        
        summary.add_row("Total Rotations", str(stats["total_rotations"]))
        summary.add_row("Successful Rotations", str(stats["successful_rotations"]))
        summary.add_row("Failed Rotations", str(stats["failed_rotations"]))
        summary.add_row("Success Rate", f"{success_rate:.2f}%")
        summary.add_row("Unique IPs Obtained", str(len(stats["unique_ips"])))
        summary.add_row("Total Runtime", f"{runtime:.2f}s")
        summary.add_row("Avg Rotation Time", f"{runtime/stats['total_rotations']:.2f}s" if stats['total_rotations'] > 0 else "N/A")
        
        console.print(summary)
        console.print(f"\n[dim]Log file: {CONFIG['log_file']}[/dim]")


def check_tor_service():
    """Check if TOR service is running"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "tor"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False


def print_banner():
    """Print tool banner"""
    banner = """
[bold cyan]
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔄 ADVANCED TOR IP ROTATION TOOL 🔄                    ║
║                                                           ║
║   Professional-grade IP rotation system                  ║
║   For authorized security testing only                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
[/bold cyan]

[yellow]⚠️  LEGAL NOTICE:[/yellow]
This tool is intended for authorized security testing,
penetration testing with proper authorization, and research
purposes only. Unauthorized use may violate laws.

[dim]Configure your applications to use SOCKS5 proxy: 127.0.0.1:9050[/dim]
"""
    console.print(banner)


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Advanced TOR IP Rotation Tool for authorized testing"
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=5,
        help="Interval between rotations in seconds (default: 5)"
    )
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=0,
        help="Number of rotations (0 for infinite, default: 0)"
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        default="",
        help="TOR control port password (if set)"
    )
    parser.add_argument(
        "-c", "--countries",
        type=str,
        nargs="+",
        help="Preferred country codes (e.g., US GB DE)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check TOR service status and exit"
    )
    
    args = parser.parse_args()
    
    # Check TOR service
    if args.check:
        if check_tor_service():
            console.print("[green]✓[/green] TOR service is running")
            sys.exit(0)
        else:
            console.print("[red]✗[/red] TOR service is not running")
            console.print("[yellow]Start TOR with:[/yellow] sudo systemctl start tor")
            sys.exit(1)
    
    # Print banner
    print_banner()
    
    # Check if TOR is running
    if not check_tor_service():
        console.print("[red]✗[/red] TOR service is not running!")
        console.print("[yellow]Start TOR with:[/yellow] sudo systemctl start tor")
        sys.exit(1)
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        console.print("\n[yellow]![/yellow] Received interrupt signal, stopping...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run rotation
    async with TorRotator(
        interval=args.interval,
        max_rotations=args.number,
        password=args.password,
        country_codes=args.countries
    ) as rotator:
        await rotator.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        logger.exception("Fatal error occurred")
        sys.exit(1)
