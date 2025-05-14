#!/usr/bin/env python3
import os
import sys
import re
import hashlib
import platform
import requests
import subprocess
from typing import Dict, List, Tuple, Set
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Back, Style
import shutil
import tempfile
import json
import concurrent.futures

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class HostsManager:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.hosts_path = self._get_hosts_path()
        self.config_dir = self._get_config_dir()
        self.backup_dir = self.config_dir / 'backups'
        self.whitelist_path = self.config_dir / 'whitelist'
        self.blacklist_path = self.config_dir / 'blacklist'
        
        # Create required directories
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.whitelist_path.parent.mkdir(parents=True, exist_ok=True)
        self.blacklist_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize whitelist/blacklist files if they don't exist
        if not self.whitelist_path.exists():
            self.whitelist_path.write_text("")
        if not self.blacklist_path.exists():
            self.blacklist_path.write_text("")
        
        # Clear screen on start
        self.clear_screen()
        
        self.base_url = "https://raw.githubusercontent.com/StevenBlack/hosts/master"
        self.hosts_categories = {
            '1': ('Unified hosts (adware + malware)', f'{self.base_url}/hosts'),
            '2': ('Unified hosts + fakenews', f'{self.base_url}/alternates/fakenews/hosts'),
            '3': ('Unified hosts + gambling', f'{self.base_url}/alternates/gambling/hosts'),
            '4': ('Unified hosts + porn', f'{self.base_url}/alternates/porn/hosts'),
            '5': ('Unified hosts + social', f'{self.base_url}/alternates/social/hosts'),
            '6': ('Unified hosts + fakenews + gambling', f'{self.base_url}/alternates/fakenews-gambling/hosts'),
            '7': ('Unified hosts + fakenews + porn', f'{self.base_url}/alternates/fakenews-porn/hosts'),
            '8': ('Unified hosts + fakenews + social', f'{self.base_url}/alternates/fakenews-social/hosts'),
            '9': ('Unified hosts + gambling + porn', f'{self.base_url}/alternates/gambling-porn/hosts'),
            '10': ('Unified hosts + gambling + social', f'{self.base_url}/alternates/gambling-social/hosts'),
            '11': ('Unified hosts + porn + social', f'{self.base_url}/alternates/porn-social/hosts'),
            '12': ('Unified hosts + fakenews + gambling + porn', f'{self.base_url}/alternates/fakenews-gambling-porn/hosts'),
            '13': ('Unified hosts + fakenews + gambling + social', f'{self.base_url}/alternates/fakenews-gambling-social/hosts'),
            '14': ('Unified hosts + fakenews + porn + social', f'{self.base_url}/alternates/fakenews-porn-social/hosts'),
            '15': ('Unified hosts + gambling + porn + social', f'{self.base_url}/alternates/gambling-porn-social/hosts'),
            '16': ('Unified hosts + ALL', f'{self.base_url}/alternates/fakenews-gambling-porn-social/hosts')
        }

    def _get_config_dir(self) -> Path:
        """Get the appropriate configuration directory based on the operating system."""
        if self.os_type == 'windows':
            return Path(os.getenv('LOCALAPPDATA')) / 'HostsManager'
        return Path.home() / '.hostsmanager'

    def clear_screen(self):
        """Clear the console screen based on the operating system."""
        if self.os_type == 'windows':
            os.system('cls')
        else:  # Linux and macOS
            os.system('clear')

    def _get_hosts_path(self) -> str:
        """Get the appropriate hosts file path based on the operating system."""
        if self.os_type == 'windows':
            return r'C:\Windows\System32\drivers\etc\hosts'
        return '/etc/hosts'

    def get_domain_count(self, hosts_content: str) -> int:
        """Count unique domains in hosts file content."""
        pattern = re.compile(r'^\s*\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9])', re.MULTILINE)
        domains = set(pattern.findall(hosts_content))
        return len(domains)

    def get_current_hosts_hash(self) -> str:
        """Get MD5 hash of current hosts file."""
        with open(self.hosts_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def check_for_updates(self, current_choice: str) -> bool:
        """Check if a newer version of the hosts file is available."""
        if current_choice not in self.hosts_categories:
            return False
        
        try:
            _, url = self.hosts_categories[current_choice]
            response = requests.head(url)
            online_etag = response.headers.get('etag', '').strip('"')
            
            if not online_etag:
                return False
                
            current_hash = self.get_current_hosts_hash()
            return online_etag != current_hash
        except Exception:
            return False

    def load_whitelist(self) -> Set[str]:
        """Load whitelisted domains."""
        try:
            return set(self.whitelist_path.read_text().splitlines())
        except Exception:
            return set()

    def load_blacklist(self) -> Set[str]:
        """Load blacklisted domains."""
        try:
            return set(self.blacklist_path.read_text().splitlines())
        except Exception:
            return set()

    def apply_whitelist_blacklist(self, hosts_content: str) -> str:
        """Apply whitelist and blacklist to hosts content."""
        whitelist = self.load_whitelist()
        blacklist = self.load_blacklist()
        
        # Split content into lines and filter
        lines = hosts_content.splitlines()
        filtered_lines = []
        
        for line in lines:
            if line.strip() and not line.strip().startswith('#'):
                # Extract domain from hosts line
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
                    if domain in whitelist:
                        continue
                    if domain in blacklist and not any(domain in l for l in filtered_lines):
                        filtered_lines.append(f"0.0.0.0 {domain}")
            filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)

    def manage_whitelist_blacklist(self):
        """Manage whitelist and blacklist entries."""
        while True:
            self.clear_screen()
            print(f"\n{Style.BRIGHT}{Fore.CYAN}=== Whitelist/Blacklist Manager ===")
            print(f"\n{Fore.WHITE}Current Lists:")
            
            whitelist = self.load_whitelist()
            blacklist = self.load_blacklist()
            
            print(f"\n{Fore.GREEN}Whitelist ({len(whitelist)} domains):")
            for domain in sorted(whitelist):
                print(f"  {domain}")
            
            print(f"\n{Fore.RED}Blacklist ({len(blacklist)} domains):")
            for domain in sorted(blacklist):
                print(f"  {domain}")
            
            print(f"\n{Fore.YELLOW}Options:")
            print("1. Add domain to whitelist")
            print("2. Remove domain from whitelist")
            print("3. Add domain to blacklist")
            print("4. Remove domain from blacklist")
            print("5. Import whitelist from file")
            print("6. Import blacklist from file")
            print("b. Back to main menu")
            
            choice = input(f"\n{Fore.CYAN}Enter choice: {Style.RESET_ALL}").lower()
            
            if choice == 'b':
                break
            elif choice in ['1', '2', '3', '4']:
                domain = input("Enter domain (e.g., example.com): ").strip().lower()
                if not domain:
                    continue
                
                if choice == '1':
                    whitelist.add(domain)
                    self.whitelist_path.write_text('\n'.join(sorted(whitelist)))
                elif choice == '2':
                    whitelist.discard(domain)
                    self.whitelist_path.write_text('\n'.join(sorted(whitelist)))
                elif choice == '3':
                    blacklist.add(domain)
                    self.blacklist_path.write_text('\n'.join(sorted(blacklist)))
                elif choice == '4':
                    blacklist.discard(domain)
                    self.blacklist_path.write_text('\n'.join(sorted(blacklist)))
            elif choice in ['5', '6']:
                path = input("Enter path to import file: ").strip()
                try:
                    with open(path, 'r') as f:
                        domains = set(line.strip().lower() for line in f if line.strip())
                    if choice == '5':
                        whitelist.update(domains)
                        self.whitelist_path.write_text('\n'.join(sorted(whitelist)))
                    else:
                        blacklist.update(domains)
                        self.blacklist_path.write_text('\n'.join(sorted(blacklist)))
                except Exception as e:
                    print(f"{Fore.RED}Error importing file: {e}")
                    input("Press Enter to continue...")

    def create_backup(self) -> None:
        """Create a backup of the current hosts file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = self.backup_dir / f'hosts_backup_{timestamp}'
        shutil.copy2(self.hosts_path, backup_path)
        print(f"{Fore.GREEN}✓ Backup created at: {backup_path}")

    def manage_backups(self) -> None:
        """Manage hosts file backups."""
        while True:
            self.clear_screen()
            print(f"\n{Style.BRIGHT}{Fore.CYAN}=== Backup Manager ===")
            
            backups = sorted(self.backup_dir.glob('hosts_backup_*'))
            
            if not backups:
                print(f"\n{Fore.YELLOW}No backups found.")
            else:
                print(f"\n{Fore.WHITE}Available backups:")
                for i, backup in enumerate(backups, 1):
                    timestamp = backup.name.replace('hosts_backup_', '')
                    size = backup.stat().st_size / 1024  # Size in KB
                    print(f"{i}. {timestamp} ({size:.1f} KB)")
            
            print(f"\n{Fore.YELLOW}Options:")
            print("c. Create new backup")
            print("r. Restore backup")
            print("d. Delete backup")
            print("b. Back to main menu")
            
            choice = input(f"\n{Fore.CYAN}Enter choice: {Style.RESET_ALL}").lower()
            
            if choice == 'b':
                break
            elif choice == 'c':
                self.create_backup()
            elif choice == 'r' and backups:
                try:
                    index = int(input("Enter backup number to restore: ")) - 1
                    if 0 <= index < len(backups):
                        self.restore_backup(backups[index])
                    else:
                        print(f"{Fore.RED}Invalid backup number!")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number!")
            elif choice == 'd' and backups:
                try:
                    index = int(input("Enter backup number to delete: ")) - 1
                    if 0 <= index < len(backups):
                        backups[index].unlink()
                        print(f"{Fore.GREEN}Backup deleted successfully!")
                    else:
                        print(f"{Fore.RED}Invalid backup number!")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number!")
            
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

    def restore_backup(self, backup_path: Path) -> None:
        """Restore a specific backup."""
        try:
            # Create a backup of current hosts file before restoring
            self.create_backup()
            
            # Restore the selected backup
            shutil.copy2(backup_path, self.hosts_path)
            print(f"{Fore.GREEN}✓ Restored backup from: {backup_path}")
            
            # Flush DNS cache
            self.flush_dns_cache()
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to restore backup: {e}")

    def display_menu(self) -> None:
        """Display the main menu with available hosts file options."""
        print(f"\n{Style.BRIGHT}{Fore.CYAN}=== Hosts File Manager ===")
        print(f"{Fore.YELLOW}Current OS: {platform.system()}")
        print(f"Hosts file location: {self.hosts_path}\n")

        # Display table header
        print(f"{Style.BRIGHT}{Fore.WHITE}{'Option':<8} {'Description':<50} {'Domains':<10}")
        print("-" * 68)

        # Display options
        for key, (desc, _) in self.hosts_categories.items():
            print(f"{Fore.GREEN}{key:<8} {Fore.WHITE}{desc:<50}")

        print(f"\n{Fore.YELLOW}Additional Options:")
        print(f"{Fore.GREEN}b{Fore.WHITE} - Restore latest backup")
        print(f"{Fore.GREEN}c{Fore.WHITE} - Create backup of current hosts file")
        print(f"{Fore.GREEN}w{Fore.WHITE} - Manage whitelist/blacklist")
        print(f"{Fore.GREEN}m{Fore.WHITE} - Manage backups")
        print(f"{Fore.GREEN}s{Fore.WHITE} - Show current statistics")
        print(f"{Fore.GREEN}q{Fore.WHITE} - Quit")

    def show_statistics(self) -> None:
        """Display current hosts file statistics."""
        try:
            current_content = Path(self.hosts_path).read_text()
            domains = self.get_domain_count(current_content)
            whitelist = len(self.load_whitelist())
            blacklist = len(self.load_blacklist())
            backups = len(list(self.backup_dir.glob('hosts_backup_*')))
            
            print(f"\n{Style.BRIGHT}{Fore.CYAN}=== Current Statistics ===")
            print(f"{Fore.WHITE}Blocked Domains: {Fore.GREEN}{domains}")
            print(f"{Fore.WHITE}Whitelisted Domains: {Fore.GREEN}{whitelist}")
            print(f"{Fore.WHITE}Blacklisted Domains: {Fore.GREEN}{blacklist}")
            print(f"{Fore.WHITE}Available Backups: {Fore.GREEN}{backups}")
            
            # Show file details
            stats = os.stat(self.hosts_path)
            size_kb = stats.st_size / 1024
            modified = datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"\n{Fore.WHITE}Hosts File Details:")
            print(f"Size: {size_kb:.1f} KB")
            print(f"Last Modified: {modified}")
            
            # Check for updates
            update_available = self.check_for_updates(self._get_current_category())
            if update_available:
                print(f"\n{Fore.YELLOW}Note: Updates are available!")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error getting statistics: {e}")

    def _get_current_category(self) -> str:
        """Try to determine current hosts file category."""
        try:
            current_content = Path(self.hosts_path).read_text()
            current_hash = hashlib.md5(current_content.encode()).hexdigest()
            
            for key, (_, url) in self.hosts_categories.items():
                try:
                    response = requests.get(url, timeout=5)
                    if hashlib.md5(response.content).hexdigest() == current_hash:
                        return key
                except:
                    continue
        except:
            pass
        return ""

    def update_hosts(self, choice: str) -> None:
        """Update the hosts file with the selected category."""
        # Handle backup option
        if choice == 'c':
            self.create_backup()
            print(f"\n{Fore.GREEN}Backup created in: {self.backup_dir}")
            return
        elif choice == 'w':
            self.manage_whitelist_blacklist()
            return
        elif choice == 'm':
            self.manage_backups()
            return
        elif choice == 's':
            self.show_statistics()
            return
            
        if choice not in self.hosts_categories:
            print(f"{Fore.RED}✗ Invalid choice!")
            return

        desc, url = self.hosts_categories[choice]
        print(f"\n{Fore.YELLOW}Downloading {desc}...")

        try:
            # Download new hosts file
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content = response.text
            
            # Apply whitelist and blacklist
            content = self.apply_whitelist_blacklist(content)
            
            # Create backup before modifying
            self.create_backup()

            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name

            # Copy temporary file to hosts location with proper permissions
            if self.os_type == 'windows':
                # For Windows, we need to use specific commands
                subprocess.run(['takeown', '/F', self.hosts_path], check=True)
                subprocess.run(['icacls', self.hosts_path, '/grant', 'administrators:F'], check=True)
                shutil.copy2(temp_path, self.hosts_path)
            else:
                # For Unix-like systems
                shutil.copy2(temp_path, self.hosts_path)
                os.chmod(self.hosts_path, 0o644)

            # Clean up
            os.unlink(temp_path)
            
            print(f"{Fore.GREEN}✓ Hosts file updated successfully!")
            
            # Flush DNS cache based on OS
            self.flush_dns_cache()

        except Exception as e:
            print(f"{Fore.RED}✗ Error updating hosts file: {e}")

    def flush_dns_cache(self) -> None:
        """Flush the DNS cache based on the operating system."""
        try:
            if self.os_type == 'windows':
                subprocess.run(['ipconfig', '/flushdns'], check=True)
            elif self.os_type == 'darwin':  # macOS
                subprocess.run(['sudo', 'killall', '-HUP', 'mDNSResponder'], check=True)
                subprocess.run(['sudo', 'killall', 'mDNSResponderHelper'], check=True)
                subprocess.run(['sudo', 'dscacheutil', '-flushcache'], check=True)
            elif self.os_type == 'linux':
                # Try different service managers
                if shutil.which('systemctl'):
                    subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=True)
                elif shutil.which('service'):
                    subprocess.run(['sudo', 'service', 'network-manager', 'restart'], check=True)
                # Try nscd if available
                if shutil.which('nscd'):
                    subprocess.run(['sudo', 'nscd', '-K'], check=True)
                    subprocess.run(['sudo', 'nscd'], check=True)
            print(f"{Fore.GREEN}✓ DNS cache flushed successfully!")
        except Exception as e:
            print(f"{Fore.YELLOW}! Warning: Could not flush DNS cache: {e}")

def has_admin_privileges() -> bool:
    """Check if the script is running with administrator privileges."""
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except AttributeError:
        return False

def main():
    # Check if running with admin/root privileges
    if not has_admin_privileges():
        os_type = platform.system().lower()
        print(f"\n{Fore.RED}╔══ Error: Administrator Privileges Required ══╗")
        print(f"{Fore.RED}This script must be run with elevated privileges!")
        print(f"\n{Fore.YELLOW}Please run the script as follows for your OS:{Style.RESET_ALL}")
        
        if os_type == 'linux':
            print(f"\n{Fore.CYAN}For Linux:{Style.RESET_ALL}")
            print("Method 1: Run with sudo:")
            print("  sudo python3 hosts_manager.py")
            print("\nMethod 2: Switch to root and run:")
            print("  su -")
            print("  python3 hosts_manager.py")
            
        elif os_type == 'darwin':  # macOS
            print(f"\n{Fore.CYAN}For macOS:{Style.RESET_ALL}")
            print("Method 1: Run with sudo:")
            print("  sudo python3 hosts_manager.py")
            print("\nMethod 2: Use Terminal.app:")
            print("1. Open Terminal.app")
            print("2. Navigate to script directory:")
            print("   cd /path/to/script/directory")
            print("3. Run with sudo:")
            print("   sudo python3 hosts_manager.py")
            
        elif os_type == 'windows':
            print(f"\n{Fore.CYAN}For Windows:{Style.RESET_ALL}")
            print("Method 1: Command Prompt (Admin):")
            print("1. Right-click Command Prompt")
            print("2. Select 'Run as administrator'")
            print("3. Navigate to script directory:")
            print("   cd C:\\path\\to\\script\\directory")
            print("4. Run:")
            print("   python hosts_manager.py")
            print("\nMethod 2: PowerShell (Admin):")
            print("1. Right-click PowerShell")
            print("2. Select 'Run as administrator'")
            print("3. Navigate to script directory:")
            print("   cd C:\\path\\to\\script\\directory")
            print("4. Run:")
            print("   python hosts_manager.py")
            
        print(f"\n{Fore.YELLOW}Note: Make sure Python and required packages are installed:{Style.RESET_ALL}")
        print("pip install colorama requests")
        sys.exit(1)

    manager = HostsManager()
    
    while True:
        manager.display_menu()
        choice = input(f"\n{Fore.CYAN}Enter your choice: {Style.RESET_ALL}").lower()

        if choice == 'q':
            print(f"\n{Fore.GREEN}Goodbye!")
            break
        else:
            manager.update_hosts(choice)
        
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        manager.clear_screen()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program terminated by user.")
        sys.exit(0) 
