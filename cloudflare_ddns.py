#!/usr/bin/env python3
"""
Cloudflare DDNS Updater for Unifi UDM Pro

This script queries UniFi Controller API for device IPs (by MAC address)
and updates Cloudflare DNS records. Supports both IPv4 (A records) and IPv6 (AAAA records).

Author: Generated with Claude Code
License: MIT
"""

import sys
import os
import logging
import json
import fcntl
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List, Any

try:
    import yaml
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from cloudflare import Cloudflare
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install dependencies: pip install -r requirements.txt")
    sys.exit(1)

# Suppress SSL warnings when verify_ssl=false
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Custom Exceptions
class DDNSException(Exception):
    """Base exception for DDNS updater."""
    pass


class UniFiAPIError(DDNSException):
    """UniFi API returned an error."""
    pass


class CloudflareAPIError(DDNSException):
    """Cloudflare API returned an error."""
    pass


class ConfigurationError(DDNSException):
    """Configuration is invalid."""
    pass


# JSON Formatter for Logging
class JsonFormatter(logging.Formatter):
    """Format logs as JSON for easy parsing."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        # Add exception info if present
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, 'device'):
            log_obj['device'] = record.device
        if hasattr(record, 'mac'):
            log_obj['mac'] = record.mac
        if hasattr(record, 'record'):
            log_obj['record'] = record.record

        return json.dumps(log_obj)


# Configuration Manager
class ConfigManager:
    """Handles configuration file loading and validation."""

    def __init__(self, config_path: str = 'config.yaml'):
        self.config_path = config_path
        self.config = None

    def load_config(self) -> Dict[str, Any]:
        """Load and validate configuration file."""
        if not os.path.exists(self.config_path):
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")

        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML syntax: {e}")

        self.validate_config()
        return self.config

    def validate_config(self) -> None:
        """Validate configuration structure."""
        if not self.config:
            raise ConfigurationError("Configuration is empty")

        # Required top-level keys
        required_keys = ['unifi', 'cloudflare', 'devices']
        for key in required_keys:
            if key not in self.config:
                raise ConfigurationError(f"Missing required config key: {key}")

        # Validate UniFi section
        unifi = self.config['unifi']
        if 'host' not in unifi:
            raise ConfigurationError("Missing 'host' in unifi section")
        if 'api_key' not in unifi and ('username' not in unifi or 'password' not in unifi):
            raise ConfigurationError(
                "Must provide either 'api_key' or both 'username' and 'password' in unifi section"
            )

        # Validate Cloudflare section
        cf = self.config['cloudflare']
        if 'api_token' not in cf and 'api_token_env' not in cf:
            raise ConfigurationError("Must provide api_token or api_token_env in cloudflare section")

        # Validate devices
        if not self.config['devices']:
            raise ConfigurationError("Must configure at least one device")

        for idx, device in enumerate(self.config['devices']):
            if 'mac' not in device:
                raise ConfigurationError(f"Device at index {idx} missing 'mac' field")
            if 'records' not in device or not device['records']:
                raise ConfigurationError(f"Device with MAC '{device.get('mac', idx)}' has no records")

            # Validate each record
            for rec_idx, record in enumerate(device['records']):
                required_record_keys = ['domain', 'hostname', 'ipv4', 'ipv6']
                for key in required_record_keys:
                    if key not in record:
                        raise ConfigurationError(
                            f"Record {rec_idx} in device '{device['mac']}' missing '{key}' field"
                        )

    def get_cloudflare_api_token(self) -> str:
        """Get Cloudflare API token from config or environment."""
        cf = self.config['cloudflare']

        # Try direct token first
        if 'api_token' in cf and cf['api_token']:
            return cf['api_token']

        # Try environment variable
        if 'api_token_env' in cf:
            env_var = cf['api_token_env']
            token = os.getenv(env_var)
            if token:
                return token
            raise ConfigurationError(f"Environment variable {env_var} not set")

        raise ConfigurationError("No API token configured")


# UniFi Controller Client
class UniFiClient:
    """Handles UniFi Controller API interactions."""

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.logger = logger
        self.host = config['host']
        self.port = config.get('port', 443)
        self.site = config.get('site', 'default')
        self.verify_ssl = config.get('verify_ssl', False)

        # Authentication
        self.api_key = config.get('api_key')
        self.username = config.get('username')
        self.password = config.get('password')

        # Base URL
        self.base_url = f"https://{self.host}:{self.port}"

        # Session for API requests
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Authenticate
        self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate with UniFi Controller."""
        if self.api_key:
            # Use API key authentication
            self.session.headers.update({
                'X-API-KEY': self.api_key
            })
            self.logger.info("Authenticated with UniFi API using API key")
        else:
            # Use username/password authentication
            login_url = f"{self.base_url}/api/auth/login"
            payload = {
                'username': self.username,
                'password': self.password
            }

            try:
                response = self.session.post(login_url, json=payload)
                response.raise_for_status()
                self.logger.info("Authenticated with UniFi API using username/password")
            except requests.RequestException as e:
                raise UniFiAPIError(f"Failed to authenticate with UniFi Controller: {e}")

    def get_client_by_mac(self, mac: str) -> Optional[Dict[str, Any]]:
        """
        Get client information by MAC address.

        Args:
            mac: MAC address of the client (e.g., 'aa:bb:cc:dd:ee:ff')

        Returns:
            dict with client info including 'ip' and 'ip6' fields, or None if not found
        """
        # Normalize MAC address (lowercase, with colons)
        mac = mac.lower().replace('-', ':')

        try:
            # For UDM Pro, use /proxy/network prefix
            url = f"{self.base_url}/proxy/network/api/s/{self.site}/stat/sta"

            self.logger.debug(f"Querying UniFi API for clients at {url}")
            response = self.session.get(url)
            response.raise_for_status()

            data = response.json()

            if data.get('meta', {}).get('rc') != 'ok':
                raise UniFiAPIError(f"UniFi API returned error: {data.get('meta', {}).get('msg')}")

            clients = data.get('data', [])
            self.logger.debug(f"Found {len(clients)} total clients")

            # Find client by MAC address
            for client in clients:
                client_mac = client.get('mac', '').lower()
                if client_mac == mac:
                    self.logger.debug(f"Found client with MAC {mac}: {client.get('hostname', 'unknown')}")
                    self.logger.debug(f"Raw client data: {client}")
                    return {
                        'mac': client_mac,
                        'hostname': client.get('hostname', client.get('name', 'unknown')),
                        'ip': client.get('ip'),  # IPv4 address
                        'ip6': self._get_ipv6(client),  # IPv6 address
                        'last_seen': client.get('last_seen')
                    }

            self.logger.warning(f"Client with MAC {mac} not found in UniFi")
            return None

        except requests.RequestException as e:
            raise UniFiAPIError(f"Failed to query UniFi API: {e}")

    def _get_ipv6(self, client: Dict[str, Any]) -> Optional[str]:
        """Extract IPv6 address from client data, filtering out link-local addresses."""
        # Try different possible fields for IPv6
        ipv6_fields = ['last_ipv6', 'ipv6_addresses', 'ip6', 'ipv6_address', 'ipv6']

        for field in ipv6_fields:
            if field in client:
                ipv6 = client[field]
                if isinstance(ipv6, list) and ipv6:
                    # Take first non-link-local address
                    for addr in ipv6:
                        if not addr.startswith('fe80:'):
                            return addr
                elif isinstance(ipv6, str) and ipv6 and not ipv6.startswith('fe80:'):
                    return ipv6

        return None


# Cloudflare Client
class CloudflareClient:
    """Manages Cloudflare API interactions."""

    def __init__(self, api_token: str, logger: logging.Logger):
        self.logger = logger
        self.client = Cloudflare(api_token=api_token)
        self.zone_cache: Dict[str, str] = {}

    def get_zone_id(self, domain: str) -> str:
        """
        Get zone ID for domain, with caching.

        Args:
            domain: Domain name (e.g., 'example.com')

        Returns:
            str: Zone ID

        Raises:
            CloudflareAPIError: If zone not found or API error
        """
        if domain in self.zone_cache:
            return self.zone_cache[domain]

        try:
            self.logger.debug(f"Fetching zone ID for domain: {domain}")
            zones = self.client.zones.list(name=domain)

            if not zones.result:
                raise CloudflareAPIError(f"Zone not found: {domain}")

            zone_id = zones.result[0].id
            self.zone_cache[domain] = zone_id
            self.logger.debug(f"Cached zone ID for {domain}: {zone_id}")
            return zone_id

        except CloudflareAPIError:
            raise
        except Exception as e:
            raise CloudflareAPIError(f"Failed to get zone ID for {domain}: {e}")

    def get_dns_record(self, zone_id: str, name: str, record_type: str) -> Optional[Any]:
        """
        Get existing DNS record.

        Args:
            zone_id: Cloudflare zone ID
            name: Full hostname (e.g., 'docker00.example.com')
            record_type: Record type ('A' or 'AAAA')

        Returns:
            DNSRecord or None if not found
        """
        try:
            self.logger.debug(f"Fetching {record_type} record for {name}")
            records = self.client.dns.records.list(
                zone_id=zone_id,
                name=name,
                type=record_type
            )

            if records.result:
                return records.result[0]
            return None

        except Exception as e:
            self.logger.error(f"Failed to get DNS record {name} ({record_type}): {e}")
            return None

    def update_dns_record(
        self,
        zone_id: str,
        record_id: str,
        name: str,
        ip: str,
        record_type: str,
        ttl: int = 120
    ) -> Any:
        """
        Update existing DNS record.

        Args:
            zone_id: Cloudflare zone ID
            record_id: DNS record ID
            name: Full hostname
            ip: IP address to set
            record_type: 'A' or 'AAAA'
            ttl: TTL in seconds

        Returns:
            Updated DNSRecord

        Raises:
            CloudflareAPIError: If update fails
        """
        try:
            self.logger.info(f"Updating {record_type} record for {name} to {ip}")
            record = self.client.dns.records.update(
                dns_record_id=record_id,
                zone_id=zone_id,
                name=name,
                content=ip,
                type=record_type,
                ttl=ttl,
                proxied=False  # Don't proxy DDNS records
            )
            return record

        except Exception as e:
            raise CloudflareAPIError(f"Failed to update {record_type} record {name}: {e}")

    def create_dns_record(
        self,
        zone_id: str,
        name: str,
        ip: str,
        record_type: str,
        ttl: int = 120
    ) -> Any:
        """
        Create new DNS record.

        Args:
            zone_id: Cloudflare zone ID
            name: Full hostname
            ip: IP address to set
            record_type: 'A' or 'AAAA'
            ttl: TTL in seconds

        Returns:
            Created DNSRecord

        Raises:
            CloudflareAPIError: If creation fails
        """
        try:
            self.logger.info(f"Creating {record_type} record for {name} with {ip}")
            record = self.client.dns.records.create(
                zone_id=zone_id,
                name=name,
                content=ip,
                type=record_type,
                ttl=ttl,
                proxied=False
            )
            return record

        except Exception as e:
            raise CloudflareAPIError(f"Failed to create {record_type} record {name}: {e}")


# DDNS Updater
class DDNSUpdater:
    """Main orchestration for DDNS updates."""

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger

        # Initialize UniFi client (for device queries)
        self.unifi_client = UniFiClient(config['unifi'], logger)

        # Initialize Cloudflare client
        config_manager = ConfigManager()
        config_manager.config = config
        cloudflare_api_token = config_manager.get_cloudflare_api_token()
        self.cf_client = CloudflareClient(cloudflare_api_token, logger)

        self.ttl = config.get('settings', {}).get('ttl', 120)
        self.only_update_if_changed = config.get('settings', {}).get('only_update_if_changed', True)

    def run(self) -> None:
        """Main execution loop."""
        self.logger.info("Starting DDNS update process")

        devices = self.config.get('devices', [])
        total_updates = 0
        total_errors = 0

        for device_config in devices:
            try:
                updates, errors = self.process_device(device_config)
                total_updates += updates
                total_errors += errors
            except Exception as e:
                self.logger.error(
                    f"Failed to process device: {e}",
                    exc_info=True,
                    extra={
                        'device': device_config.get('name', 'unknown'),
                        'mac': device_config.get('mac', 'unknown')
                    }
                )
                total_errors += 1

        self.logger.info(
            f"DDNS update complete: {total_updates} updates, {total_errors} errors"
        )

    def process_device(self, device_config: Dict[str, Any]) -> tuple:
        """
        Process single device with comprehensive error handling.

        Returns:
            tuple: (update_count, error_count)
        """
        mac = device_config['mac']
        device_name = device_config.get('name', mac)
        updates = 0
        errors = 0

        try:
            # Get device info from UniFi
            self.logger.debug(f"Processing device: {device_name} ({mac})")
            client_info = self.unifi_client.get_client_by_mac(mac)

            if not client_info:
                self.logger.warning(f"Device {device_name} ({mac}) not found in UniFi")
                return (updates, errors)

            ipv4 = client_info.get('ip')
            ipv6 = client_info.get('ip6')

            if not ipv4 and not ipv6:
                self.logger.warning(f"No IPs found for device {device_name} ({mac})")
                return (updates, errors)

            self.logger.info(
                f"Found device {device_name} ({mac}): IPv4={ipv4}, IPv6={ipv6}"
            )

            # Process each DNS record
            for record_config in device_config['records']:
                try:
                    ips = {'ipv4': ipv4, 'ipv6': ipv6}
                    if self.update_dns_record(ips, record_config, device_name, mac):
                        updates += 1
                except CloudflareAPIError as e:
                    self.logger.error(
                        f"Cloudflare API error updating {record_config['hostname']}: {e}",
                        extra={
                            'device': device_name,
                            'mac': mac,
                            'record': record_config['hostname']
                        }
                    )
                    errors += 1
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error updating {record_config['hostname']}: {e}",
                        exc_info=True,
                        extra={
                            'device': device_name,
                            'mac': mac,
                            'record': record_config['hostname']
                        }
                    )
                    errors += 1

        except UniFiAPIError as e:
            self.logger.error(f"UniFi API error for device {device_name} ({mac}): {e}")
            errors += 1
        except Exception as e:
            self.logger.error(
                f"Failed to process device {device_name} ({mac}): {e}",
                exc_info=True
            )
            errors += 1

        return (updates, errors)

    def update_dns_record(
        self,
        ips: Dict[str, Optional[str]],
        record_config: Dict[str, Any],
        device_name: str,
        mac: str
    ) -> bool:
        """
        Update Cloudflare DNS record.

        Returns:
            bool: True if any update was performed
        """
        hostname = record_config['hostname']
        domain = record_config['domain']
        update_ipv4 = record_config.get('ipv4', False)
        update_ipv6 = record_config.get('ipv6', False)

        return self._update_cloudflare_record(
            ips, hostname, domain, update_ipv4, update_ipv6, device_name
        )

    def _update_cloudflare_record(
        self,
        ips: Dict[str, Optional[str]],
        hostname: str,
        domain: str,
        update_ipv4: bool,
        update_ipv6: bool,
        device_name: str
    ) -> bool:
        """Update Cloudflare DNS records."""
        if not self.cf_client:
            self.logger.error("Cloudflare client not initialized")
            return False

        updated = False

        # Get zone ID
        try:
            zone_id = self.cf_client.get_zone_id(domain)
        except CloudflareAPIError as e:
            self.logger.error(f"Failed to get zone ID for {domain}: {e}")
            raise

        # Update IPv4 (A record)
        if update_ipv4 and ips['ipv4']:
            if self._update_cloudflare_record_helper(zone_id, hostname, ips['ipv4'], 'A'):
                updated = True
        elif update_ipv4 and not ips['ipv4']:
            self.logger.debug(f"No IPv4 available for {device_name}, skipping Cloudflare A record for {hostname}")

        # Update IPv6 (AAAA record)
        if update_ipv6 and ips['ipv6']:
            if self._update_cloudflare_record_helper(zone_id, hostname, ips['ipv6'], 'AAAA'):
                updated = True
        elif update_ipv6 and not ips['ipv6']:
            self.logger.debug(f"No IPv6 available for {device_name}, skipping Cloudflare AAAA record for {hostname}")

        return updated

    def _update_cloudflare_record_helper(self, zone_id: str, hostname: str, ip: str, record_type: str) -> bool:
        """
        Update or create a DNS record.

        Returns:
            bool: True if update was performed
        """
        # Get current DNS record
        dns_record = self.cf_client.get_dns_record(zone_id, hostname, record_type)

        if dns_record:
            # Check if update is needed
            if self.only_update_if_changed and dns_record.content == ip:
                self.logger.debug(f"No change for {hostname} ({record_type}): {ip}")
                return False

            # Update existing record
            self.cf_client.update_dns_record(
                zone_id=zone_id,
                record_id=dns_record.id,
                name=hostname,
                ip=ip,
                record_type=record_type,
                ttl=self.ttl
            )
            self.logger.info(
                f"Updated {record_type} record for {hostname}: {dns_record.content} -> {ip}"
            )
        else:
            # Create new record
            self.cf_client.create_dns_record(
                zone_id=zone_id,
                name=hostname,
                ip=ip,
                record_type=record_type,
                ttl=self.ttl
            )
            self.logger.info(f"Created {record_type} record for {hostname}: {ip}")

        return True


# Setup Functions
def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """Configure logging with rotation and formatting."""
    log_config = config.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO').upper())
    log_file = log_config.get('file', 'logs/ddns.log')
    log_format = log_config.get('format', 'json')

    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # Create logger
    logger = logging.getLogger('cloudflare_ddns')
    logger.setLevel(log_level)

    # Clear any existing handlers
    logger.handlers.clear()

    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=log_config.get('max_bytes', 10485760),  # 10MB
        backupCount=log_config.get('backup_count', 5)
    )

    # Console handler
    console_handler = logging.StreamHandler()

    # Set formatter
    if log_format == 'json':
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def acquire_lock(lock_file: str = '/tmp/cloudflare_ddns.lock') -> Any:
    """
    Prevent multiple simultaneous executions.

    Returns:
        File descriptor for the lock
    """
    try:
        lock_fd = open(lock_file, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(str(os.getpid()))
        lock_fd.flush()
        return lock_fd
    except IOError:
        print("Another instance is already running")
        sys.exit(0)


def main():
    """Main entry point."""
    # Get script directory
    script_dir = Path(__file__).parent.resolve()
    config_path = script_dir / 'config.yaml'

    # Acquire lock to prevent concurrent executions
    lock = acquire_lock()

    try:
        # Load configuration
        config_manager = ConfigManager(str(config_path))
        config = config_manager.load_config()

        # Setup logging
        logger = setup_logging(config)
        logger.info("=" * 60)
        logger.info("Cloudflare DDNS Updater starting")
        logger.info("=" * 60)

        # Run DDNS updater
        updater = DDNSUpdater(config, logger)
        updater.run()

        logger.info("Cloudflare DDNS Updater completed successfully")

    except ConfigurationError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    except UniFiAPIError as e:
        print(f"UniFi API error: {e}", file=sys.stderr)
        sys.exit(1)
    except CloudflareAPIError as e:
        print(f"Cloudflare API error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Release lock
        if lock:
            lock.close()


if __name__ == '__main__':
    main()
