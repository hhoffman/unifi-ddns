# Cloudflare DDNS Updater for UniFi

A Python-based Dynamic DNS (DDNS) updater that queries UniFi Controller for device IPs by MAC address and automatically updates Cloudflare DNS records. Supports both IPv4 (A records) and IPv6 (AAAA records).

## Features

- Query UniFi Controller by MAC address to get current device IPs
- Update both IPv4 (A) and IPv6 (AAAA) DNS records in Cloudflare
- Automatic detection of IP changes (only updates when needed)
- Comprehensive error handling and logging
- JSON-formatted logs for easy parsing
- Prevents concurrent executions with lock file
- Configurable via YAML file
- Docker deployment with automatic restarts

## Requirements

- UniFi Controller (UDM Pro, Cloud Key, or self-hosted)
- Docker and Docker Compose
- Cloudflare account with API token
- Devices with assigned IP addresses in UniFi

## Installation

### Docker Deployment (Recommended)

This application runs as a Docker container and checks for IP changes every 5 minutes.

1. **Clone or download the files to your Docker host:**
   ```bash
   mkdir -p /opt/cloudflare-ddns
   cd /opt/cloudflare-ddns
   ```

   Copy these files to this directory:
   - `Dockerfile`
   - `docker-compose.yml`
   - `cloudflare_ddns.py`
   - `requirements.txt`
   - `config.yaml` (your configuration)

2. **Create your configuration:**
   ```bash
   cp config.yaml.example config.yaml
   vi config.yaml
   ```

   Update with your:
   - UniFi Controller host and API key
   - Cloudflare API token
   - Device MAC addresses and DNS records

3. **Build and start the container:**
   ```bash
   docker compose up -d --build
   ```

4. **View logs:**
   ```bash
   docker logs -f cloudflare-ddns
   ```

5. **Stop/restart the container:**
   ```bash
   docker compose down
   docker compose restart
   ```

### Configuration

#### Creating a Cloudflare API Token

1. Log in to your Cloudflare account
2. Go to Profile → API Tokens → Create Token
3. Use the "Edit zone DNS" template
4. Configure:
   - **Permissions**: Zone → DNS → Edit
   - **Zone Resources**: Include → Specific zone → Select your domain
5. Copy the generated token

#### Creating a UniFi API Key

1. Log in to your UniFi Controller
2. Go to Settings → Admins
3. Select your admin user
4. Scroll to "API Keys" and create a new key
5. Copy the generated key

#### Configuration File (config.yaml)

```yaml
# UniFi Controller Configuration
unifi:
  # UDM Pro hostname or IP address
  host: "192.168.1.1"

  # UniFi Controller port (default: 443)
  port: 443

  # Site name (default is usually "default")
  site: "default"

  # API Key (recommended)
  api_key: "your_unifi_api_key_here"

  # Verify SSL certificate (set to false for self-signed certs)
  verify_ssl: false

# Cloudflare API Configuration
cloudflare:
  # API token with Zone:DNS:Edit permissions
  api_token: "your_cloudflare_api_token_here"

# Logging Configuration
logging:
  level: INFO
  file: /app/logs/ddns.log
  max_bytes: 10485760  # 10MB
  backup_count: 5
  format: json

# DNS Update Settings
settings:
  ttl: 120  # DNS TTL in seconds (120 = 2 minutes)
  only_update_if_changed: true

# Device to DNS Record Mappings
devices:
  # Example device
  - mac: "aa:bb:cc:dd:ee:ff"
    name: "Docker Server 01"
    records:
      - domain: example.com
        hostname: docker01.example.com
        ipv4: true
        ipv6: true

  # Add more devices as needed
  - mac: "11:22:33:44:55:66"
    name: "Web Server"
    records:
      - domain: example.com
        hostname: web.example.com
        ipv4: true
        ipv6: false  # No IPv6 for this device
```

**Configuration Options:**

- `unifi.host`: UniFi Controller hostname or IP
- `unifi.api_key`: UniFi API key (or use username/password)
- `cloudflare.api_token`: Your Cloudflare API token
- `logging.level`: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `settings.ttl`: DNS TTL in seconds (120 = 2 minutes, recommended for dynamic IPs)
- `settings.only_update_if_changed`: Only update DNS when IP changes (default: true)
- `devices`: List of devices to monitor by MAC address
  - `mac`: Device MAC address (must match UniFi)
  - `name`: Friendly name for logs
  - `records`: DNS records to update for this device
    - `domain`: Your domain name
    - `hostname`: Full hostname to update (FQDN)
    - `ipv4`: Update A record (true/false)
    - `ipv6`: Update AAAA record (true/false)

### Security Best Practices

1. **Protect your configuration file:**
   ```bash
   chmod 600 /opt/cloudflare-ddns/config.yaml
   ```

2. **Scope your API tokens** to only the zones and permissions needed

3. **Never commit** `config.yaml` to version control (already in `.gitignore`)

4. **Alternative: Use environment variables:**
   ```yaml
   cloudflare:
     api_token_env: "CF_API_TOKEN"
   ```
   Then set the environment variable in docker-compose.yml

## Usage

### Docker Container Management

**View container status:**
```bash
docker ps | grep cloudflare-ddns
```

**View live logs:**
```bash
docker logs -f cloudflare-ddns
```

**View application logs:**
```bash
docker exec cloudflare-ddns tail -f /app/logs/ddns.log
```

**Restart after config changes:**
```bash
# Edit config on host
vi /opt/cloudflare-ddns/config.yaml

# Rebuild and restart container
docker compose down
docker compose up -d --build
```

**Change update interval:**

Edit `docker-compose.yml` and modify the sleep value (in seconds):
```yaml
# For 2-minute intervals:
command: sh -c 'while true; do python3 cloudflare_ddns.py; sleep 120; done'

# For 15-minute intervals:
command: sh -c 'while true; do python3 cloudflare_ddns.py; sleep 900; done'
```

### Boot Persistence

The container automatically restarts unless stopped (using `restart: unless-stopped` policy). If Docker is configured to start on boot, the container will start automatically after reboot.

Verify Docker starts on boot:
```bash
systemctl is-enabled docker
```

If not enabled:
```bash
systemctl enable docker
```

## Monitoring and Logs

### View Logs

**Docker container logs (stdout):**
```bash
docker logs -f cloudflare-ddns
```

**Application JSON logs:**
```bash
docker exec cloudflare-ddns tail -f /app/logs/ddns.log
```

### Log Format

Logs are in JSON format for easy parsing:
```json
{
  "timestamp": "2025-12-20T15:12:47.762083Z",
  "level": "INFO",
  "message": "Updated A record for docker01.example.com: 192.168.1.50 -> 192.168.1.51",
  "module": "cloudflare_ddns",
  "function": "_update_cloudflare_record_helper",
  "line": 928
}
```

### Log Rotation

Logs automatically rotate when they reach 10MB, keeping the last 5 files.

## Troubleshooting

### Container Not Starting

```bash
# Check container status
docker ps -a | grep cloudflare-ddns

# View container logs
docker logs cloudflare-ddns

# Check docker-compose errors
docker compose up
```

### Configuration Errors

**Error:** `Configuration file not found`

**Solution:** Ensure `config.yaml` exists in the same directory as `cloudflare_ddns.py` inside the container. Rebuild the image if you added the file after building.

### UniFi API Errors

**Error:** `Failed to authenticate with UniFi Controller`

**Solutions:**
- Verify UniFi host, port, and API key in config
- Check that API key has sufficient permissions
- Verify SSL settings (set `verify_ssl: false` for self-signed certs)

**Error:** `Client with MAC aa:bb:cc:dd:ee:ff not found`

**Solutions:**
- Verify MAC address matches device in UniFi
- Ensure device is online and connected
- Check that device is in the correct site (default site usually)

### Cloudflare API Errors

**Error:** `Cloudflare API error: Authentication failed`

**Solutions:**
1. Verify your API token in `config.yaml`
2. Check token permissions at Cloudflare dashboard
3. Ensure token has "Zone → DNS → Edit" permission for your zone

**Error:** `Zone not found: example.com`

**Solution:** Ensure the domain in your config matches a zone in your Cloudflare account

### DNS Records Not Updating

**Check:**
1. Verify the IP actually changed (script only updates on change by default)
2. Check logs for errors: `docker logs cloudflare-ddns`
3. Verify DNS record exists in Cloudflare dashboard (will be created on first run)
4. Test manually: `docker exec cloudflare-ddns python3 cloudflare_ddns.py`

### No IPv6 Updates

**Message:** `No IPv6 available for device, skipping AAAA record`

**Explanation:** The device doesn't have a non-link-local IPv6 address. This is normal if:
- IPv6 is not configured for the device
- Only link-local addresses (fe80::) are available

**Solution:** Disable IPv6 updates for that record:
```yaml
ipv6: false
```

## How It Works

1. **Read Configuration**: Loads `config.yaml` and validates settings
2. **Acquire Lock**: Prevents multiple simultaneous executions
3. **For Each Device**:
   - Queries UniFi Controller for device info by MAC address
   - Retrieves IPv4 and IPv6 addresses
   - Filters out link-local IPv6 addresses (fe80::)
4. **For Each DNS Record**:
   - Gets Cloudflare zone ID (cached for efficiency)
   - Checks if DNS record exists
   - Compares current IP with DNS record
   - Updates or creates record if needed
5. **Log Results**: Records all updates and errors in JSON format

## Architecture

The script is organized into several classes:

- **`ConfigManager`**: Handles configuration loading and validation
- **`UniFiClient`**: Manages UniFi Controller API interactions
- **`CloudflareClient`**: Manages Cloudflare API interactions
- **`DDNSUpdater`**: Main orchestration and error handling

## Performance

- **Single device, single record**: ~1-2 seconds
- **Multiple devices (5), multiple records (10)**: ~5-10 seconds
- **API calls per execution**: 2-3 per record (zone lookup + record lookup + update)
- **Daily API calls** (5-minute interval): ~4,320 (well under Cloudflare's rate limits)

## Docker Volumes

The application uses Docker volumes for persistent storage:

- **`cloudflare-ddns_ddns-logs`**: Stores application logs

Configuration is baked into the Docker image for simplicity.

## Contributing

Issues and pull requests are welcome! Please ensure:

1. Code follows existing style
2. Error handling is comprehensive
3. Changes are documented in README
4. Configuration changes include example updates

## License

MIT License - See LICENSE file for details

## Acknowledgments

Built with:
- [Cloudflare Python SDK](https://github.com/cloudflare/cloudflare-python)
- [PyYAML](https://pyyaml.org/)
- [Requests](https://requests.readthedocs.io/)

---

Generated with Claude Code
