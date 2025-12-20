#!/bin/bash
#
# Installation script for Cloudflare DDNS Updater on Unifi UDM Pro
#
# This script:
# - Creates installation directory at /data/ddns (persists across UDM Pro updates)
# - Copies script files
# - Sets appropriate permissions
# - Creates Python virtual environment
# - Installs dependencies
# - Provides instructions for cron setup
#

set -e  # Exit on error

INSTALL_DIR="/data/ddns"
SCRIPT_NAME="cloudflare_ddns.py"
CONFIG_EXAMPLE="config.yaml.example"
CONFIG_NAME="config.yaml"
REQUIREMENTS="requirements.txt"
VENV_DIR="$INSTALL_DIR/venv"

echo "=========================================="
echo "Cloudflare DDNS Updater Installation"
echo "=========================================="
echo ""

# Check if running on UDM Pro (optional - can install on any Linux system)
if [ -d "/data" ]; then
    echo "✓ Detected /data directory (UDM Pro or similar system)"
else
    echo "⚠ Warning: /data directory not found. Installing anyway..."
fi

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"

# Copy files
echo "Copying files..."
if [ ! -f "$SCRIPT_NAME" ]; then
    echo "Error: $SCRIPT_NAME not found in current directory"
    exit 1
fi

cp "$SCRIPT_NAME" "$INSTALL_DIR/"
cp "$CONFIG_EXAMPLE" "$INSTALL_DIR/"
cp "$REQUIREMENTS" "$INSTALL_DIR/"

# Check if config exists, if not copy example
if [ ! -f "$INSTALL_DIR/$CONFIG_NAME" ]; then
    echo "Creating initial config file from example..."
    cp "$INSTALL_DIR/$CONFIG_EXAMPLE" "$INSTALL_DIR/$CONFIG_NAME"
    echo "⚠ IMPORTANT: Edit $INSTALL_DIR/$CONFIG_NAME with your settings!"
else
    echo "✓ Config file already exists, not overwriting"
fi

# Set permissions
echo "Setting permissions..."
chmod 700 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/$CONFIG_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found. Please install Python 3.7 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Found Python $PYTHON_VERSION"

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"

# Activate virtual environment and install dependencies
echo "Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip > /dev/null 2>&1
pip install -r "$INSTALL_DIR/$REQUIREMENTS"
deactivate

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Edit configuration file:"
echo "   vi $INSTALL_DIR/$CONFIG_NAME"
echo ""
echo "2. Add your Cloudflare API token and interface/DNS mappings"
echo ""
echo "3. Test the script manually:"
echo "   $VENV_DIR/bin/python $INSTALL_DIR/$SCRIPT_NAME"
echo ""
echo "4. Add cron job for automatic updates:"
echo "   crontab -e"
echo ""
echo "   Add this line (runs every 5 minutes):"
echo "   */5 * * * * $VENV_DIR/bin/python $INSTALL_DIR/$SCRIPT_NAME >> $INSTALL_DIR/logs/cron.log 2>&1"
echo ""
echo "5. (Optional) Create boot persistence script for UDM Pro:"
echo "   See README.md for instructions"
echo ""
echo "Logs will be written to: $INSTALL_DIR/logs/"
echo ""
