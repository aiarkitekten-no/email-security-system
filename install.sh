#!/bin/bash
# Installation script for Advanced SpamAssassin Learning System
# Version: 1.0.0

echo "=========================================="
echo "Advanced SpamAssassin Learning System"
echo "Installation Script"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Note: Some steps may require sudo privileges"
    USE_SUDO="sudo"
else
    USE_SUDO=""
fi

# Check Python version
echo "Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $PYTHON_VERSION"

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "ERROR: Python 3.8 or higher is required"
    exit 1
fi

# Check SpamAssassin
echo ""
echo "Checking for SpamAssassin..."
if command -v sa-learn &> /dev/null; then
    SA_VERSION=$(sa-learn --version 2>&1 | head -1)
    echo "Found: $SA_VERSION"
else
    echo "WARNING: SpamAssassin not found"
    echo "Install with: sudo apt-get install spamassassin"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt --user
    if [ $? -eq 0 ]; then
        echo "Dependencies installed successfully"
    else
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
else
    echo "ERROR: requirements.txt not found"
    exit 1
fi

# Create directories
echo ""
echo "Creating directories..."

# Try system directories first
$USE_SUDO mkdir -p /var/lib/spamtrainer 2>/dev/null && \
$USE_SUDO chown $(whoami):$(whoami) /var/lib/spamtrainer 2>/dev/null && \
echo "  - /var/lib/spamtrainer (created)" || \
echo "  - /var/lib/spamtrainer (will use /tmp)"

$USE_SUDO mkdir -p /var/log/spamtrainer 2>/dev/null && \
$USE_SUDO chown $(whoami):$(whoami) /var/log/spamtrainer 2>/dev/null && \
echo "  - /var/log/spamtrainer (created)" || \
echo "  - /var/log/spamtrainer (will use /tmp)"

$USE_SUDO mkdir -p /var/backups/spamassassin 2>/dev/null && \
$USE_SUDO chown $(whoami):$(whoami) /var/backups/spamassassin 2>/dev/null && \
echo "  - /var/backups/spamassassin (created)" || \
echo "  - /var/backups/spamassassin (will use /tmp)"

mkdir -p ~/.config/spamtrainer 2>/dev/null
echo "  - ~/.config/spamtrainer (created)"

# Copy configuration file
echo ""
echo "Setting up configuration..."
if [ -f "config.yaml" ]; then
    if [ ! -f ~/.config/spamtrainer/config.yaml ]; then
        cp config.yaml ~/.config/spamtrainer/config.yaml
        
        # Auto-detect mail location
        if [ -d "/var/qmail/mailnames" ]; then
            echo "Detected Plesk/qmail system"
            sed -i 's|maildir_base: /var/vmail|maildir_base: /var/qmail/mailnames|g' ~/.config/spamtrainer/config.yaml
            echo "  - Updated maildir_base to /var/qmail/mailnames"
        elif [ -d "/var/vmail" ]; then
            echo "Detected /var/vmail"
            echo "  - Using maildir_base: /var/vmail"
        else
            echo "WARNING: Could not auto-detect mail location"
            echo "Please manually set maildir_base in config.yaml"
        fi
        
        echo "Configuration copied to ~/.config/spamtrainer/config.yaml"
    else
        echo "Configuration already exists at ~/.config/spamtrainer/config.yaml"
        read -p "Overwrite? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cp config.yaml ~/.config/spamtrainer/config.yaml
            echo "Configuration overwritten"
        fi
    fi
else
    echo "ERROR: config.yaml not found"
    exit 1
fi

# Make script executable
echo ""
echo "Making spam_trainer.py executable..."
chmod +x spam_trainer.py
echo "Done"

# Test run
echo ""
echo "Testing installation..."
if python3 spam_trainer.py --help > /dev/null 2>&1; then
    echo "✓ Installation successful!"
else
    echo "✗ Test failed - check error messages above"
    exit 1
fi

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Edit configuration:"
echo "   nano ~/.config/spamtrainer/config.yaml"
echo ""
echo "2. Update these settings:"
echo "   - maildir_base: /var/vmail (your mailbox location)"
echo "   - report_to: your-email@domain.com"
echo "   - smtp_host: your-smtp-server"
echo ""
echo "3. Test with dry run:"
echo "   ./spam_trainer.py --dry-run --learn"
echo ""
echo "4. Run interactively:"
echo "   ./spam_trainer.py"
echo ""
echo "5. Add to cron for automation:"
echo "   crontab -e"
echo "   0 2 * * * /path/to/spam_trainer.py --cron"
echo ""
echo "For help:"
echo "   ./spam_trainer.py --help"
echo "   cat README.md"
echo ""
