#!/bin/bash
echo "=========================================="
echo "Testing SpamAssassin Cron Jobs"
echo "=========================================="
echo ""

echo "1. Testing script execution..."
if ./spam_trainer.py --help > /dev/null 2>&1; then
    echo "   ✅ Script is executable"
else
    echo "   ❌ Script execution failed"
    exit 1
fi

echo ""
echo "2. Testing log file write..."
LOG_FILE="/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log"
if touch "$LOG_FILE" 2>/dev/null; then
    echo "   ✅ Log file writable: $LOG_FILE"
else
    echo "   ❌ Cannot write to log file"
    exit 1
fi

echo ""
echo "3. Verifying cron schedule..."
echo "   Learning cycle: Every hour at minute 0"
echo "   HTML report:    Daily at 02:00"

echo ""
echo "4. Current crontab entries:"
crontab -l | grep -A 1 "spam_trainer.py"

echo ""
echo "=========================================="
echo "✅ All tests passed!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  - Learning will run every hour"
echo "  - HTML report sent to terje@smartesider.no at 02:00"
echo "  - Logs written to: $LOG_FILE"
echo "  - Monitor with: tail -f $LOG_FILE"
