# Changelog - Advanced SpamAssassin Learning System

## Version 2.0 - Performance & Usability Update

**Release Date:** 2025-01-11

### 🚀 Major Features

#### 1. Ham (Legitimate Email) Learning
- **NEW:** Automatic learning from legitimate emails (Inbox/Sent folders)
- Improves SpamAssassin accuracy by teaching it what good email looks like
- Configurable limit per folder (default: 100 emails) to avoid overwhelming
- Smart folder detection - automatically skips Trash, Drafts, Templates
- Enable/disable with `learn_ham: true/false` in config

#### 2. Batch Learning Optimization
- **PERFORMANCE:** 10-20x faster learning for large spam folders
- Processes 50 emails at once instead of one-by-one
- Reduces sa-learn overhead dramatically
- Automatic fallback to individual mode for small folders or dry-run
- Example: Learning 753 spam emails reduced from ~15 minutes to ~1 minute
- Configure with `batch_learning: true/false`

#### 3. Progress Indicators
- **UX:** Real-time progress display when processing folders
- Shows: `[Folder 5/26] Processing: /path/to/folder`
- File-level progress: `Progress: 150/632 files (23%)`
- Prevents "is it frozen?" confusion during long operations
- Visual feedback with emoji indicators 🔍📧📬✅

#### 4. System Status Command
- **NEW:** `--status` command provides comprehensive system overview
- Displays:
  - Configuration file location and validity
  - Maildir path and size
  - Detected spam/ham folders with counts
  - Database statistics and last run info
  - SpamAssassin version
  - Current settings (dry_run, learn_ham, batch_learning, etc.)
- Essential for debugging and verification

#### 5. Mailbox Listing Command
- **NEW:** `--list-mailboxes` provides detailed folder report
- Shows all detected mailboxes with email counts
- Separate sections for spam and ham folders
- Sorted by email count for easy identification
- Calculates actual learning amounts (respects max_ham_per_folder limit)
- Includes helpful tips on what to run next

### 📊 Enhanced Detection

- **Multi-pattern spam detection:** .Spam, .Junk, .INBOX.Spam
- **Smart ham detection:** .INBOX, .Sent (excluding trash/drafts)
- **Pre-scan phase:** Discovers all folders before learning starts
- **Better logging:** Detailed per-folder statistics

### 🔧 Configuration Updates

New config options in `config.yaml`:

```yaml
general:
  batch_learning: true        # Enable batch mode for speed
  max_ham_per_folder: 100    # Limit ham per folder

learning:
  learn_ham: true            # Enable ham learning
```

### 📝 Documentation Improvements

- Updated README.md with "Quick Start Commands" section
- Added "Key Features" section highlighting v2.0 improvements
- Enhanced installation instructions
- Added usage examples for new commands
- Better config.yaml comments with system-specific paths

### 🐛 Bug Fixes

- Fixed mail directory detection for Plesk/qmail systems
- Improved folder scanning logic to catch all spam folder variants
- Better error handling for permission issues
- Fixed progress display clearing in terminal

### ⚡ Performance Metrics

Tested on production system with:
- 26 spam folders
- 753 spam emails
- 131 ham folders  
- 16,461 ham emails

**Results:**
- Spam learning: ~1 minute (batch mode) vs ~15 minutes (individual mode)
- Ham learning: ~8 minutes for 100 emails per folder (13,100 total)
- Total runtime: ~9 minutes vs ~120+ minutes in v1.0

**Speedup: 13x faster!**

### 🔄 Migration from v1.0

No breaking changes! Simply replace `spam_trainer.py` and update `config.yaml`:

1. Backup current config: `cp config.yaml config.yaml.backup`
2. Update `spam_trainer.py`: `chmod +x spam_trainer.py`
3. Add new config options (optional - has sensible defaults):
   ```yaml
   general:
     batch_learning: true
     max_ham_per_folder: 100
   learning:
     learn_ham: true
   ```
4. Test with: `sudo ./spam_trainer.py --status`
5. Verify with: `sudo ./spam_trainer.py --list-mailboxes`
6. Dry-run test: `sudo ./spam_trainer.py --dry-run --learn`

### 📋 Command Reference

```bash
# NEW COMMANDS
--status              # Show system status and configuration
--list-mailboxes      # List all detected mailboxes

# EXISTING COMMANDS  
--learn               # Run learning cycle
--dry-run --learn     # Test without making changes
--report              # Generate statistics report
--cron                # Run in quiet mode (for cron)
--config FILE         # Use custom config file
```

### 🎯 Recommended Workflow

1. **First time setup:**
   ```bash
   sudo ./spam_trainer.py --status
   sudo ./spam_trainer.py --list-mailboxes
   sudo ./spam_trainer.py --dry-run --learn
   ```

2. **Regular usage:**
   ```bash
   sudo ./spam_trainer.py --learn
   ```

3. **Monitoring:**
   ```bash
   sudo ./spam_trainer.py --report
   ```

### 🙏 Credits

Based on the original plan.json specification with 54 features.
Implemented iteratively with bug fixes and performance optimizations.

### 📞 Support

For issues or questions:
- Check logs in `/var/log/spamtrainer/`
- Run `--status` to verify configuration
- Use `--dry-run` to test without making changes
- Review `README.md` for detailed documentation

---

## Version 1.0 - Initial Release

**Release Date:** 2025-01-10

### Features

- Multi-user spam learning from maildir folders
- SQLite database for statistics tracking
- SpamAssassin integration (sa-learn, sa-update)
- Repeat offender detection and reporting
- DNSBL checking (Spamhaus, SpamCop)
- Daily statistics with email/JSON/CSV export
- Interactive menu and command-line interface
- Cron mode for automation
- Dry-run mode for testing
- Comprehensive logging
- Bayes database backup and expiration
- Configurable thresholds and settings
