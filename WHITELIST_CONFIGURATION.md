# 🛡️ Whitelist Configuration Guide

**Version:** 3.3.2  
**Date:** November 13, 2025

---

## 📋 Overview

The whitelist feature prevents false positives by bypassing threat detection (virus scanning and phishing detection) for emails from your own domains, servers, and trusted senders.

**Critical Use Cases:**
- Contact form submissions from your own website
- Automated system emails from your servers
- Internal company communications
- Partner/vendor emails that contain security keywords

---

## ⚙️ Configuration

Edit `config.yaml` under the `threat_detection` section:

```yaml
threat_detection:
  enabled: true
  
  # Whitelist configuration
  whitelist:
    enabled: true                    # Enable/disable whitelist
    
    # Whitelist by domain
    domains:
      - skycrm.no
      - smartesider.no
      - skycode.no
    
    # Whitelist by hostname (from Received headers)
    hostnames:
      - hotell.skycode.no
      - mail.example.com
      - smtp1.yourdomain.com
    
    # Whitelist by sender pattern (supports wildcards)
    senders:
      - "*@skycrm.no"              # All emails from this domain
      - "*@smartesider.no"
      - "noreply@example.com"      # Specific sender
      - "system-*@example.com"     # Pattern matching
```

---

## 🎯 Whitelist Methods

### 1. Domain Whitelist

**Purpose:** Bypass all emails from specific domains

**Configuration:**
```yaml
whitelist:
  domains:
    - yourdomain.com
    - partner.com
```

**Matches:**
- `user@yourdomain.com`
- `admin@yourdomain.com`
- Any email ending with `@yourdomain.com`

---

### 2. Hostname Whitelist

**Purpose:** Bypass emails from specific mail servers

**Configuration:**
```yaml
whitelist:
  hostnames:
    - mail.yourdomain.com
    - smtp.partner.com
```

**Matches:** Checked against `Received` headers in email

**Use Case:** When your server sends emails that might trigger phishing detection (e.g., password reset emails, contact forms)

---

### 3. Sender Pattern Whitelist

**Purpose:** Fine-grained control with wildcard support

**Configuration:**
```yaml
whitelist:
  senders:
    - "*@yourdomain.com"           # All from domain
    - "noreply@example.com"        # Specific address
    - "system-*@example.com"       # Pattern: system-xyz@example.com
```

**Wildcard Support:**
- `*@domain.com` - All emails from domain
- `prefix-*@domain.com` - Pattern matching

---

## 🔍 How It Works

### Detection Flow

```
Email Arrives
    ↓
Extract Sender & Headers
    ↓
Check Whitelist (domains, hostnames, senders)
    ↓
    ├─ WHITELISTED? → Bypass all threat detection → SAFE
    └─ NOT WHITELISTED? → Run threat detection (virus + phishing)
```

### Logging

When an email is whitelisted, you'll see:

```
INFO: ✅ Whitelisted domain: skycrm.no
INFO: ✅ Whitelisted hostname in Received: hotell.skycode.no
INFO: ✅ Whitelisted sender pattern: admin@skycrm.no matches *@skycrm.no
```

---

## ⚠️ Important Notes

### 1. Whitelist Applies to ALL Threat Detection

When whitelisted, the email bypasses:
- ✅ Virus scanning (ClamAV)
- ✅ Phishing detection (all sources)
- ✅ URL analysis
- ✅ Keyword detection

**Be careful!** Only whitelist domains/senders you fully trust.

### 2. Order of Checks

Whitelist is checked **FIRST** before any threat detection:

1. **Whitelist check** (fast, immediate bypass)
2. Virus scanning (only if not whitelisted)
3. Phishing detection (only if not whitelisted)

### 3. Case-Insensitive Matching

All whitelist matching is **case-insensitive**:
- `SkyCode.no` matches `skycode.no`
- `Admin@Example.COM` matches `admin@example.com`

---

## 📝 Common Scenarios

### Scenario 1: Contact Form False Positive

**Problem:**
```
WARNING: 🎣 Phishing detected (score: 270): [🚨 PHISHING] Melding fra kontaktskjemaet
```

**Solution:**
```yaml
whitelist:
  domains:
    - skycrm.no
  hostnames:
    - hotell.skycode.no
  senders:
    - "*@skycrm.no"
```

---

### Scenario 2: Internal System Emails

**Problem:** Automated password reset emails flagged as phishing

**Solution:**
```yaml
whitelist:
  senders:
    - "noreply@yourdomain.com"
    - "system@yourdomain.com"
    - "admin@yourdomain.com"
```

---

### Scenario 3: Partner/Vendor Emails

**Problem:** Trusted partner emails contain security keywords

**Solution:**
```yaml
whitelist:
  domains:
    - trustedpartner.com
    - vendor.com
```

---

## 🛠️ Testing Your Whitelist

### 1. Enable Debug Logging

```yaml
general:
  log_level: DEBUG
```

### 2. Run Test

```bash
sudo python3 spam_trainer.py --learn
```

### 3. Check Logs

```bash
tail -f /var/log/spamtrainer/spamtrainer.log | grep -i whitelist
```

Expected output for whitelisted email:
```
INFO: ✅ Whitelisted domain: skycrm.no
```

---

## 📊 Best Practices

### ✅ DO:
- Whitelist your own domains
- Whitelist your mail servers (hostnames)
- Use wildcard patterns for system emails
- Test after adding new whitelist entries
- Document why each domain/sender is whitelisted

### ❌ DON'T:
- Whitelist external domains you don't control
- Use broad wildcards like `*@*.com`
- Disable whitelist checking (keep `enabled: true`)
- Forget to restart/rerun after config changes

---

## 🔧 Troubleshooting

### Issue: Whitelist Not Working

**Check:**
1. Is `whitelist.enabled: true`?
2. Is the domain/sender spelled correctly?
3. Are you checking the right log file?
4. Did you restart the system after config change?

**Debug:**
```bash
# Check config loading
sudo python3 spam_trainer.py --status

# Enable debug logging
nano config.yaml  # Set log_level: DEBUG

# Watch logs in real-time
tail -f /var/log/spamtrainer/spamtrainer.log
```

---

### Issue: Still Getting False Positives

**Possible Causes:**
1. Sender doesn't match whitelist pattern
2. Email coming from relay server (check Received headers)
3. Typo in domain/sender

**Solution:**
Check the actual sender in logs:
```bash
grep "Phishing detected" /var/log/spamtrainer/spamtrainer.log
```

Then add exact sender to whitelist.

---

## 📈 Performance Impact

**Whitelist checking is extremely fast:**
- **Time:** < 1ms per email
- **Memory:** Minimal (list stored in RAM)
- **CPU:** Negligible

**Impact on detection:**
- Whitelisted emails: **0% detection** (bypassed)
- Non-whitelisted: No performance change

---

## 🎯 Example Full Configuration

```yaml
threat_detection:
  enabled: true
  
  whitelist:
    enabled: true
    
    # Your company domains
    domains:
      - skycrm.no
      - smartesider.no
      - skycode.no
      - yourcompany.com
    
    # Your mail servers
    hostnames:
      - hotell.skycode.no
      - mail.yourcompany.com
      - smtp1.yourcompany.com
      - smtp2.yourcompany.com
    
    # System and no-reply addresses
    senders:
      - "*@skycrm.no"
      - "*@smartesider.no"
      - "*@skycode.no"
      - "*@yourcompany.com"
      - "noreply@partner.com"
      - "system@vendor.com"
  
  # Rest of threat detection config
  clamav_enabled: true
  phishing_enabled: true
  phishing_threshold: 70
```

---

## 🆘 Support

**Need help configuring whitelisting?**

📧 **Email:** post@smartesider.no  
🌐 **GitHub:** https://github.com/aiarkitekten-no/email-security-system

---

**Made with ❤️ by AI Arkitekten AS** | MIT License
