# 🛡️ 10 Prioriterte Sikkerhetstiltak for Spam/Angrep-Reduksjon

**Dato:** 2025-11-12  
**Nåværende Beskyttelse:** SpamAssassin + 7 DNSBL + Spamhaus API + Blacklist Monitoring

---

## 📊 Hurtigoversikt (Sortering etter Impact)

| # | Tiltak | Impact | Kompleksitet | Tid | Anbefaling |
|---|--------|--------|--------------|-----|------------|
| 1 | **Greylisting** | 🔥🔥🔥🔥🔥 | ⭐⭐ | 1-2t | ⭐⭐⭐⭐⭐ MUST HAVE |
| 2 | **Rate Limiting (Postfix)** | 🔥🔥🔥🔥🔥 | ⭐⭐ | 1t | ⭐⭐⭐⭐⭐ MUST HAVE |
| 3 | **SPF/DKIM/DMARC Validering** | 🔥🔥🔥🔥 | ⭐⭐⭐ | 2-3t | ⭐⭐⭐⭐ HIGH |
| 4 | **Fail2Ban Anti-Brute-Force** | 🔥🔥🔥🔥🔥 | ⭐⭐ | 1t | ⭐⭐⭐⭐⭐ MUST HAVE |
| 5 | **IP Reputation (RBL Caching)** | 🔥🔥🔥 | ⭐⭐⭐ | 2t | ⭐⭐⭐ MEDIUM |
| 6 | **Attachment Filtering** | 🔥🔥🔥🔥 | ⭐⭐ | 1t | ⭐⭐⭐⭐ HIGH |
| 7 | **Geo-Blocking (Country Filter)** | 🔥🔥🔥 | ⭐⭐ | 1-2t | ⭐⭐⭐ MEDIUM |
| 8 | **Sender Verification (callout)** | 🔥🔥🔥 | ⭐⭐⭐⭐ | 2-3t | ⭐⭐ LOW (risikabelt) |
| 9 | **Honeypot Email Addresses** | 🔥🔥 | ⭐ | 30min | ⭐⭐⭐ MEDIUM (passiv) |
| 10 | **Content Filtering (ClamAV)** | 🔥🔥🔥 | ⭐⭐⭐ | 1-2t | ⭐⭐⭐ MEDIUM |

---

## 1. 🚦 Greylisting (Postgrey/Postscreen)

### Hva det er:
Midlertidig avviser e-post fra ukjente sendere. Legitime mailservere prøver igjen (RFC-compliance), spambots gjør ikke det.

### Hvorfor det fungerer:
- **85-95% spam reduksjon** umiddelbart
- Spambots sender ikke fra ekte mailservere
- Kun 4-15 min forsinkelse for legitim e-post første gang
- Ingen CPU overhead (bare database lookup)

### Implementering:
```bash
# Installer postgrey
apt-get install postgrey

# Konfigurer Postfix
postconf -e "smtpd_recipient_restrictions = 
  permit_mynetworks,
  permit_sasl_authenticated,
  reject_unauth_destination,
  check_policy_service inet:127.0.0.1:10023"

# Start postgrey
systemctl enable postgrey
systemctl start postgrey

# Whitelist viktige domener
echo "google.com" >> /etc/postgrey/whitelist_clients.local
echo "microsoft.com" >> /etc/postgrey/whitelist_clients.local
```

### Konfigurasjon:
```bash
# /etc/default/postgrey
POSTGREY_OPTS="--inet=127.0.0.1:10023 \
  --delay=300 \              # 5 min delay (kan reduseres til 60)
  --max-age=35 \             # Hold 35 dager
  --greylist-text='Greylisted, retry in %s seconds'"
```

### Fordeler:
- ✅ Ekstremt effektivt (85-95% reduksjon)
- ✅ Minimal forsinkelse (5 min første gang)
- ✅ Ingen false positives (RFC-compliant servere prøver igjen)
- ✅ Lav CPU/RAM bruk

### Ulemper:
- ❌ 5-15 min forsinkelse for nye avsendere
- ❌ Problematisk for tidsavhengige e-poster (reset passord, etc.)

### Kode Integrasjon:
```python
# I spam_trainer.py - statistikk
def get_greylisting_stats(self):
    """Parse postgrey logs for statistics"""
    stats = {'greylisted': 0, 'passed': 0, 'rejected': 0}
    
    with open('/var/log/mail.log', 'r') as f:
        for line in f:
            if 'postgrey' in line:
                if 'action=greylist' in line:
                    stats['greylisted'] += 1
                elif 'action=pass' in line:
                    stats['passed'] += 1
    
    return stats
```

**Anbefaling:** ⭐⭐⭐⭐⭐ **MUST HAVE** - Enkleste og mest effektive tiltaket!

---

## 2. 🚫 Rate Limiting (Postfix Anvil)

### Hva det er:
Begrenser antall e-poster per time/minutt fra samme IP eller sender. Stopper mass-mailing angrep.

### Hvorfor det fungerer:
- Spambots sender tusenvis av e-poster raskt
- Legitime brukere sender maksimalt 10-50 per time
- Stoppes på SMTP-nivå (før SpamAssassin)

### Implementering:
```bash
# /etc/postfix/main.cf
# Rate limiting
smtpd_client_connection_count_limit = 10
smtpd_client_connection_rate_limit = 30
smtpd_client_message_rate_limit = 100

# Per sender rate limit
smtpd_client_recipient_rate_limit = 10
smtpd_client_new_tls_session_rate_limit = 10

# Anvil service (rate limiting daemon)
anvil_rate_time_unit = 60s
anvil_status_update_time = 600s
```

### Fordeler:
- ✅ Stopper mass-mailing umiddelbart
- ✅ Beskytter mot DDoS via SMTP
- ✅ Innebygd i Postfix (ingen nye pakker)
- ✅ Minimal CPU overhead

### Ulemper:
- ❌ Kan blokkere store mailservere (Google/Microsoft)
- ❌ Krever tuning for din trafikk

### Whitelist Store Sendere:
```bash
# /etc/postfix/client_rate_limits
# Format: IP/netmask  limit
209.85.128.0/17  1000  # Gmail
40.92.0.0/15     1000  # Microsoft
```

### Overvåking:
```bash
# Se blokkerte clients
postcat -q ALL | grep -i "rate limit"

# Se Anvil status
postqueue -p
```

**Anbefaling:** ⭐⭐⭐⭐⭐ **MUST HAVE** - Kritisk for DDoS-beskyttelse!

---

## 3. 🔐 SPF/DKIM/DMARC Validering

### Hva det er:
Validerer at e-post faktisk kommer fra autorisert server for domenet.

### Hvorfor det fungerer:
- **SPF:** Sjekker om sender-IP er autorisert
- **DKIM:** Kryptografisk signatur verifiserer innhold
- **DMARC:** Policy for hva som skal gjøres ved feil

### Impact:
- 40-60% spam reduksjon
- Stopper email spoofing/phishing
- Industri-standard for e-postautentisering

### Implementering:
```bash
# Installer OpenDKIM + OpenDMARC
apt-get install opendkim opendkim-tools opendmarc

# Konfigurer Postfix
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:localhost:8891,inet:localhost:8893"
postconf -e "non_smtpd_milters = inet:localhost:8891,inet:localhost:8893"

# OpenDKIM config
# /etc/opendkim.conf
Mode                    sv
Canonicalization        relaxed/simple
Socket                  inet:8891@localhost

# OpenDMARC config
# /etc/opendmarc.conf
Socket                  inet:8893@localhost
RejectFailures          true
```

### Python Integrasjon:
```python
# spam_trainer.py - ny klasse
class EmailAuthValidator:
    def validate_spf(self, sender_ip, sender_domain):
        """Check SPF record"""
        import spf
        result = spf.check2(i=sender_ip, s=sender_domain, h='mail.example.com')
        return result[0]  # 'pass', 'fail', 'softfail', 'neutral'
    
    def validate_dkim(self, email_content):
        """Verify DKIM signature"""
        import dkim
        return dkim.verify(email_content)
    
    def validate_dmarc(self, sender_domain):
        """Check DMARC policy"""
        import dns.resolver
        try:
            answers = dns.resolver.resolve(f'_dmarc.{sender_domain}', 'TXT')
            for rdata in answers:
                if 'v=DMARC1' in str(rdata):
                    return str(rdata)
        except:
            return None
```

### Database Tracking:
```sql
ALTER TABLE sender_tracking ADD COLUMN spf_status TEXT;
ALTER TABLE sender_tracking ADD COLUMN dkim_valid INTEGER;
ALTER TABLE sender_tracking ADD COLUMN dmarc_policy TEXT;
```

**Anbefaling:** ⭐⭐⭐⭐ **HIGH PRIORITY** - Industri-standard, stopper spoofing!

---

## 4. 🔒 Fail2Ban - Anti-Brute-Force

### Hva det er:
Overvåker logger for mistenkelig aktivitet og banner IP-er automatisk via iptables.

### Hvorfor det fungerer:
- Stopper brute-force SMTP AUTH angrep
- Blokkerer IP-er som sender for mye spam
- Automatisk unbanning etter X timer

### Implementering:
```bash
# Installer fail2ban
apt-get install fail2ban

# /etc/fail2ban/jail.local
[postfix-sasl]
enabled  = true
port     = smtp,ssmtp,submission
filter   = postfix-sasl
logpath  = /var/log/mail.log
maxretry = 3
bantime  = 3600

[postfix-spam]
enabled  = true
port     = smtp,ssmtp,submission
filter   = postfix-spam
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 86400
```

### Custom Filter for SpamAssassin:
```bash
# /etc/fail2ban/filter.d/spamassassin.conf
[Definition]
failregex = ^.* spamd: identified spam \(.*\) from <HOST>
ignoreregex =
```

### Integrasjon med spam_trainer.py:
```python
def report_to_fail2ban(self, sender_ip, reason="spam"):
    """Report IP to fail2ban"""
    log_message = f"spam_trainer: identified spam from {sender_ip} - {reason}"
    
    # Skriv til fail2ban-logg
    with open('/var/log/spam_trainer_fail2ban.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()} {log_message}\n")
```

### Overvåking:
```bash
# Se bannede IP-er
fail2ban-client status postfix-sasl

# Unban manuelt
fail2ban-client set postfix-sasl unbanip 1.2.3.4
```

**Anbefaling:** ⭐⭐⭐⭐⭐ **MUST HAVE** - Kritisk for server-sikkerhet!

---

## 5. 📊 IP Reputation System (RBL Caching)

### Hva det er:
Cacher DNSBL-oppslag i X timer for å unngå repetitive DNS queries. Bygger lokal reputation database.

### Hvorfor det fungerer:
- Samme spam-IP-er sender flere ganger
- DNSBL DNS queries er trege (100-500ms)
- Lokal cache = instant lookup (1-5ms)

### Implementering:
```python
class DNSBLCache:
    def __init__(self, ttl=3600):
        self.cache = {}  # {ip: {'listed': bool, 'lists': [], 'timestamp': float}}
        self.ttl = ttl
    
    def check_cached(self, ip):
        if ip in self.cache:
            entry = self.cache[ip]
            if time.time() - entry['timestamp'] < self.ttl:
                return entry
            else:
                del self.cache[ip]
        return None
    
    def cache_result(self, ip, listed, lists):
        self.cache[ip] = {
            'listed': listed,
            'lists': lists,
            'timestamp': time.time()
        }
    
    def get_reputation_score(self, ip):
        """Calculate reputation based on cache history"""
        if ip not in self.reputation_db:
            return 50  # Neutral
        
        checks = self.reputation_db[ip]
        listed_count = sum(1 for c in checks if c['listed'])
        score = max(0, 100 - (listed_count * 10))
        return score
```

### Database Schema:
```sql
CREATE TABLE ip_reputation (
    ip TEXT PRIMARY KEY,
    first_seen TEXT,
    last_seen TEXT,
    check_count INTEGER DEFAULT 0,
    listed_count INTEGER DEFAULT 0,
    reputation_score INTEGER DEFAULT 50,
    last_listed_on TEXT
);

CREATE INDEX idx_reputation_score ON ip_reputation(reputation_score);
```

### Performance Gain:
- **Before:** 7 DNSBL × 200ms = 1400ms per email
- **After:** 1ms cache lookup
- **Speedup:** ~1400x raskere! 🚀

**Anbefaling:** ⭐⭐⭐ **MEDIUM** - Stor performance boost, kompleks implementering.

---

## 6. 📎 Attachment Filtering (MIMEDefang/Amavis)

### Hva det er:
Blokkerer farlige filtyper (.exe, .scr, .vbs, etc.) og scanner vedlegg med ClamAV.

### Hvorfor det fungerer:
- 90% av malware kommer via e-post vedlegg
- .exe, .scr, .bat, .vbs er nesten alltid ondsinnede
- Legitim business bruker .pdf, .docx, .xlsx

### Implementering med Postfix:
```bash
# /etc/postfix/main.cf
mime_header_checks = regexp:/etc/postfix/mime_header_checks

# /etc/postfix/mime_header_checks
/^Content-(Disposition|Type).*name\s*=\s*"?.*\.(exe|scr|vbs|bat|cmd|com|pif|lnk|jar)"?/
  REJECT Dangerous attachment type not allowed

/^Content-(Disposition|Type).*name\s*=\s*"?.*\.zip"?/
  WARN ZIP file detected - scanning for malware
```

### Python Implementering:
```python
class AttachmentFilter:
    DANGEROUS_EXTENSIONS = {
        'exe', 'scr', 'vbs', 'bat', 'cmd', 'com', 'pif', 'lnk', 
        'jar', 'js', 'jse', 'hta', 'msi', 'reg', 'ps1'
    }
    
    SUSPICIOUS_EXTENSIONS = {
        'zip', 'rar', '7z', 'iso', 'dmg'
    }
    
    def scan_email_attachments(self, email_path):
        """Scan email for dangerous attachments"""
        with open(email_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        dangerous = []
        suspicious = []
        
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                ext = filename.split('.')[-1].lower()
                if ext in self.DANGEROUS_EXTENSIONS:
                    dangerous.append(filename)
                elif ext in self.SUSPICIOUS_EXTENSIONS:
                    suspicious.append(filename)
        
        return {
            'dangerous': dangerous,
            'suspicious': suspicious,
            'safe': len(dangerous) == 0
        }
```

### Whitelist Business Files:
```python
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'txt', 'csv', 'jpg', 'png', 'gif', 'mp4', 'mov'
}
```

**Anbefaling:** ⭐⭐⭐⭐ **HIGH PRIORITY** - Stopper malware, enkelt å implementere!

---

## 7. 🌍 Geo-Blocking (Country Filtering)

### Hva det er:
Blokkerer e-post fra land du aldri mottar legitim e-post fra (Russland, Kina, Nigeria, etc.).

### Hvorfor det fungerer:
- 80% av spam kommer fra få land
- Norsk business mottar sjelden e-post fra Kina/Russland
- Legitime kunder kan whitelistes

### Implementering:
```bash
# Installer GeoIP
apt-get install geoipupdate geoip-database

# Download MaxMind database
geoipupdate

# Postfix integrasjon med policy daemon
# /etc/postfix/main.cf
smtpd_recipient_restrictions = 
  check_policy_service inet:127.0.0.1:10040
```

### Python Policy Daemon:
```python
import geoip2.database

class GeoPolicyDaemon:
    BLOCKED_COUNTRIES = ['CN', 'RU', 'NG', 'IN', 'PK', 'VN', 'ID']
    
    def __init__(self):
        self.reader = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-Country.mmdb')
    
    def check_country(self, ip):
        try:
            response = self.reader.country(ip)
            country_code = response.country.iso_code
            
            if country_code in self.BLOCKED_COUNTRIES:
                return f"REJECT Email from {country_code} not accepted"
            else:
                return "DUNNO"  # Accept
        except:
            return "DUNNO"  # Unknown IP, allow
```

### Statistikk:
```python
def get_country_stats(self):
    """Get spam distribution by country"""
    conn = self.database.get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT country_code, COUNT(*) as count
        FROM sender_tracking
        WHERE spam_count > 0
        GROUP BY country_code
        ORDER BY count DESC
        LIMIT 10
    ''')
    return c.fetchall()
```

### Whitelist:
```python
WHITELISTED_IPS = [
    '209.85.128.0/17',  # Gmail
    '40.92.0.0/15',     # Microsoft
]
```

**Anbefaling:** ⭐⭐⭐ **MEDIUM** - Effektivt men kan blokkere legitim trafikk!

---

## 8. ✅ Sender Verification (Recipient Callout)

### Hva det er:
Verifiserer at avsender-e-postadressen faktisk eksisterer ved å spørre sender-serveren.

### Hvorfor det fungerer:
- Spambots bruker falske avsenderadresser
- Callout verifiserer at mailboxen finnes
- Stopper dictionary attacks

### Implementering:
```bash
# /etc/postfix/main.cf
smtpd_recipient_restrictions = 
  reject_unverified_sender

# Callout cache
address_verify_sender = postmaster@$myhostname
address_verify_cache_cleanup_interval = 12h
```

### Fordeler:
- ✅ Verifiserer ekte avsendere
- ✅ Stopper falske/spoofed adresser

### Ulemper:
- ❌ Kan forårsake forsinkelser (1-5 sek per email)
- ❌ Noen mailservere blokkerer callouts (ansees som scanning)
- ❌ Kan føre til greylistet hos andre
- ❌ Privacy concerns

**Anbefaling:** ⭐⭐ **LOW PRIORITY** - Risikabelt, kan forårsake problemer!

---

## 9. 🍯 Honeypot Email Addresses

### Hva det er:
Skjulte e-postadresser som aldri brukes legitimt. Kun spambots finner dem (web scraping).

### Hvorfor det fungerer:
- Publiser "hidden" e-postadresser på nettsiden
- Spambots scraper nettsider for @-adresser
- All e-post til honeypot = garantert spam
- Auto-blacklist avsender-IP

### Implementering:
```html
<!-- På nettsiden (skjult i HTML) -->
<div style="display:none">
  <a href="mailto:spam-trap@smartesider.no">Contact</a>
  <a href="mailto:sales-bot@smartesider.no">Sales</a>
</div>
```

### Postfix Honeypot:
```bash
# /etc/postfix/virtual
spam-trap@smartesider.no    honeypot
sales-bot@smartesider.no    honeypot

# /etc/aliases
honeypot: |/usr/local/bin/honeypot_handler.sh
```

### Honeypot Handler:
```bash
#!/bin/bash
# /usr/local/bin/honeypot_handler.sh

# Ekstrakt sender IP fra headers
SENDER_IP=$(grep "Received:" | head -1 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

# Blacklist i fail2ban
fail2ban-client set postfix banip $SENDER_IP

# Logg
echo "$(date) Honeypot triggered by $SENDER_IP" >> /var/log/honeypot.log
```

### Python Integrasjon:
```python
class HoneypotMonitor:
    HONEYPOT_ADDRESSES = [
        'spam-trap@smartesider.no',
        'sales-bot@smartesider.no',
        'admin-test@smartesider.no'
    ]
    
    def is_honeypot_target(self, recipient):
        return recipient in self.HONEYPOT_ADDRESSES
    
    def report_honeypot_hit(self, sender_ip, sender_email):
        """Automatic blacklist"""
        self.logger.warning(f"Honeypot hit from {sender_ip} ({sender_email})")
        self.database.blacklist_ip(sender_ip, reason="honeypot")
        self.fail2ban_ban(sender_ip)
```

**Anbefaling:** ⭐⭐⭐ **MEDIUM** - Passiv, enkelt, ingen false positives!

---

## 10. 🦠 Content Filtering (ClamAV Integration)

### Hva det er:
Skanner alle innkommende e-poster og vedlegg for virus/malware med ClamAV.

### Hvorfor det fungerer:
- Oppdaget ~99% av kjent malware
- Blokkerer før e-post når brukeren
- Beskytter mot zero-day (heuristikk)

### Implementering:
```bash
# Installer ClamAV
apt-get install clamav clamav-daemon clamsmtp

# /etc/clamsmtpd.conf
OutAddress: 127.0.0.1:10026
Listen: 127.0.0.1:10025
Action: drop
Quarantine: /var/spool/clamav/quarantine

# Postfix config
postconf -e "content_filter = scan:127.0.0.1:10025"
```

### Python Integrasjon:
```python
import pyclamd

class VirusScanner:
    def __init__(self):
        self.clam = pyclamd.ClamdUnixSocket()
    
    def scan_email(self, email_path):
        """Scan email file for viruses"""
        result = self.clam.scan_file(email_path)
        
        if result:
            # Virus funnet
            return {
                'infected': True,
                'virus': result[email_path][1],
                'action': 'quarantine'
            }
        else:
            return {'infected': False}
    
    def scan_attachment(self, attachment_data):
        """Scan attachment bytes"""
        result = self.clam.scan_stream(attachment_data)
        return result
```

### Statistikk:
```sql
CREATE TABLE virus_detections (
    timestamp TEXT,
    sender TEXT,
    virus_name TEXT,
    action TEXT
);
```

### Performance:
- Små e-poster (<1MB): 50-200ms
- Store e-poster (5-10MB): 500ms-2s
- Med vedlegg: Avhenger av størrelse

**Anbefaling:** ⭐⭐⭐ **MEDIUM** - Viktig for sikkerhet, men performance overhead!

---

## 📊 Sammenligning & Prioritering

### Tier 1: MUST HAVE (Implementer ASAP)
1. **Greylisting** - 85-95% spam reduksjon, minimal setup
2. **Rate Limiting** - Stopper DDoS, innebygd i Postfix
4. **Fail2Ban** - Kritisk for server-sikkerhet

**Total tid:** 3-4 timer  
**Total impact:** 90-95% spam reduksjon  
**Kompleksitet:** Lav

### Tier 2: HIGH PRIORITY (Neste uke)
3. **SPF/DKIM/DMARC** - Industri-standard, stopper spoofing
6. **Attachment Filtering** - Stopper malware, enkelt

**Total tid:** 4-5 timer  
**Total impact:** +40-50% bedre deteksjon  
**Kompleksitet:** Medium

### Tier 3: MEDIUM PRIORITY (Neste måned)
5. **IP Reputation/Caching** - Performance boost
7. **Geo-Blocking** - Blokkerer land med mye spam
9. **Honeypots** - Passiv deteksjon, ingen maintenance
10. **ClamAV** - Virus-scanning

**Total tid:** 6-8 timer  
**Total impact:** +20-30% bedre deteksjon  
**Kompleksitet:** Medium-High

### Tier 4: LOW PRIORITY (Ved behov)
8. **Sender Verification** - Risikabelt, kan forårsake problemer

---

## 🎯 Min Anbefaling (Quick Wins)

**Hvis du har 4 timer:**
```bash
1. Greylisting (postgrey)      - 2 timer  → 85% reduksjon
2. Rate Limiting (postfix)     - 1 time   → DDoS beskyttelse  
4. Fail2Ban                    - 1 time   → Brute-force beskyttelse
```

**Resultat:** 90-95% mindre spam + full DDoS/brute-force beskyttelse

**Hvis du har 8 timer (full upgrade):**
```bash
+ SPF/DKIM/DMARC              - 3 timer  → Stopper spoofing
+ Attachment Filtering        - 1 time   → Blokkerer malware
```

**Resultat:** Enterprise-grade e-postsikkerhet 🛡️

---

## 💡 Bonus: Hybrid Approach

Kombiner flere systemer for maksimal beskyttelse:

```
SMTP Connection
     ↓
1. Rate Limiting (Postfix) ← Stopper DDoS
     ↓
2. Geo-Blocking (hvis enabled) ← Blokkerer land
     ↓
3. Greylisting (Postgrey) ← 85% spam faller bort
     ↓
4. SPF/DKIM/DMARC (OpenDKIM) ← Verifiserer avsender
     ↓
5. Attachment Filter ← Blokkerer .exe, .scr
     ↓
6. ClamAV Scanning ← Virus-sjekk
     ↓
7. SpamAssassin (ditt nåværende system) ← Innholdsanalyse
     ↓
8. DNSBL Check (7 servere) ← IP reputation
     ↓
9. Fail2Ban ← Banner repeat offenders
     ↓
Deliver to Mailbox
```

**Total blokkering:** ~98-99% av spam! 🎯

---

## Velg Dine Prioriteringer

Svar med numrene du vil implementere, f.eks:
- `1, 2, 4` → Quick wins (4 timer)
- `1, 2, 3, 4, 6` → Full beskyttelse (8 timer)
- `Alle` → Maximum security (15-20 timer)

Jeg implementerer dem i rekkefølge! 🚀
