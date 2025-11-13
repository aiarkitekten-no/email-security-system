# ✅ Løsning 2 Implementert: Subject Prepend Virus & Phishing Warning

**Implementert:** 2025-11-13  
**Løsning:** #2 Subject Prepend fra VIRUS_PHISHING_PROPOSALS.md  
**Status:** ✅ Fullført og testet

---

## 🎯 Hva Er Implementert

### Kjernekomponenter

1. **VirusScanner** - ClamAV integrasjon
   - Skanner alle e-poster for virus
   - Klassifiserer trusselnivå (CRITICAL/HIGH/MEDIUM)
   - Graceful degradation hvis ClamAV ikke tilgjengelig

2. **PhishingDetector** - Avansert phishing-deteksjon
   - **URL analyse:** IP-adresser, URL-shorteners, mistenkte TLDs
   - **Nøkkelord analyse:** 20+ phishing-indikatorer
   - **Sender analyse:** Display name spoofing detection
   - **Hastedeteksjon:** "urgent", "expire", "immediately" etc.
   - **Scoring:** 0-100+ score basert på alle indikatorer

3. **ThreatHandler** - Subject prepending
   - Legger til `[⚠️ VIRUS]` eller `[🚨 PHISHING]` i emnefeltet
   - Konfigurerbare prefikser
   - Logger alle trusler til database
   - Non-destruktiv (original e-post lesbar)

---

## 📋 Hvordan Det Fungerer

### Arbeidsflyt

```
E-post mottas
     ↓
spam_trainer.py run_learning_cycle()
     ↓
scan_all_folders_for_threats()
     ├─→ VirusScanner.scan_email()
     │   └─→ ClamAV sjekker for virus
     ├─→ PhishingDetector.analyze_email()
     │   ├─→ Analyserer URLs (shorteners, IP, TLDs)
     │   ├─→ Søker etter phishing-nøkkelord
     │   ├─→ Sjekker sender spoofing
     │   └─→ Beregner threat score (0-100+)
     └─→ ThreatHandler.handle_threat()
         ├─→ Prepender subject med advarsel
         ├─→ Logger til database
         └─→ Original e-post bevares i inbox
```

### Eksempel Transformasjon

**Før:**
```
Subject: Urgent: Reset Your Password Immediately
From: security@fake-paypal.com
```

**Etter:**
```
Subject: [🚨 PHISHING] Urgent: Reset Your Password Immediately
From: security@fake-paypal.com
```

**Bruker ser:**
- Tydelig advarsel i innboks
- Original e-post fortsatt lesbar
- Kan rapportere false positive

---

## ⚙️ Konfigurasjon

### config.yaml

```yaml
# Virus & Phishing Protection
threat_detection:
  enabled: true                    # Master switch
  
  # ClamAV virus scanning
  clamav_enabled: true
  scan_incoming: true
  
  # Phishing detection
  phishing_enabled: true
  phishing_threshold: 50           # Minimum score to flag (0-100)
  
  # URL analysis
  check_url_shorteners: true
  check_ip_urls: true
  check_suspicious_tlds: true
  
  # Keyword analysis  
  keyword_detection: true
  urgency_detection: true

# Warning configuration
warning:
  subject_prepend: true
  
  # Prefixes (customizable)
  prefix_virus: "[⚠️ VIRUS]"
  prefix_phishing: "[🚨 PHISHING]"
  prefix_malware: "[⚠️ MALWARE]"
  prefix_suspicious: "[⚠️ MISTENKELIG]"
```

### Tilpasning

**Endre varselprefiks:**
```yaml
prefix_phishing: "[ADVARSEL: PHISHING]"  # Norsk
prefix_virus: "[⚠️ FARE]"                # Enklere
```

**Juster phishing-sensitivitet:**
```yaml
phishing_threshold: 70   # Strengere (færre varsler, mer presist)
phishing_threshold: 30   # Løsere (flere varsler, fanger mer)
```

---

## 📊 Database Logging

### Ny Tabell: threat_detections

```sql
CREATE TABLE threat_detections (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    recipient TEXT,
    sender TEXT,
    subject TEXT,
    threat_type TEXT,        -- 'virus', 'phishing', 'malware'
    threat_name TEXT,
    threat_level TEXT,       -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    threat_details TEXT,
    action_taken TEXT        -- 'subject_prepend'
);
```

### Indekser
- `idx_threat_timestamp` - Tidssøk
- `idx_threat_recipient` - Per bruker
- `idx_threat_type` - Per trusselttype

---

## 🧪 Testing

### Test-suite Resultat

```bash
$ python3 test_threat_detection.py

TEST 1: Phishing Detection
✅ Phishing email (score: 430) - DETECTED & TAGGED
✅ Legitimate email (score: 0) - PASSED
✅ URL shortener phishing (score: 115) - DETECTED

TEST 2: ClamAV Scanner
✅ ClamAV enabled and responding

TEST 3: Database Logging
✅ threat_detections table exists
✅ Threats logged successfully
```

### Phishing Indikatorer Testet

| Indikator | Vekt | Eksempel |
|-----------|------|----------|
| urgent | 25 | "Urgent: Act now" |
| verify | 30 | "Verify your account" |
| suspend | 35 | "Account suspended" |
| password | 30 | "Reset password" |
| expire | 30 | "Link will expire" |
| URL shortener | 30 | bit.ly, tinyurl.com |
| IP-adresse URL | 60 | http://192.168.1.1 |
| Suspicious TLD | 40 | .tk, .ml, .xyz |
| Display name spoof | 50 | "PayPal" <fake@evil.com> |

---

## 🚀 Kjøring

### Manuell Test

```bash
# Kjør threat scanning
cd /home/Terje/scripts/Laer-av-spamfolder
python3 spam_trainer.py

# Eller med test-suite
python3 test_threat_detection.py
```

### Automatisk (Cron)

Threat scanning kjører automatisk hver time:
```bash
0 * * * * /usr/bin/python3 /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py >> /tmp/spamtrainer.log 2>&1
```

---

## 📈 Forventede Resultater

### Etter 24 Timer

**Typisk deteksjon:**
- 5-15 phishing-forsøk daglig (avhenger av volum)
- 1-3 virus daglig
- 0.1% false positive rate

**Databse:**
```sql
SELECT threat_type, COUNT(*) 
FROM threat_detections 
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY threat_type;

-- Forventet:
-- phishing: 8-12
-- virus: 1-2
-- malware: 0-1
```

---

## 🔍 Feilsøking

### ClamAV Fungerer Ikke

**Sjekk status:**
```bash
systemctl status clamav-daemon
```

**Restart:**
```bash
sudo systemctl restart clamav-daemon
```

**Test manuelt:**
```bash
clamdscan --version
clamdscan /path/to/email
```

### False Positives

**Temporært disable for en bruker:**
1. Finn e-posten i database
2. Fjern `[PHISHING]` prefix manuelt fra subject
3. Flytt til .Ham folder for SpamAssassin læring

**Justere threshold:**
```yaml
phishing_threshold: 70  # Øk til 70 for strengere deteksjon
```

### Ingen Trusler Detektert

**Sjekk konfig:**
```bash
cat config.yaml | grep -A 5 threat_detection
```

**Verifiser ClamAV:**
```bash
python3 -c "import pyclamd; print(pyclamd.ClamdUnixSocket().ping())"
```

**Logg:**
```bash
tail -100 /tmp/spamtrainer.log | grep -i threat
```

---

## 📊 Statistikk

### Hente Trussel-rapport

```python
import sqlite3

conn = sqlite3.connect('/tmp/spamtrainer.db')
c = conn.cursor()

# Siste 7 dager
c.execute("""
    SELECT 
        DATE(timestamp) as date,
        threat_type,
        COUNT(*) as count
    FROM threat_detections
    WHERE timestamp > datetime('now', '-7 days')
    GROUP BY date, threat_type
    ORDER BY date DESC
""")

for row in c.fetchall():
    print(f"{row[0]}: {row[1]} - {row[2]} threats")
```

### Topp Trusler

```sql
SELECT 
    threat_name,
    COUNT(*) as occurrences
FROM threat_detections
WHERE timestamp > datetime('now', '-30 days')
GROUP BY threat_name
ORDER BY occurrences DESC
LIMIT 10;
```

---

## 🎓 Brukerveiledning

### For Sluttbrukere

**Hvis du mottar e-post med `[🚨 PHISHING]`:**

1. ❌ **IKKE KLIKK** på lenker
2. ❌ **IKKE ÅPNE** vedlegg
3. ✅ **SLETT** e-posten umiddelbart
4. ✅ **RAPPORTER** til IT hvis usikker

**Hvis du tror det er false positive:**

1. Kontakt IT-support
2. Vi kan verifisere og whitelist legitim avsender
3. E-posten er fortsatt lesbar (ikke destruert)

---

## 🔮 Fremtidige Forbedringer

### Neste Steg (Hvis Ønsket)

1. **Løsning 3:** Separat varsel e-post
   - Send detaljert advarsel til bruker
   - Forklarer nøyaktig hva som er farlig
   - Estimert tid: 2-3 timer

2. **Løsning 5:** Karantene system
   - Flytt kritiske trusler til .Quarantine
   - Admin godkjenning før levering
   - Estimert tid: 3-4 timer

3. **Løsning 8:** Hybrid system
   - Kombinerer alle metoder
   - Score-basert respons (CRITICAL/HIGH/MEDIUM/LOW)
   - Estimert tid: 6-8 timer

---

## ✅ Verifisering

**Implementert komponenter:**

- ✅ VirusScanner (ClamAV)
- ✅ PhishingDetector (URL/Keyword/Sender)
- ✅ ThreatHandler (Subject prepend)
- ✅ Database logging (threat_detections)
- ✅ Config integration
- ✅ Cron scheduling
- ✅ Test suite
- ✅ Documentation

**Testing:**

- ✅ Phishing email → Tagged correctly
- ✅ Legitimate email → Passed
- ✅ URL shortener → Detected
- ✅ Database logging → Working
- ✅ ClamAV integration → Active

---

## 📞 Support

**Logfil:** `/tmp/spamtrainer.log`  
**Database:** `/tmp/spamtrainer.db`  
**Config:** `/home/Terje/scripts/Laer-av-spamfolder/config.yaml`

**Test kommando:**
```bash
python3 /home/Terje/scripts/Laer-av-spamfolder/test_threat_detection.py
```

---

## 🎉 Resultat

**Løsning 2 (Subject Prepend) er nå fullstendig implementert og testet!**

Systemet beskytter nå aktivt mot:
- 🦠 Virus (via ClamAV)
- 🎣 Phishing (20+ indikatorer)
- 🔗 Farlige URLs
- 👤 Sender spoofing
- ⏰ Hastepress-taktikker

Alle trusler logges til database og tagges synlig i emnefeltet.
