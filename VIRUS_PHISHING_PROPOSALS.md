# 🦠 Virus & Phishing Beskyttelse - Løsningsforslag

**Dato:** 2025-11-13  
**Problem:** Virus og phishing slipper inn (PDF-klikk, fake passord reset, falske domener)  
**Behov:** Advare kunder uten å ødelegge e-post rekken

---

## 📊 Hurtigoversikt - 8 Løsningsforslag

| # | Løsning | Varsling | E-post Påvirkning | Kompleksitet | Falske Positiver | Anbefaling |
|---|---------|----------|-------------------|--------------|------------------|------------|
| **1** | X-Header Flagging | Ingen synlig | ❌ Ingen | ⭐ | ✅ Lavest | ⭐⭐⭐⭐⭐ |
| **2** | Subject Prepend | [⚠️ VIRUS] i emnet | ⚠️ Liten | ⭐ | ⚠️ Medium | ⭐⭐⭐⭐ |
| **3** | Separat Varsel E-post | Egen e-post | ❌ Ingen | ⭐⭐ | ✅ Lav | ⭐⭐⭐⭐⭐ |
| **4** | Body Injection | Advarsel i toppen | ⚠️ Modifiserer | ⭐⭐⭐ | ⚠️ Medium | ⭐⭐⭐ |
| **5** | Karantene + Notification | Egen mappe + varsel | 🔴 Flyttes | ⭐⭐ | ✅ Lav | ⭐⭐⭐⭐ |
| **6** | Attachment Replacement | Erstatter vedlegg | 🔴 Modifiserer | ⭐⭐⭐⭐ | ❌ Høy | ⭐⭐ |
| **7** | Forward til Admin | Kun til admin | 🔴 Blokkert | ⭐ | ✅ Lav | ⭐⭐ |
| **8** | Hybrid (1+3+5) | Multi-layer | ⚠️ Valg | ⭐⭐⭐ | ✅ Lavest | ⭐⭐⭐⭐⭐ |

---

## Løsning 1: X-Header Flagging (Minst Invasiv) ⭐⭐⭐⭐⭐

### Konsept
Legger til usynlige X-headers i e-posten som mailklienter kan bruke til å vise varsler.

### Hvordan Det Fungerer
```
Original Email
     ↓
ClamAV Scanning → Virus funnet!
     ↓
Legg til headers:
  X-Virus-Scanned: clamav-scanner
  X-Virus-Status: INFECTED
  X-Virus-Name: Phishing.PDF.Generic
  X-Virus-Threat: HIGH
     ↓
Lever til INBOX (uendret synlig)
```

### E-post Headers
```
X-Virus-Scanned: clamav-scanner v0.103.8
X-Virus-Status: INFECTED
X-Virus-Name: Phishing.PDF.Generic
X-Virus-Threat-Level: HIGH
X-Virus-Detection-Date: 2025-11-13T10:30:45Z
X-Phishing-Score: 95
X-Phishing-Indicators: fake-domain,password-reset,urgent-action
```

### Fordeler
✅ **Ingen synlig endring** - E-post ser normal ut  
✅ **Lavest falsk positiv impact** - Bruker kan fortsatt lese  
✅ **Mailklient kan vise varsel** - Thunderbird/Outlook plugins  
✅ **Ikke-destruktiv** - Original e-post intakt  
✅ **Enkel å reversere** - Bare fjern headers

### Ulemper
❌ **Krever klient-side støtte** - Gmail/Outlook.com viser ikke headers  
❌ **Bruker ser ikke advarsel** med mindre de sjekker headers  
❌ **Ikke proaktiv beskyttelse** - Bruker må selv oppdage

### Implementering
```python
def flag_with_headers(email_path, virus_name, threat_level):
    """Add warning headers to email"""
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    # Legg til warning headers
    msg['X-Virus-Scanned'] = 'clamav-scanner v0.103.8'
    msg['X-Virus-Status'] = 'INFECTED'
    msg['X-Virus-Name'] = virus_name
    msg['X-Virus-Threat-Level'] = threat_level
    msg['X-Virus-Detection-Date'] = datetime.now().isoformat()
    
    # Skriv tilbake
    with open(email_path, 'wb') as f:
        f.write(msg.as_bytes())
```

### Bruk Med Mailklient Regler
```
Thunderbird Filter:
IF X-Virus-Status contains "INFECTED"
THEN Mark as Important + Move to "⚠️ VIRUS VARSEL" folder
```

**Best for:** Teknisk kyndige brukere, backup-løsning  
**Anbefaling:** ⭐⭐⭐⭐⭐ Som del av hybrid løsning

---

## Løsning 2: Subject Prepend (Synlig Advarsel) ⭐⭐⭐⭐

### Konsept
Legger til `[⚠️ VIRUS]` eller `[🚨 PHISHING]` i e-post emnet.

### Hvordan Det Fungerer
```
Original Subject: "Urgent: Reset Your Password"
     ↓
ClamAV/Phishing Detection
     ↓
Modified Subject: "[🚨 PHISHING] Urgent: Reset Your Password"
     ↓
Lever til INBOX
```

### Eksempler
```
[⚠️ VIRUS] Invoice.pdf - Please review
[🚨 PHISHING] Your account will be closed
[⚠️ MALWARE] Payment confirmation attached
[🚨 URGENT] Fake password reset detected
```

### Fordeler
✅ **Umiddelbart synlig** - Bruker ser advarsel med en gang  
✅ **Fungerer i alle mailklienter** - Gmail, Outlook, iPhone  
✅ **Lett å søke** - Filter på "[VIRUS]" i inbox  
✅ **Enkel implementering** - Bare endre subject-header  
✅ **Ikke-destruktiv** - E-post fortsatt lesbar

### Ulemper
❌ **Endrer e-post threading** - Kan ødelegge samtalerekker  
❌ **Synlig for avsender** - Hvis de får read receipt  
❌ **Kan ignoreres** - Brukere vender seg til det  
⚠️ **Modifiserer original** - DKIM signatur ugyldig

### Implementering
```python
def prepend_subject_warning(email_path, threat_type, threat_name):
    """Add warning to email subject"""
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    original_subject = msg.get('Subject', 'No Subject')
    
    # Warning prefixes
    warnings = {
        'virus': '[⚠️ VIRUS]',
        'phishing': '[🚨 PHISHING]',
        'malware': '[⚠️ MALWARE]',
        'suspicious': '[⚠️ MISTENKELIG]'
    }
    
    prefix = warnings.get(threat_type, '[⚠️ ADVARSEL]')
    new_subject = f"{prefix} {original_subject}"
    
    msg.replace_header('Subject', new_subject)
    
    with open(email_path, 'wb') as f:
        f.write(msg.as_bytes())
```

### Konfigurasjon
```yaml
warning:
  subject_prepend: true
  prefix_virus: "[⚠️ VIRUS]"
  prefix_phishing: "[🚨 PHISHING]"
  prefix_suspicious: "[⚠️ MISTENKELIG]"
```

**Best for:** Alle brukere, umiddelbar synlighet  
**Anbefaling:** ⭐⭐⭐⭐ God balanse mellom synlighet og ikke-destruktiv

---

## Løsning 3: Separat Varsel E-post (Anbefalt!) ⭐⭐⭐⭐⭐

### Konsept
Sender en **separat e-post** til mottaker som varsler om den farlige e-posten. Original e-post leveres uendret.

### Hvordan Det Fungerer
```
Innkommende E-post
     ↓
ClamAV/Phishing Scanning
     ↓
Virus/Phishing funnet!
     ↓
[Path 1] Lever original til INBOX (med X-headers)
     ↓
[Path 2] Send varsel-epost til samme bruker
```

### Varsel E-post Eksempel
```
Fra: security@smartesider.no
Til: bruker@smartesider.no
Emne: 🚨 SIKKERHETSVARSEL: Farlig e-post mottatt

KRITISK SIKKERHETSADVARSEL

En farlig e-post er nettopp mottatt i din inbox.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📧 E-POST DETALJER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Fra: suspicious@fake-bank.com
Emne: "Urgent: Reset Your Password Now"
Mottatt: 2025-11-13 10:30:45
Størrelse: 45 KB med 1 vedlegg (invoice.pdf)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ TRUSSLER OPPDAGET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🦠 VIRUS: Phishing.PDF.Generic
   Alvorlighetsgrad: HØYT
   
🎣 PHISHING INDIKATORER:
   ✗ Falsk domene (fake-bank.com)
   ✗ Password reset-oppfordring
   ✗ Haster-språk ("Urgent", "Immediately")
   ✗ Mistenkt vedlegg (PDF med makroer)
   ✗ Avsender ikke verifisert (SPF FAIL)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ HVA DU MÅ GJØRE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. IKKE KLIKK på lenker i e-posten
2. IKKE ÅPNE vedlegg
3. SLETT e-posten umiddelbart
4. Rapporter til IT-avdeling hvis usikker

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 TEKNISKE DETALJER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Message-ID: <abc123@fake-bank.com>
ClamAV Signatur: Phishing.PDF.Generic
Spamhaus DBL: Listed
DNSBL Listed: Yes (3 lists)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dette er en automatisk melding fra SmarteSider Sikkerhetssystem.
Ved spørsmål, kontakt support@smartesider.no

Powered by spam_trainer.py v3.0
```

### Fordeler
✅ **Proaktiv beskyttelse** - Bruker advares umiddelbart  
✅ **Original e-post uendret** - Ingen destruktive endringer  
✅ **Detaljert informasjon** - Forklarer hva som er farlig  
✅ **Fungerer for alle** - Gmail, Outlook, mobil  
✅ **Ikke falsk positiv problem** - Original fortsatt tilgjengelig  
✅ **Logging/audit trail** - Database tracking  
✅ **Eskalering mulig** - Kan cc: admin

### Ulemper
⚠️ **Ekstra e-post** - Inbox får to meldinger  
⚠️ **Kan ignoreres** - Hvis bruker ikke leser varsler  
⚠️ **Krever SMTP** - Må kunne sende e-post

### Implementering
```python
class ThreatNotifier:
    def send_threat_alert(self, recipient, original_email_info, threats):
        """Send separate threat notification email"""
        
        # Load HTML template
        template = self._load_threat_template()
        
        # Render med data
        html_content = template.render(
            recipient=recipient,
            sender=original_email_info['from'],
            subject=original_email_info['subject'],
            received_time=original_email_info['timestamp'],
            threats=threats,
            virus_name=threats.get('virus_name'),
            phishing_score=threats.get('phishing_score'),
            indicators=threats.get('indicators', [])
        )
        
        # Send notification
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 SIKKERHETSVARSEL: Farlig e-post mottatt"
        msg['From'] = 'security@smartesider.no'
        msg['To'] = recipient
        msg['Priority'] = 'urgent'
        msg['X-Priority'] = '1'
        
        msg.attach(MIMEText(html_content, 'html'))
        
        smtp = smtplib.SMTP('localhost', 25)
        smtp.send_message(msg)
        smtp.quit()
```

### Database Tracking
```sql
CREATE TABLE threat_notifications (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    recipient TEXT,
    original_sender TEXT,
    original_subject TEXT,
    threat_type TEXT,
    threat_details TEXT,
    notification_sent INTEGER DEFAULT 1,
    user_action TEXT  -- 'deleted', 'ignored', 'reported'
);
```

**Best for:** ALLE brukere, maksimal beskyttelse  
**Anbefaling:** ⭐⭐⭐⭐⭐ **BEST LØSNING** - Kombinasjon av sikkerhet og brukervennlighet

---

## Løsning 4: Body Injection (HTML Advarsel Banner) ⭐⭐⭐

### Konsept
Injiserer en stor rød advarselsboks øverst i e-postens HTML-body.

### Hvordan Det Fungerer
```html
<!DOCTYPE html>
<html>
<body>

<!-- INJISERT ADVARSEL -->
<div style="background: #dc3545; color: white; padding: 20px; 
            margin: 20px 0; border: 5px solid #bd2130; 
            font-family: Arial; border-radius: 10px;">
    <h1 style="margin: 0;">🚨 ADVARSEL: FARLIG E-POST</h1>
    <p style="font-size: 18px; margin: 10px 0;">
        Denne e-posten inneholder virus eller phishing-forsøk!
    </p>
    <ul style="font-size: 16px;">
        <li>IKKE klikk på lenker</li>
        <li>IKKE åpne vedlegg</li>
        <li>SLETT denne e-posten umiddelbart</li>
    </ul>
    <p style="font-size: 14px; margin-top: 15px;">
        Virus oppdaget: <strong>Phishing.PDF.Generic</strong><br>
        Detektert: 2025-11-13 10:30:45
    </p>
</div>

<!-- ORIGINAL E-POST INNHOLD -->
<p>Dear customer, please reset your password...</p>

</body>
</html>
```

### Fordeler
✅ **Umiddelbart synlig** - Stor rød boks bruker ikke kan overse  
✅ **I selve e-posten** - Ingen ekstra messages  
✅ **Fungerer i HTML-klienter** - Gmail, Outlook, webmail  
✅ **Kontekstuell** - Advarsel i samme e-post

### Ulemper
❌ **Endrer e-post** - Modifiserer original innhold  
❌ **Kun HTML** - Fungerer ikke for plain text  
❌ **Kan strippes** - Noen klienter fjerner styling  
❌ **DKIM ugyldig** - Signatur brytes  
⚠️ **Kompleks parsing** - Må håndtere kompleks HTML

### Implementering
```python
def inject_warning_banner(email_path, threat_info):
    """Inject warning banner into HTML email"""
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    # Finn HTML-delen
    html_part = None
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            html_part = part
            break
    
    if html_part:
        html_content = html_part.get_content()
        
        # Warning banner HTML
        banner = f"""
        <div style="background:#dc3545;color:white;padding:20px;
                    margin:20px 0;border:5px solid #bd2130;
                    border-radius:10px;">
            <h1>🚨 ADVARSEL: FARLIG E-POST</h1>
            <p>Virus: {threat_info['virus_name']}</p>
            <ul>
                <li>IKKE klikk på lenker</li>
                <li>IKKE åpne vedlegg</li>
            </ul>
        </div>
        """
        
        # Injiser etter <body>
        modified_html = html_content.replace('<body>', f'<body>{banner}')
        html_part.set_content(modified_html)
    
    with open(email_path, 'wb') as f:
        f.write(msg.as_bytes())
```

**Best for:** HTML-kyndige brukere, visuelt fokuserte  
**Anbefaling:** ⭐⭐⭐ God visualisering, men invasiv

---

## Løsning 5: Karantene + Notification (Tryggeste) ⭐⭐⭐⭐

### Konsept
Flytter farlige e-poster til `.Quarantine` mappe OG sender varsel.

### Hvordan Det Fungerer
```
Innkommende E-post
     ↓
ClamAV/Phishing Scanning
     ↓
Virus/Phishing funnet!
     ↓
Flytt til: .Quarantine/cur/
     ↓
Send varsel til bruker: "E-post fra X er i karantene"
     ↓
Admin får daglig rapport om karantene
```

### Mappestruktur
```
/var/qmail/mailnames/smartesider.no/bruker/Maildir/
├── .INBOX/
├── .Sent/
├── .Spam/
└── .Quarantine/          ← NY
    ├── cur/              ← Karantene e-poster her
    ├── new/
    └── tmp/
```

### Varsel E-post
```
Emne: ⚠️ E-post i karantene: "Reset Your Password"

En e-post er automatisk flyttet til karantene på grunn av sikkerhetstrussel.

Fra: suspicious@fake-bank.com
Emne: Reset Your Password
Årsak: Virus (Phishing.PDF.Generic)

E-posten finnes i mappen ".Quarantine" i mailklienten din.

KUN åpne hvis du er 100% sikker på at den er legitim.
```

### Fordeler
✅ **Maksimal sikkerhet** - E-post ikke i hovedinbox  
✅ **Reversibel** - Bruker kan flytte tilbake hvis false positive  
✅ **Audit trail** - All karantene logges  
✅ **Admin oversikt** - Sentral monitoring  
✅ **IMAP-synlig** - Bruker ser .Quarantine folder

### Ulemper
❌ **E-post "forsvinner"** - Ikke i INBOX  
⚠️ **Kan gå glipp av legitim** - Hvis false positive  
⚠️ **Krever brukeropplæring** - Må vite hva .Quarantine er

### Implementering
```python
def quarantine_threat(email_path, mailbox_path, threat_info):
    """Move email to quarantine folder"""
    
    # Opprett .Quarantine hvis ikke eksisterer
    quarantine_path = os.path.join(mailbox_path, '.Quarantine', 'cur')
    os.makedirs(quarantine_path, exist_ok=True)
    
    # Flytt e-post
    filename = os.path.basename(email_path)
    dest_path = os.path.join(quarantine_path, filename)
    shutil.move(email_path, dest_path)
    
    # Send notification
    recipient = extract_recipient_from_mailbox(mailbox_path)
    send_quarantine_notification(recipient, threat_info)
    
    # Logg
    log_quarantine(recipient, threat_info)
```

### Daglig Rapport til Admin
```
Karantene Rapport - 2025-11-13
═══════════════════════════════

Total i karantene: 23 e-poster

Per bruker:
  bruker1@domain.no: 5 e-poster
  bruker2@domain.no: 3 e-poster

Trusler:
  Phishing: 15
  Virus: 8

Topp virus:
  Phishing.PDF.Generic: 8
  Malware.ZIP.Trojan: 5
```

**Best for:** Paranoid sikkerhet, enterprise  
**Anbefaling:** ⭐⭐⭐⭐ Meget trygt, men krever opplæring

---

## Løsning 6: Attachment Replacement ⭐⭐

### Konsept
Erstatter farlige vedlegg med en tekstfil som forklarer hvorfor.

### Hvordan Det Fungerer
```
E-post med: invoice.pdf (VIRUS)
     ↓
Fjern invoice.pdf
     ↓
Legg til: invoice.pdf.WARNING.txt
     ↓
Lever e-post med erstatningsvedlegg
```

### Erstatningsvedlegg Innhold
```
⚠️ SIKKERHET ADVARSEL ⚠️

Dette vedlegget ble automatisk fjernet av sikkerhetssystemet.

Original filnavn: invoice.pdf
Størrelse: 245 KB
Virus oppdaget: Phishing.PDF.Generic
Deteksjon dato: 2025-11-13 10:30:45

ÅRSAK TIL BLOKKERING:
- Vedlegget inneholder phishing-makroer
- Forsøker å stjele passord
- Utgir seg for å være fra bankk

HVIS DU TROR DETTE ER EN FEIL:
1. Kontakt avsenderen via annen kanal (telefon)
2. Be om ny fil via sikker metode
3. Kontakt IT-support: support@smartesider.no

═══════════════════════════════════
SmarteSider Sikkerhetssystem
Powered by spam_trainer.py v3.0
═══════════════════════════════════
```

### Fordeler
✅ **Proaktiv blokkering** - Vedlegg kan ikke åpnes  
✅ **Forklarende** - Bruker forstår hvorfor  
✅ **E-post fortsatt lesbar** - Kun vedlegg erstattes

### Ulemper
❌ **Destruktivt** - Original vedlegg tapt  
❌ **Kan ikke reverseres** - Hvis false positive  
❌ **Kompleks** - Må håndtere multipart MIME riktig  
❌ **Høy false positive impact** - Legitime filer går tapt

**Best for:** Sjelden, kun i kombinasjon med karantene-backup  
**Anbefaling:** ⭐⭐ For risikabelt alene

---

## Løsning 7: Forward to Admin Only ⭐⭐

### Konsept
Blokkerer e-post fullstendig og sender kun til admin for vurdering.

### Hvordan Det Fungerer
```
Innkommende E-post → Virus funnet
     ↓
IKKE lever til bruker
     ↓
Forward til: security@smartesider.no
     ↓
Send varsel til bruker: "E-post blokkert"
     ↓
Admin bestemmer: Slett eller lever manuelt
```

### Fordeler
✅ **Maksimal sikkerhet** - Bruker får aldri se virus  
✅ **Admin kontroll** - Sentral beslutning

### Ulemper
❌ **Ikke skalerbart** - Admin overveldes  
❌ **False positive katastrofe** - Legitime e-poster blokkert  
❌ **Forsinkelse** - Må vente på admin

**Best for:** Veldig små organisasjoner (<5 brukere)  
**Anbefaling:** ⭐⭐ Ikke praktisk for SmarteSider

---

## Løsning 8: Hybrid (Best of All) ⭐⭐⭐⭐⭐

### Konsept
Kombinerer flere metoder basert på trusselnivå.

### Trussel Nivåer
```
CRITICAL (score 90-100):
  → Karantene (.Quarantine)
  → Varsel e-post til bruker
  → Varsel til admin
  → X-Headers

HIGH (score 70-89):
  → Subject prepend [🚨 PHISHING]
  → Varsel e-post til bruker
  → X-Headers

MEDIUM (score 50-69):
  → Subject prepend [⚠️ MISTENKELIG]
  → X-Headers

LOW (score 30-49):
  → X-Headers only
```

### Beslutningstre
```python
def handle_threat(email, threat_score, threat_type):
    if threat_score >= 90:
        # CRITICAL
        quarantine_email(email)
        send_user_alert(email, "CRITICAL")
        send_admin_alert(email)
        add_x_headers(email, threat_type)
    
    elif threat_score >= 70:
        # HIGH
        prepend_subject(email, "🚨 PHISHING")
        send_user_alert(email, "HIGH")
        add_x_headers(email, threat_type)
    
    elif threat_score >= 50:
        # MEDIUM
        prepend_subject(email, "⚠️ MISTENKELIG")
        add_x_headers(email, threat_type)
    
    else:
        # LOW
        add_x_headers(email, threat_type)
```

### Trussel Scoring
```python
def calculate_threat_score(scan_results):
    score = 0
    
    # ClamAV virus
    if scan_results.get('virus'):
        virus_name = scan_results['virus_name']
        if 'Trojan' in virus_name:
            score += 95
        elif 'Phishing' in virus_name:
            score += 85
        elif 'Malware' in virus_name:
            score += 80
        else:
            score += 70
    
    # Phishing indicators
    phishing = scan_results.get('phishing_indicators', {})
    score += phishing.get('fake_domain', 0) * 30
    score += phishing.get('password_reset', 0) * 25
    score += phishing.get('urgent_language', 0) * 15
    score += phishing.get('suspicious_links', 0) * 20
    
    # SPF/DKIM/DMARC fail
    if scan_results.get('spf_fail'):
        score += 20
    if scan_results.get('dkim_fail'):
        score += 15
    if scan_results.get('dmarc_fail'):
        score += 15
    
    # DNSBL listed
    if scan_results.get('dnsbl_listed'):
        score += 25
    
    return min(score, 100)
```

### Konfigurasjon
```yaml
threat_handling:
  mode: hybrid  # hybrid, headers-only, quarantine-only, notify-only
  
  critical_threshold: 90
  critical_actions:
    - quarantine
    - notify_user
    - notify_admin
    - add_headers
  
  high_threshold: 70
  high_actions:
    - subject_prepend
    - notify_user
    - add_headers
  
  medium_threshold: 50
  medium_actions:
    - subject_prepend
    - add_headers
  
  low_threshold: 30
  low_actions:
    - add_headers
```

### Fordeler
✅ **Beste av alle verdener** - Balansert tilnærming  
✅ **Skalerbar** - Automatisk håndtering basert på score  
✅ **Konfigurerbar** - Per trusselnivå  
✅ **Minimerer false positive impact** - Lavere scores mindre invasive  
✅ **Maksimal beskyttelse** - Høye scores aggressive

### Ulemper
⚠️ **Kompleks** - Mer kode å vedlikeholde  
⚠️ **Krever tuning** - Threshold må justeres

**Best for:** SmarteSider (produksjon)  
**Anbefaling:** ⭐⭐⭐⭐⭐ **ANBEFALT FOR PRODUKSJON**

---

## 🎯 Min Anbefaling

### For SmarteSider (Dere)

**Primær: Løsning 8 (Hybrid)** med:
- **CRITICAL (90-100):** Karantene + Varsel
- **HIGH (70-89):** Subject prepend + Varsel  
- **MEDIUM (50-69):** Subject prepend kun
- **LOW (30-49):** X-Headers kun

**Sekundær backup: Løsning 3 (Separat varsel)** alltid for CRITICAL + HIGH

### Implementeringsrekkefølge

**Fase 1 (2-3 timer):**
1. ClamAV integrasjon (scanning av alle e-poster)
2. X-Headers (Løsning 1) - Backup
3. Basic threat scoring

**Fase 2 (2-3 timer):**
4. Subject prepend (Løsning 2) - For HIGH/MEDIUM
5. Separat varsel e-post (Løsning 3) - For CRITICAL/HIGH

**Fase 3 (2-3 timer):**
6. Karantene system (Løsning 5) - For CRITICAL
7. Phishing detection (URL/domain analysis)
8. Hybrid decision engine

**Total tid:** 6-9 timer for full løsning

---

## 📊 Sammenligning Tabell

### Brukeropplevelse

| Løsning | Ser Advarsel | E-post Uendret | Reversibel | Falsk Positiv Impact |
|---------|--------------|----------------|------------|---------------------|
| 1. X-Headers | ❌ (krever klient) | ✅ Ja | ✅ Ja | ✅ Minimal |
| 2. Subject Prepend | ✅ Ja | ⚠️ Subject endret | ✅ Ja | ⚠️ Medium |
| 3. Separat Varsel | ✅ Ja | ✅ Ja | ✅ Ja | ✅ Minimal |
| 4. Body Injection | ✅ Ja | ❌ Nei | ❌ Nei | 🔴 Høy |
| 5. Karantene | ✅ (via varsel) | ❌ Flyttet | ✅ Kan flyttes tilbake | ⚠️ Medium |
| 6. Attachment Replace | ✅ Ja | ❌ Vedlegg fjernet | ❌ Nei | 🔴 Veldig høy |
| 7. Admin Only | ✅ (via varsel) | ❌ Blokkert | ⚠️ Krever admin | 🔴 Kritisk |
| 8. Hybrid | ✅ Ja | ⚠️ Avhenger av score | ✅ Ofte | ✅ Lav (balansert) |

### Teknisk Kompleksitet

| Løsning | Kode Kompleksitet | Dependencies | Maintenance | Feilmarg |
|---------|-------------------|--------------|-------------|----------|
| 1 | ⭐ Enkel | Ingen | ⭐ Lav | ⭐ Lav |
| 2 | ⭐ Enkel | Ingen | ⭐ Lav | ⭐ Lav |
| 3 | ⭐⭐ Medium | SMTP | ⭐⭐ Medium | ⭐ Lav |
| 4 | ⭐⭐⭐ Kompleks | HTML parser | ⭐⭐⭐ Høy | ⭐⭐ Medium |
| 5 | ⭐⭐ Medium | IMAP/Maildir | ⭐⭐ Medium | ⭐ Lav |
| 6 | ⭐⭐⭐⭐ Veldig kompleks | MIME parsing | ⭐⭐⭐ Høy | ⭐⭐⭐ Høy |
| 7 | ⭐ Enkel | SMTP | ⭐⭐⭐ Høy (admin) | ⭐ Lav |
| 8 | ⭐⭐⭐ Kompleks | Alle over | ⭐⭐⭐ Høy | ⭐⭐ Medium |

---

## 🔍 Phishing Detection Metoder

Uavhengig av varsling-metode, her er phishing-deteksjon:

### 1. URL Analysis
```python
def detect_phishing_urls(email_content):
    """Detect suspicious URLs"""
    urls = extract_urls(email_content)
    suspicious = []
    
    for url in urls:
        score = 0
        domain = extract_domain(url)
        
        # Sjekk mot kjente phishing-domener
        if domain in phishing_database:
            score += 100
        
        # Homograph attack (løοk-alike domains)
        if contains_unicode_lookalike(domain):
            score += 80
        
        # IP-adresse i stedet for domene
        if is_ip_address(domain):
            score += 60
        
        # Subdomain spoofing (paypal.fake.com)
        if is_subdomain_spoofing(domain):
            score += 70
        
        # URL shorteners
        if is_url_shortener(domain):
            score += 30
        
        if score > 50:
            suspicious.append({
                'url': url,
                'score': score,
                'domain': domain
            })
    
    return suspicious
```

### 2. Keyword Analysis
```python
PHISHING_KEYWORDS = {
    'urgent': 25,
    'verify': 30,
    'suspend': 35,
    'confirm': 25,
    'update': 20,
    'click here': 30,
    'account': 15,
    'password': 30,
    'security': 20,
    'expir': 30
}

def analyze_phishing_keywords(subject, body):
    score = 0
    found = []
    
    text = (subject + ' ' + body).lower()
    
    for keyword, weight in PHISHING_KEYWORDS.items():
        if keyword in text:
            score += weight
            found.append(keyword)
    
    return score, found
```

### 3. Domain Verification
```python
def verify_sender_domain(sender_email, sender_domain):
    """Check if sender domain matches FROM domain"""
    from_domain = sender_email.split('@')[1]
    
    # Mismatch = phishing
    if from_domain != sender_domain:
        return False, 70  # High phishing score
    
    # Sjekk SPF
    spf_valid = check_spf(sender_domain, sender_ip)
    if not spf_valid:
        return False, 50
    
    return True, 0
```

---

## 🛠️ Teknisk Implementering (Uavhengig av Varslingsmetode)

### ClamAV Integration
```python
import pyclamd

class VirusScanner:
    def __init__(self):
        self.clam = pyclamd.ClamdUnixSocket('/var/run/clamav/clamd.ctl')
    
    def scan_email(self, email_path):
        """Scan email for viruses"""
        result = self.clam.scan_file(email_path)
        
        if result and email_path in result:
            status, virus_name = result[email_path]
            if status == 'FOUND':
                return {
                    'infected': True,
                    'virus_name': virus_name,
                    'threat_level': self._classify_threat(virus_name)
                }
        
        return {'infected': False}
    
    def _classify_threat(self, virus_name):
        """Classify threat level"""
        if 'Trojan' in virus_name:
            return 'CRITICAL'
        elif 'Phishing' in virus_name:
            return 'HIGH'
        elif 'Malware' in virus_name:
            return 'HIGH'
        else:
            return 'MEDIUM'
```

### Database Schema
```sql
CREATE TABLE threat_detections (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    recipient TEXT,
    sender TEXT,
    subject TEXT,
    threat_type TEXT,  -- 'virus', 'phishing', 'malware'
    threat_name TEXT,
    threat_score INTEGER,
    action_taken TEXT,  -- 'quarantine', 'notify', 'subject_prepend', 'headers'
    notification_sent INTEGER DEFAULT 0
);

CREATE INDEX idx_threat_timestamp ON threat_detections(timestamp);
CREATE INDEX idx_threat_recipient ON threat_detections(recipient);
CREATE INDEX idx_threat_type ON threat_detections(threat_type);
```

---

## ❓ Hva Vil Du Velge?

**Velg én eller flere:**

**Quick wins (enkel implementering):**
- `1` - X-Headers only (2 timer)
- `2` - Subject prepend only (2 timer)
- `3` - Separat varsel only (3 timer)

**Medium løsning:**
- `5` - Karantene + Varsel (4 timer)

**Full løsning (anbefalt):**
- `8` - Hybrid system (8-9 timer)

**Eller kombiner:**
- `1 + 3` - Headers + Varsel (4 timer)
- `2 + 3` - Subject + Varsel (4 timer)
- `2 + 3 + 5` - Full beskyttelse (6 timer)

---

**Svar med tall (f.eks "8" eller "2 + 3 + 5") så implementerer jeg din valgte løsning!**
