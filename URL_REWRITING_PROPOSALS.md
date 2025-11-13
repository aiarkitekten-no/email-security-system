# 🔗 URL Rewriting & Link Protection - Implementasjonsforslag

**Dato:** 2025-11-13  
**Funksjon:** Erstatte/rewrites farlige lenker i e-poster for å beskytte mot phishing  
**Status:** FORSLAG (ikke implementert ennå)

---

## 📋 Innholdsfortegnelse

1. [Hurtigoversikt - 8 Forslag](#hurtigoversikt)
2. [Forslag 1: URL Proxy Redirect](#forslag-1-url-proxy-redirect)
3. [Forslag 2: Safe Browse Gateway](#forslag-2-safe-browse-gateway)
4. [Forslag 3: Time-of-Click Protection](#forslag-3-time-of-click-protection)
5. [Forslag 4: URL Metadata Injection](#forslag-4-url-metadata-injection)
6. [Forslag 5: Visual Warning Overlay](#forslag-5-visual-warning-overlay)
7. [Forslag 6: Link Sandboxing](#forslag-6-link-sandboxing)
8. [Forslag 7: Smart Link Replacement](#forslag-7-smart-link-replacement)
9. [Forslag 8: Hybrid Multi-Layer](#forslag-8-hybrid-multi-layer)
10. [Prisanbefaling](#prisanbefaling)
11. [SaaS-Modell (SpamExperts-lignende)](#saas-modell)

---

## 📊 Hurtigoversikt - 8 Forslag

| # | Løsning | Beskyttelse | Brukeropplevelse | Kompleksitet | Implementeringstid | Anbefaling |
|---|---------|-------------|------------------|--------------|-------------------|------------|
| **1** | URL Proxy Redirect | 🟢 Høy | ⚠️ Ekstra klikk | ⭐⭐ | 20-30 timer | ⭐⭐⭐⭐ |
| **2** | Safe Browse Gateway | 🟢 Høy | ⚠️ Delay | ⭐⭐⭐ | 30-40 timer | ⭐⭐⭐⭐⭐ |
| **3** | Time-of-Click | 🟢 Veldig høy | ✅ Usynlig | ⭐⭐⭐⭐ | 40-60 timer | ⭐⭐⭐⭐⭐ |
| **4** | URL Metadata | 🟡 Medium | ✅ Usynlig | ⭐ | 10-15 timer | ⭐⭐⭐ |
| **5** | Visual Warning | 🟡 Medium | ⚠️ Pop-ups | ⭐⭐⭐ | 25-35 timer | ⭐⭐⭐ |
| **6** | Link Sandboxing | 🟢 Veldig høy | ⚠️ Preview | ⭐⭐⭐⭐⭐ | 80-120 timer | ⭐⭐⭐⭐ |
| **7** | Smart Replacement | 🟢 Høy | ✅ Transparent | ⭐⭐⭐ | 35-50 timer | ⭐⭐⭐⭐⭐ |
| **8** | Hybrid Multi-Layer | 🟢 Maksimal | ⚠️ Varierer | ⭐⭐⭐⭐ | 60-80 timer | ⭐⭐⭐⭐⭐ |

---

## Forslag 1: URL Proxy Redirect

### 🎯 Konsept
Erstatter alle lenker i e-posten med en proxy-URL som sjekker lenken før redirect.

### 🔄 Hvordan Det Fungerer

```
Original e-post:
  "Klikk her: https://evil-bank.com/login"

     ↓ URL Rewriting

Modifisert e-post:
  "Klikk her: https://safe.smartesider.no/check?url=aHR0cHM6Ly9ldmlsLWJhbmsuY29tL2xvZ2lu&token=abc123"

     ↓ Bruker klikker

Proxy-server:
  1. Dekoder URL
  2. Sjekker mot threat-databaser
  3. Hvis trygg → redirect til original
  4. Hvis farlig → vis advarsel
```

### 🛠️ Teknisk Implementering

#### 1.1 URL Extraction & Replacement
```python
def rewrite_urls_in_email(email_path):
    """Rewrite all URLs in email to proxy"""
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    # Finn alle lenker
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                html = part.get_content()
                modified_html = rewrite_html_links(html)
                part.set_content(modified_html)
            elif part.get_content_type() == 'text/plain':
                text = part.get_content()
                modified_text = rewrite_text_links(text)
                part.set_content(modified_text)
    
    # Skriv tilbake
    with open(email_path, 'wb') as f:
        f.write(msg.as_bytes())

def rewrite_html_links(html_content):
    """Rewrite <a href> tags"""
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html_content, 'html.parser')
    
    for link in soup.find_all('a', href=True):
        original_url = link['href']
        
        # Skip internal/safe domains
        if is_safe_domain(original_url):
            continue
        
        # Generer proxy URL
        proxy_url = generate_proxy_url(original_url)
        link['href'] = proxy_url
        
        # Legg til visuell indikator
        link['title'] = f"Protected link (original: {original_url[:50]}...)"
    
    return str(soup)

def generate_proxy_url(original_url):
    """Generate proxy redirect URL"""
    import base64
    import hmac
    import hashlib
    
    # Base64-encode original URL
    encoded_url = base64.urlsafe_b64encode(original_url.encode()).decode()
    
    # Generer HMAC token (forhindrer manipulation)
    secret_key = load_secret_key()
    token = hmac.new(
        secret_key.encode(),
        encoded_url.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    
    # Bygg proxy URL
    proxy_url = f"https://safe.smartesider.no/check?url={encoded_url}&token={token}"
    
    return proxy_url
```

#### 1.2 Proxy Server (Flask/FastAPI)
```python
from flask import Flask, request, redirect, render_template
import base64

app = Flask(__name__)

@app.route('/check')
def check_url():
    """Check URL and redirect or warn"""
    
    # Hent parameters
    encoded_url = request.args.get('url')
    token = request.args.get('token')
    
    # Valider token (forhindre URL manipulation)
    if not validate_token(encoded_url, token):
        return "Invalid request", 400
    
    # Dekoder original URL
    try:
        original_url = base64.urlsafe_b64decode(encoded_url).decode()
    except:
        return "Invalid URL", 400
    
    # Sjekk mot threat-databaser
    threat_check = check_url_threats(original_url)
    
    if threat_check['is_threat']:
        # Vis advarselside
        return render_template('warning.html',
            url=original_url,
            threats=threat_check['threats'],
            risk_score=threat_check['score']
        )
    
    # Trygg URL - redirect
    return redirect(original_url, code=302)

def check_url_threats(url):
    """Check URL against threat databases"""
    threats = []
    score = 0
    
    # 1. Google Safe Browsing
    if google_safe_browsing_check(url):
        threats.append('Google Safe Browsing: MALWARE')
        score += 100
    
    # 2. PhishTank
    if phishtank_check(url):
        threats.append('PhishTank: PHISHING')
        score += 100
    
    # 3. URLhaus
    if urlhaus_check(url):
        threats.append('URLhaus: MALWARE')
        score += 100
    
    # 4. Domain reputation
    domain_score = check_domain_reputation(url)
    score += domain_score
    
    # 5. Homograph detection
    if detect_homograph_attack(url):
        threats.append('Homograph attack detected')
        score += 80
    
    return {
        'is_threat': score >= 50,
        'threats': threats,
        'score': score
    }
```

#### 1.3 Warning Page Template
```html
<!-- templates/warning.html -->
<!DOCTYPE html>
<html>
<head>
    <title>⚠️ SIKKERHETSADVARSEL</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .warning-box {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .warning-header {
            text-align: center;
            color: #dc3545;
            font-size: 48px;
            margin-bottom: 20px;
        }
        .risk-score {
            background: #dc3545;
            color: white;
            padding: 10px 20px;
            border-radius: 10px;
            display: inline-block;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .threat-list {
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }
        .url-display {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            word-break: break-all;
            font-family: monospace;
            margin: 20px 0;
        }
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 30px;
        }
        .btn {
            flex: 1;
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
            display: block;
        }
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        .btn-safe {
            background: #28a745;
            color: white;
        }
    </style>
</head>
<body>
    <div class="warning-box">
        <div class="warning-header">⚠️ ADVARSEL</div>
        <h2>Farlig Lenke Oppdaget!</h2>
        
        <div class="risk-score">
            🚨 Risikoscore: {{ risk_score }}/100
        </div>
        
        <p style="font-size: 18px; margin: 20px 0;">
            Lenken du forsøkte å åpne er flagget som farlig av våre sikkerhetssystemer.
        </p>
        
        <div class="threat-list">
            <strong>⚠️ Trusler oppdaget:</strong>
            <ul>
                {% for threat in threats %}
                <li>{{ threat }}</li>
                {% endfor %}
            </ul>
        </div>
        
        <div class="url-display">
            <strong>URL:</strong><br>
            {{ url }}
        </div>
        
        <h3>🛡️ Hva Bør Du Gjøre?</h3>
        <ul>
            <li>❌ <strong>IKKE</strong> fortsett til denne siden</li>
            <li>📧 Slett e-posten denne lenken kom fra</li>
            <li>📞 Kontakt avsender via en annen kanal hvis du kjenner dem</li>
            <li>🔒 Skift passord hvis du har klikket tidligere</li>
        </ul>
        
        <div class="button-group">
            <a href="javascript:history.back()" class="btn btn-safe">
                ← Gå Tilbake (Anbefalt)
            </a>
            <a href="{{ url }}" class="btn btn-danger" 
               onclick="return confirm('Er du SIKKER på at du vil fortsette til denne farlige siden?')">
                ⚠️ Fortsett Likevel (Farlig!)
            </a>
        </div>
        
        <p style="margin-top: 30px; font-size: 12px; color: #6c757d; text-align: center;">
            Beskyttet av SmarteSider Sikkerhetssystem<br>
            Powered by spam_trainer.py v3.2
        </p>
    </div>
</body>
</html>
```

### ✅ Fordeler
- **Høy beskyttelse:** Alle lenker sjekkes før åpning
- **Time-of-click:** Oppdaterte threat-data ved klikk
- **Reversibel:** Bruker kan fortsette hvis false positive
- **Audit trail:** Logger alle klikk og trusler
- **Skalerbar:** Proxy kan håndtere mange requests

### ❌ Ulemper
- **Ekstra klikk:** Bruker opplever redirect-delay (100-300ms)
- **Privacy:** Alle klikk går via proxy (logging)
- **Endrer lenker:** DKIM-signatur ugyldig
- **Krever hosting:** Proxy-server må kjøre 24/7
- **Kompleksitet:** Må vedlikeholde proxy-infrastruktur

### 📊 Tekniske Krav
- **Frontend:** URL rewriting i e-post
- **Backend:** Flask/FastAPI proxy-server
- **Database:** URL cache, threat-log
- **SSL:** HTTPS sertifikat for proxy-domene
- **Monitoring:** Uptime, latency, threat-rate

### ⏱️ Implementeringstid
**20-30 timer:**
- URL parsing & rewriting: 8 timer
- Proxy server: 10 timer
- Warning page UI: 4 timer
- Testing & deployment: 6 timer

### 💰 Kostnad
- **Utvikling:** 20-30 timer × 1000 kr = **20,000-30,000 kr**
- **Drift:** VPS (4GB RAM): **200-500 kr/mnd**
- **SSL sertifikat:** Gratis (Let's Encrypt)

---

## Forslag 2: Safe Browse Gateway

### 🎯 Konsept
Bygger videre på Forslag 1, men legger til **pre-scanning** av alle lenker før e-posten leveres.

### 🔄 Hvordan Det Fungerer

```
E-post mottas
     ↓
Ekstraher alle URLs
     ↓
Sjekk hver URL mot threat-databaser
     ↓
Kategoriser:
  - 🟢 SAFE: Behold original
  - 🟡 UNKNOWN: Rewrite til proxy
  - 🔴 DANGEROUS: Rewrite + inject warning
     ↓
Lever e-post med modifiserte lenker
```

### 🛠️ Teknisk Implementering

```python
class SafeBrowseGateway:
    def __init__(self):
        self.threat_cache = {}  # Cache threat checks
        self.safe_domains = load_safe_domains()
    
    def process_email(self, email_path):
        """Pre-scan all URLs before delivery"""
        
        # 1. Ekstraher alle URLs
        urls = self.extract_all_urls(email_path)
        
        # 2. Pre-scan
        url_classifications = {}
        for url in urls:
            classification = self.classify_url(url)
            url_classifications[url] = classification
        
        # 3. Rewrite basert på klassifisering
        self.rewrite_based_on_classification(email_path, url_classifications)
        
        return url_classifications
    
    def classify_url(self, url):
        """Classify URL: SAFE, UNKNOWN, DANGEROUS"""
        
        # Sjekk cache først
        if url in self.threat_cache:
            cached = self.threat_cache[url]
            if cached['timestamp'] > time.time() - 3600:  # 1 hour
                return cached['classification']
        
        domain = extract_domain(url)
        
        # 1. Kjente safe domains
        if domain in self.safe_domains:
            return self._cache_result(url, 'SAFE', 0, [])
        
        # 2. Threat database checks
        threats = []
        score = 0
        
        # Google Safe Browsing
        if google_safe_browsing_check(url):
            threats.append('Google: MALWARE')
            score += 100
        
        # PhishTank
        if phishtank_check(url):
            threats.append('PhishTank: PHISHING')
            score += 100
        
        # URLhaus
        if urlhaus_check(url):
            threats.append('URLhaus: MALWARE')
            score += 100
        
        # Domain reputation
        domain_rep = check_domain_reputation(domain)
        score += domain_rep['score']
        threats.extend(domain_rep['threats'])
        
        # Klassifiser
        if score >= 70:
            classification = 'DANGEROUS'
        elif score >= 30:
            classification = 'UNKNOWN'
        else:
            classification = 'SAFE'
        
        return self._cache_result(url, classification, score, threats)
    
    def _cache_result(self, url, classification, score, threats):
        """Cache classification result"""
        result = {
            'classification': classification,
            'score': score,
            'threats': threats,
            'timestamp': time.time()
        }
        self.threat_cache[url] = result
        return result
    
    def rewrite_based_on_classification(self, email_path, classifications):
        """Rewrite URLs based on classification"""
        
        with open(email_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                html = part.get_content()
                
                for url, classification in classifications.items():
                    if classification['classification'] == 'SAFE':
                        # Behold original
                        continue
                    
                    elif classification['classification'] == 'UNKNOWN':
                        # Rewrite til proxy
                        proxy_url = generate_proxy_url(url)
                        html = html.replace(
                            f'href="{url}"',
                            f'href="{proxy_url}" title="Protected link"'
                        )
                    
                    elif classification['classification'] == 'DANGEROUS':
                        # Rewrite + inject inline warning
                        proxy_url = generate_proxy_url(url)
                        html = html.replace(
                            f'href="{url}"',
                            f'href="{proxy_url}" style="color:red;text-decoration:line-through;" '
                            f'title="⚠️ DANGEROUS: {classification["threats"]}"'
                        )
                        
                        # Inject warning before link
                        warning_html = f'''
                        <span style="background:#dc3545;color:white;padding:2px 8px;
                                     border-radius:3px;font-size:11px;font-weight:bold;">
                            ⚠️ FARLIG LENKE
                        </span>
                        '''
                        html = html.replace(
                            f'<a href="{proxy_url}"',
                            f'{warning_html} <a href="{proxy_url}"'
                        )
                
                part.set_content(html)
        
        with open(email_path, 'wb') as f:
            f.write(msg.as_bytes())
```

### ✅ Fordeler
- **Proaktiv:** Sjekker før levering
- **Bedre UX:** SAFE lenker er uendret (raskere)
- **Visuell warning:** Farlige lenker får rød styling
- **Cache:** Raskere for kjente URLs
- **Hybrid:** Kombinerer flere metoder

### ❌ Ulemper
- **Delivery delay:** Må scanne alle URLs (200-500ms per URL)
- **API rate limits:** Kan treffe Google/PhishTank limits
- **Kompleksitet:** Mer kode å vedlikeholde

### ⏱️ Implementeringstid
**30-40 timer:**
- URL classification: 12 timer
- Cache system: 6 timer
- Inline warning injection: 8 timer
- Testing: 8 timer

### 💰 Kostnad
**30,000-40,000 kr** utvikling + **300-600 kr/mnd** drift

---

## Forslag 3: Time-of-Click Protection

### 🎯 Konsept
Den **mest avanserte** løsningen - sjekker URLs **på nytt ved klikk-tidspunkt**, ikke bare ved levering.

### 🔄 Hvordan Det Fungerer

```
E-post leveres (T0)
  URLs rewritten til: safe.smartesider.no/click/abc123

Bruker leser e-post (T+2 timer)
  Threat-databaser oppdatert i mellomtiden

Bruker klikker lenke (T+3 timer)
     ↓
Proxy sjekker URL på nytt (real-time)
     ↓
  Hvis trygg NÅ → redirect
  Hvis farlig NÅ → blokkér
```

### 🛡️ Beskyttelse Mot

**Zero-Day Phishing:**
- URL var safe ved T0
- Ble kompromittert ved T+2 timer
- Blokkeres likevel ved T+3 timer (klikk)

**Delayed Activation:**
- Phisher aktiverer farlig side timer/dager etter e-post sendt
- Tradisjonell scanning mister dette
- Time-of-click fanger det

### 🛠️ Teknisk Implementering

```python
class TimeOfClickProtection:
    def __init__(self):
        self.url_tracking_db = Database('url_tracking.db')
        self._init_db()
    
    def _init_db(self):
        """Create URL tracking table"""
        self.url_tracking_db.execute("""
            CREATE TABLE IF NOT EXISTS tracked_urls (
                id INTEGER PRIMARY KEY,
                tracking_id TEXT UNIQUE,
                original_url TEXT,
                recipient TEXT,
                email_subject TEXT,
                first_check_time TEXT,
                first_check_status TEXT,  -- 'safe', 'unknown', 'dangerous'
                first_check_score INTEGER,
                click_count INTEGER DEFAULT 0,
                last_click_time TEXT,
                last_check_status TEXT,
                last_check_score INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS url_clicks (
                id INTEGER PRIMARY KEY,
                tracking_id TEXT,
                click_time TEXT,
                status TEXT,
                threats TEXT,
                user_action TEXT  -- 'allowed', 'blocked', 'warned'
            );
        """)
    
    def rewrite_url_with_tracking(self, original_url, recipient, email_subject):
        """Generate tracking URL"""
        
        # Generer unik tracking ID
        tracking_id = generate_unique_id()
        
        # Initial threat check
        initial_check = self.check_url_threats(original_url)
        
        # Lagre i database
        self.url_tracking_db.execute("""
            INSERT INTO tracked_urls 
            (tracking_id, original_url, recipient, email_subject,
             first_check_time, first_check_status, first_check_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            tracking_id,
            original_url,
            recipient,
            email_subject,
            datetime.now().isoformat(),
            initial_check['status'],
            initial_check['score']
        ))
        
        # Generer tracking URL
        tracking_url = f"https://safe.smartesider.no/click/{tracking_id}"
        
        return tracking_url
    
    def handle_click(self, tracking_id):
        """Handle click on tracked URL"""
        
        # Hent original URL
        result = self.url_tracking_db.query_one(
            "SELECT * FROM tracked_urls WHERE tracking_id = ?",
            (tracking_id,)
        )
        
        if not result:
            return "Invalid tracking ID", 404
        
        original_url = result['original_url']
        
        # RE-CHECK URL (time-of-click!)
        current_check = self.check_url_threats(original_url)
        
        # Oppdater database
        self.url_tracking_db.execute("""
            UPDATE tracked_urls 
            SET click_count = click_count + 1,
                last_click_time = ?,
                last_check_status = ?,
                last_check_score = ?
            WHERE tracking_id = ?
        """, (
            datetime.now().isoformat(),
            current_check['status'],
            current_check['score'],
            tracking_id
        ))
        
        # Logg klikk
        self.log_click(tracking_id, current_check)
        
        # Beslutning basert på current threat level
        if current_check['score'] >= 70:
            # DANGEROUS - blokkér
            return self.show_blocked_page(original_url, current_check)
        
        elif current_check['score'] >= 30:
            # UNKNOWN - vis warning, la bruker velge
            return self.show_warning_page(original_url, current_check)
        
        else:
            # SAFE - redirect
            return redirect(original_url, code=302)
    
    def log_click(self, tracking_id, check_result):
        """Log click event"""
        self.url_tracking_db.execute("""
            INSERT INTO url_clicks
            (tracking_id, click_time, status, threats, user_action)
            VALUES (?, ?, ?, ?, ?)
        """, (
            tracking_id,
            datetime.now().isoformat(),
            check_result['status'],
            json.dumps(check_result['threats']),
            'pending'
        ))
    
    def check_url_threats(self, url):
        """Real-time threat check"""
        # Samme som tidligere, men ALLTID real-time (ingen cache)
        # ...
        pass
    
    def get_url_statistics(self):
        """Get tracking statistics"""
        stats = self.url_tracking_db.query_one("""
            SELECT 
                COUNT(*) as total_urls,
                SUM(click_count) as total_clicks,
                COUNT(CASE WHEN first_check_status = 'dangerous' THEN 1 END) as dangerous_urls,
                COUNT(CASE WHEN last_check_status = 'dangerous' 
                           AND first_check_status != 'dangerous' THEN 1 END) as became_dangerous
            FROM tracked_urls
        """)
        
        return stats
```

### 📊 Tracking Dashboard

```python
@app.route('/admin/url-tracking')
def url_tracking_dashboard():
    """Admin dashboard for URL tracking"""
    
    tracker = TimeOfClickProtection()
    
    # Overall stats
    stats = tracker.get_url_statistics()
    
    # Recent dangerous URLs
    dangerous = tracker.url_tracking_db.query("""
        SELECT * FROM tracked_urls
        WHERE last_check_status = 'dangerous'
        ORDER BY last_click_time DESC
        LIMIT 50
    """)
    
    # URLs that became dangerous after delivery
    zero_day = tracker.url_tracking_db.query("""
        SELECT * FROM tracked_urls
        WHERE first_check_status != 'dangerous'
          AND last_check_status = 'dangerous'
        ORDER BY last_click_time DESC
    """)
    
    return render_template('admin_url_tracking.html',
        stats=stats,
        dangerous=dangerous,
        zero_day=zero_day
    )
```

### ✅ Fordeler
- **🏆 Beste beskyttelse:** Fanger zero-day og delayed threats
- **Real-time:** Alltid oppdaterte threat-data
- **Analytics:** Detaljert tracking av klikk
- **Forensics:** Komplett audit trail
- **Zero-day detection:** Fanger trusler som dukker opp senere

### ❌ Ulemper
- **Kompleksitet:** Mye kode og infrastruktur
- **Privacy concerns:** Logger alle klikk (GDPR)
- **Database størrelse:** Vokser fort
- **API costs:** Mange threat-checks (kan bli dyrt)

### ⏱️ Implementeringstid
**40-60 timer:**
- URL tracking system: 15 timer
- Database schema & tracking: 10 timer
- Real-time threat checks: 10 timer
- Admin dashboard: 10 timer
- Testing & optimization: 10 timer

### 💰 Kostnad
**40,000-60,000 kr** utvikling + **500-1000 kr/mnd** drift (API costs + VPS)

---

## Forslag 4: URL Metadata Injection

### 🎯 Konsept
Enkleste løsning - legger til **metadata** ved lenker uten å endre dem.

### 🔄 Hvordan Det Fungerer

```html
Original:
  <a href="https://suspicious-site.com">Klikk her</a>

     ↓

Modified:
  <a href="https://suspicious-site.com" 
     data-threat-score="75"
     data-threats="phishing,fake-domain"
     title="⚠️ Advarsel: Mistenkt phishing (score: 75)"
     class="suspicious-link">Klikk her</a>

  <style>
    .suspicious-link { border: 2px solid red !important; }
  </style>
```

### 🛠️ Implementering

```python
def inject_url_metadata(email_path):
    """Add metadata to suspicious links"""
    
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            html = part.get_content()
            soup = BeautifulSoup(html, 'html.parser')
            
            # Inject CSS for suspicious links
            style = soup.new_tag('style')
            style.string = """
                .suspicious-link {
                    border: 2px solid #ff9800 !important;
                    background: #fff3e0 !important;
                    padding: 2px 4px !important;
                }
                .dangerous-link {
                    border: 2px solid #dc3545 !important;
                    background: #f8d7da !important;
                    padding: 2px 4px !important;
                    text-decoration: line-through !important;
                }
            """
            soup.head.append(style)
            
            # Check and annotate links
            for link in soup.find_all('a', href=True):
                url = link['href']
                check = check_url_threats(url)
                
                if check['score'] >= 70:
                    link['class'] = 'dangerous-link'
                    link['title'] = f"⚠️ FARLIG: {', '.join(check['threats'])}"
                    link['data-threat-score'] = str(check['score'])
                
                elif check['score'] >= 30:
                    link['class'] = 'suspicious-link'
                    link['title'] = f"⚠️ Mistenkt: {', '.join(check['threats'])}"
                    link['data-threat-score'] = str(check['score'])
            
            part.set_content(str(soup))
    
    with open(email_path, 'wb') as f:
        f.write(msg.as_bytes())
```

### ✅ Fordeler
- **Enkel:** Minimal kodeendring
- **Ikke-invasiv:** URLs uendret
- **Visuell:** Styling indikerer fare
- **Reversibel:** Bruker kan fortsatt klikke

### ❌ Ulemper
- **Lav beskyttelse:** Ingen aktiv blokkering
- **Avhengig av klient:** CSS kan strippes
- **Kun visuelt:** Ikke teknisk blokkering

### ⏱️ Implementeringstid
**10-15 timer**

### 💰 Kostnad
**10,000-15,000 kr** utvikling + minimal drift

---

## Forslag 5: Visual Warning Overlay

### 🎯 Konsept
Injiserer JavaScript som viser **pop-up advarsel** før bruker forlater til ekstern lenke.

### 🛠️ Implementering

```html
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Threat data injected by server
    const threatData = {
        'https://evil-site.com': {
            score: 95,
            threats: ['Phishing', 'Fake domain']
        }
    };
    
    // Intercept all link clicks
    document.querySelectorAll('a').forEach(function(link) {
        link.addEventListener('click', function(e) {
            const url = this.href;
            
            if (threatData[url]) {
                e.preventDefault();
                
                const proceed = confirm(
                    '⚠️ ADVARSEL!\n\n' +
                    'Denne lenken er flagget som farlig:\n\n' +
                    'Trusler: ' + threatData[url].threats.join(', ') + '\n' +
                    'Risiko: ' + threatData[url].score + '/100\n\n' +
                    'Vil du fortsette?'
                );
                
                if (proceed) {
                    window.open(url, '_blank');
                }
            }
        });
    });
});
</script>
```

### ⏱️ Implementeringstid
**25-35 timer**

### 💰 Kostnad
**25,000-35,000 kr**

---

## Forslag 6: Link Sandboxing

### 🎯 Konsept
Åpner lenker i **sandboxed iframe** eller via headless browser for pre-rendering.

### 🔄 Hvordan Det Fungerer

```
Bruker klikker lenke
     ↓
Proxy åpner side i headless browser (Puppeteer/Playwright)
     ↓
Analyserer:
  - JavaScript behavior
  - Form fields (password inputs)
  - Redirects
  - Cookie stealing attempts
     ↓
Hvis trygg: Viser preview eller redirect
Hvis farlig: Blokkerer med rapport
```

### 🛠️ Implementering

```python
from playwright.sync_api import sync_playwright

class LinkSandbox:
    def analyze_url(self, url):
        """Analyze URL in sandbox"""
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            # Behavioral analysis
            threats = []
            
            # 1. Intercept network requests
            def handle_request(request):
                if 'malware' in request.url:
                    threats.append('Malware download attempt')
            page.on('request', handle_request)
            
            # 2. Detect suspicious forms
            def handle_response(response):
                if response.status == 200:
                    # Check for password forms
                    pass
            page.on('response', handle_response)
            
            # 3. Navigate
            try:
                page.goto(url, timeout=10000)
                
                # Check for password fields
                password_fields = page.locator('input[type="password"]').count()
                if password_fields > 0:
                    threats.append('Password field detected')
                
                # Check for suspicious JavaScript
                # ...
                
            except Exception as e:
                threats.append(f'Navigation error: {str(e)}')
            
            browser.close()
            
            return {
                'threats': threats,
                'score': len(threats) * 30
            }
```

### ⏱️ Implementeringstid
**80-120 timer**

### 💰 Kostnad
**80,000-120,000 kr** + høy drift (**1000-2000 kr/mnd** for compute)

---

## Forslag 7: Smart Link Replacement

### 🎯 Konsept
Erstatter **kun mistenkelige lenker**, beholder legitime uendret.

### 🔄 Hvordan Det Fungerer

```
Kjente safe domains (google.com, microsoft.com, etc.)
  → Behold original

Ukjente domains
  → Sjekk threat score
  → Hvis score < 30: Behold
  → Hvis score >= 30: Rewrite

Kjente farlige
  → Alltid rewrite + warning
```

### ⏱️ Implementeringstid
**35-50 timer**

### 💰 Kostnad
**35,000-50,000 kr**

---

## Forslag 8: Hybrid Multi-Layer

### 🎯 Konsept
Kombinerer **Forslag 2, 3, og 7** for maksimal beskyttelse.

### 🔄 Arkitektur

```
Layer 1: Pre-Delivery Scan (Forslag 2)
  → Klassifiser alle URLs

Layer 2: Smart Replacement (Forslag 7)
  → Safe: Behold original
  → Suspicious: Rewrite til proxy
  → Dangerous: Rewrite + inject warning

Layer 3: Time-of-Click (Forslag 3)
  → Re-check ved klikk
  → Blokkér zero-day

Layer 4: Analytics & Learning
  → Track click patterns
  → Machine learning threat detection
```

### ⏱️ Implementeringstid
**60-80 timer**

### 💰 Kostnad
**60,000-80,000 kr** + **800-1500 kr/mnd** drift

---

## 💰 Prisanbefaling

### 🏷️ Engangslisens

#### Modell 1: Per Server/Domene
```
Lite (1-50 mailboxes):     15,000 kr
Medium (51-250 mailboxes):  30,000 kr
Stort (251-1000 mailboxes): 60,000 kr
Enterprise (1000+):         120,000 kr + forhandling
```

#### Modell 2: Flat Rate
```
Ubegrenset mailboxes: 50,000 kr
(Inkluderer basis URL protection - Forslag 1 eller 2)

Premium features (Forslag 3+8):
  + Time-of-Click: +25,000 kr
  + Link Sandboxing: +40,000 kr
  + Hybrid Multi-Layer: +35,000 kr
```

#### Modell 3: Feature-Based
```
Basis Package (Forslag 1+4):      20,000 kr
  - URL Proxy Redirect
  - Metadata Injection
  - X-Headers

Professional (Forslag 2+7):       45,000 kr
  - Safe Browse Gateway
  - Smart Link Replacement
  - Inline warnings
  - Basis inkludert

Enterprise (Forslag 3+8):         85,000 kr
  - Time-of-Click Protection
  - Hybrid Multi-Layer
  - Admin dashboard
  - Professional inkludert

Ultimate (Alle forslag):          150,000 kr
  - Link Sandboxing
  - Machine learning
  - Dedikert support
  - Enterprise inkludert
```

### 🔄 Årlig Lisens

#### Support & Oppdateringer
```
Basis: 15% av engangspris/år
  Eksempel: 50,000 kr engangslisens
  → 7,500 kr/år

Premium: 20% av engangspris/år
  + Prioritert support
  + Nye features
  Eksempel: 50,000 kr
  → 10,000 kr/år

Enterprise: 25% av engangspris/år
  + 24/7 support
  + Dedikert konsulent
  + Custom features
  Eksempel: 85,000 kr
  → 21,250 kr/år
```

### 📊 Sammenligning Med Konkurrenter

| Løsning | Engangslisens | Årlig Kostnad | URL Protection |
|---------|---------------|---------------|----------------|
| **SmarteSider (dere)** | 20,000-150,000 kr | 3,000-37,500 kr | ✅ |
| Barracuda ESG | ❌ Ingen | 35,000-120,000 kr/år | ✅ |
| Mimecast | ❌ Ingen | 85,000-250,000 kr/år | ✅ |
| Proofpoint | ❌ Ingen | 120,000-400,000 kr/år | ✅ |
| SpamExperts | ❌ Ingen | 15,000-80,000 kr/år | ⚠️ Begrenset |

**Deres konkurransefortrinn:**
- ✅ Engangslisens tilgjengelig (konkurrenter kun SaaS)
- ✅ 50-80% lavere årlig kostnad
- ✅ Norsk support
- ✅ Self-hosted (data privacy)
- ✅ Ingen per-mailbox fees

---

## 🌐 SaaS-Modell (SpamExperts-lignende)

### 🏗️ Arkitektur

```
Internet
    ↓
MX1: filter.smartesider.no (Deres SaaS)
    ↓
[Spam Scanning]
[Virus Scanning]
[Phishing Detection]
[URL Rewriting] ← NY
    ↓
MX2: mail.kunde.no (Kunde server)
    ↓
Kunde mailboxes
```

### 🔧 Teknisk Oppsett

#### DNS Konfigurasjon (Kunde)
```
kunde.no.   MX  10  filter.smartesider.no.
kunde.no.   MX  20  mail.kunde.no.
```

#### Mail Flow
```
1. E-post ankommer filter.smartesider.no
2. Spam/virus/phishing scanning
3. URL rewriting (hvis enabled)
4. Relay til mail.kunde.no
5. Kunde mottar "ren" e-post
```

### 💰 SaaS Prising

#### Per-Mailbox Model
```
Basis:
  1-50 mailboxes:    15 kr/mailbox/mnd
  51-250 mailboxes:  12 kr/mailbox/mnd
  251-1000:          10 kr/mailbox/mnd
  1000+:              8 kr/mailbox/mnd

Premium (+ URL Protection):
  1-50:    20 kr/mailbox/mnd
  51-250:  17 kr/mailbox/mnd
  251-1000: 14 kr/mailbox/mnd
  1000+:    11 kr/mailbox/mnd

Enterprise (+ Time-of-Click):
  1-50:    30 kr/mailbox/mnd
  51-250:  25 kr/mailbox/mnd
  251-1000: 20 kr/mailbox/mnd
  1000+:    15 kr/mailbox/mnd
```

#### Flat Rate Model (Hosting Companies)
```
Small Hosting (1-100 kunder):
  5,000 kr/mnd (ubegrenset mailboxes)

Medium Hosting (101-500 kunder):
  12,000 kr/mnd

Large Hosting (501-2000 kunder):
  25,000 kr/mnd

Enterprise Hosting (2000+ kunder):
  Custom pricing (40,000-100,000 kr/mnd)
```

#### Hybrid Model (Best for Growth)
```
Base Fee: 2,000 kr/mnd
  + Infrastruktur
  + Support
  + Oppdateringer

Plus: 8 kr/mailbox/mnd
  Eksempel: 500 mailboxes
  → 2,000 + (500 × 8) = 6,000 kr/mnd
```

### 📊 Revenue Calculator

```python
# Scenario: Medium hosting company
kunder = 200
mailboxes_per_kunde = 10  # Gjennomsnitt
total_mailboxes = kunder * mailboxes_per_kunde  # 2000

# Flat rate model
monthly_revenue = 12000  # kr/mnd
yearly_revenue = monthly_revenue * 12  # 144,000 kr/år

# Per-mailbox model (hvis Premium)
monthly_per_mailbox = total_mailboxes * 17  # 34,000 kr/mnd
yearly_per_mailbox = monthly_per_mailbox * 12  # 408,000 kr/år

# Hybrid model
base_fee = 2000
mailbox_fee = total_mailboxes * 8  # 16,000
monthly_hybrid = base_fee + mailbox_fee  # 18,000 kr/mnd
yearly_hybrid = monthly_hybrid * 12  # 216,000 kr/år
```

### 📈 Sammenligning Med SpamExperts

| Feature | SpamExperts | SmarteSider SaaS |
|---------|-------------|------------------|
| **Pris/mailbox/mnd** | 12-20 kr | 8-17 kr |
| **Setup fee** | 5,000-15,000 kr | Gratis |
| **URL Rewriting** | ✅ | ✅ |
| **Time-of-Click** | ⚠️ Begrenset | ✅ Premium |
| **Norsk support** | ❌ | ✅ |
| **Self-hosted option** | ❌ | ✅ |
| **API** | ✅ | ✅ (kan utvikles) |
| **White-label** | ✅ Dyrt | ✅ Inkludert |

### 🎯 Go-to-Market Strategi

#### Fase 1: Soft Launch (Måned 1-3)
- **Target:** 5-10 pilot-kunder (gratis/rabatt)
- **Focus:** Testing, feedback, bug fixing
- **Pricing:** 50% rabatt (4-8 kr/mailbox)

#### Fase 2: Beta (Måned 4-6)
- **Target:** 20-30 kunder
- **Focus:** Stabilitet, performance optimization
- **Pricing:** 25% rabatt (6-12 kr/mailbox)

#### Fase 3: General Availability (Måned 7+)
- **Target:** 100+ kunder innen år 1
- **Focus:** Markedsføring, salg
- **Pricing:** Full pris (8-17 kr/mailbox)

#### Revenue Projection (År 1)
```
Måned 1-3:   10 kunder × 100 mailboxes × 6 kr  =   6,000 kr/mnd
Måned 4-6:   30 kunder × 100 mailboxes × 9 kr  =  27,000 kr/mnd
Måned 7-12:  100 kunder × 100 mailboxes × 12 kr = 120,000 kr/mnd

Totalt År 1: ~750,000 kr

År 2 (200 kunder): ~2,400,000 kr
År 3 (400 kunder): ~4,800,000 kr
```

### 🛠️ SaaS Infrastruktur Kostnad

```
Servers (3× load-balanced):
  3× 8GB RAM VPS:         1,500 kr/mnd

Database (PostgreSQL):
  Managed instance:       500 kr/mnd

Storage (email cache):
  1TB SSD:                300 kr/mnd

Bandwidth (50TB/mnd):
  Included with VPS:      0 kr/mnd

Monitoring (Prometheus):
  Self-hosted:            0 kr/mnd

Backup (daily):
  S3-compatible:          200 kr/mnd

SSL Certificates:
  Let's Encrypt:          0 kr/mnd

API Costs (threat DBs):
  Google Safe Browsing:   ~1,000 kr/mnd
  Other APIs:             ~500 kr/mnd

──────────────────────────────────
Total Infrastructure:     ~4,000 kr/mnd
```

**Break-even:**
- Flat rate: 1 Medium kunde (12,000 kr)
- Per-mailbox: ~300 mailboxes (4,000 kr)
- **Margin:** 70-85% etter break-even

---

## 🎯 Min Anbefaling

### For SmarteSider

#### Kortsiktig (Neste 1-2 måneder)
**Implementer Forslag 7 (Smart Link Replacement):**
- ✅ God beskyttelse
- ✅ Balansert brukeropplevelse
- ✅ Moderat kompleksitet
- ⏱️ 35-50 timer
- 💰 Selges for: **45,000 kr engangslisens** + **6,000 kr/år support**

#### Mellomlang sikt (3-6 måneder)
**Oppgrader til Forslag 8 (Hybrid Multi-Layer):**
- ✅ Maksimal beskyttelse
- ✅ Konkurransedyktig med enterprise-løsninger
- ⏱️ +25-30 timer ekstra
- 💰 Selges for: **85,000 kr engangslisens** + **15,000 kr/år support**

#### Langsiktig (6-12 måneder)
**Lansér SaaS (SpamExperts-konkurrent):**
- ✅ Recurring revenue
- ✅ Skalerbar forretningsmodell
- ✅ Høy margin (70-85%)
- 💰 Pricing: **12-17 kr/mailbox/mnd** eller **flat rate 5,000-25,000 kr/mnd**
- 📈 Potensial: **2-5 millioner kr/år** innen 2-3 år

---

## 📋 Oppsummering

### Beste Løsninger (Rangert)

1. **Forslag 8: Hybrid Multi-Layer** ⭐⭐⭐⭐⭐
   - Beste beskyttelse
   - Enterprise-grade
   - 85,000 kr engangslisens

2. **Forslag 3: Time-of-Click Protection** ⭐⭐⭐⭐⭐
   - Zero-day beskyttelse
   - Real-time checks
   - 50,000-60,000 kr

3. **Forslag 7: Smart Link Replacement** ⭐⭐⭐⭐⭐
   - God balanse
   - Praktisk
   - 45,000 kr

4. **Forslag 2: Safe Browse Gateway** ⭐⭐⭐⭐
   - Solid beskyttelse
   - Pre-scanning
   - 35,000-40,000 kr

5. **Forslag 1: URL Proxy Redirect** ⭐⭐⭐⭐
   - Enklere versjon
   - Grunnleggende beskyttelse
   - 25,000-30,000 kr

### Pricing Anbefaling

**Engangslisens:**
```
Basis (Forslag 1+4):        25,000 kr
Professional (Forslag 7):   45,000 kr
Enterprise (Forslag 8):     85,000 kr
Ultimate (Alle):           150,000 kr
```

**Årlig Support:**
```
15-25% av engangspris
Eksempel: 45,000 kr → 6,750-11,250 kr/år
```

**SaaS Model:**
```
Per mailbox: 8-17 kr/mnd
Flat rate: 5,000-25,000 kr/mnd
Hybrid: 2,000 kr base + 8 kr/mailbox
```

---

**Vil du at jeg skal implementere noen av disse forslagene? Si fra hvilket nummer!**
