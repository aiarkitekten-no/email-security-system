# v3.0 Kritisk Logikk-Endring

**Dato:** 2025-11-12  
**Endret av:** AI Assistant (på forespørsel fra Terje)

## 🎯 Ny Strategi: Kun Lær Fra Spam

### Problemstilling
Tidligere lærte systemet både fra:
- **Spam-mapper** (.Spam/.Junk) → lærte som spam ✅
- **Vanlige mapper** (INBOX/Sent) → lærte som ham ⚠️

Dette skapte risiko for **falske positiver** fordi systemet antok at ALT i INBOX var legitimt.

### Ny Løsning (v3.0)

**SpamAssassin lærer KUN fra bekreftede spam-mapper**

#### Spam-Mapper (.Spam/.Junk)
- ✅ Lær ALLTID som spam
- ✅ Tren SpamAssassin med disse
- ✅ Oppdater statistikk

#### Vanlige Mapper (INBOX/Sent)
- 🔍 **IKKE** lær som ham
- 🔍 **SJEKK** kun om avsendere er på DNSBL
- 🚫 **BLOKKER** avsendere med ≥5 e-poster fra svartelistede IP-er
- ✅ Unngår falske positiver

### Teknisk Implementasjon

#### Ny Funksjon: `check_ham_folder_for_blacklisted()`
```python
def check_ham_folder_for_blacklisted(self, folder):
    """
    Check ham folders for blacklisted senders, do NOT learn as ham
    Only block if threshold+ emails from DNSBL-listed senders found
    """
    # For hver e-post i mappen:
    # 1. Ekstraher avsender og IP
    # 2. Sjekk IP mot 7 DNSBL-servere
    # 3. Tell antall e-poster fra hver svartelistet avsender
    # 4. Blokker avsendere med ≥ blacklist_threshold e-poster
```

#### Endret Funksjon: `learn_ham()`
```python
def learn_ham(self, folder):
    """
    DEPRECATED - v3.0: Ham folders should NOT be learned from
    """
    self.logger.warning("learn_ham() called but ham learning is disabled in v3.0")
    return 0
```

#### Endret Funksjon: `run_learning_cycle()`
```python
# GAMMELT:
if learn_ham and ham_folders:
    print("Learning from ham folders...")
    ham_count = self.learn_ham(folder)

# NYTT:
if ham_folders:
    print("Checking ham folders for blacklisted senders...")
    print("(NOT learning as ham - only checking DNSBL)")
    blocked_senders = self.check_ham_folder_for_blacklisted(folder)
```

### Konfigurasjon

**config.yaml endringer:**

```yaml
learning:
  learn_spam: true
  
  # v3.0: Ham learning er DEAKTIVERT
  # Systemet lærer KUN fra bekreftede spam-mapper
  # Vanlige mapper sjekkes kun for DNSBL-listede avsendere
  learn_ham: false  # ENDRET fra true
  
  # Minimum e-poster fra svartelistet avsender før blokkering
  blacklist_threshold: 5  # NYT
```

### Fordeler med Ny Logikk

#### 1. Smartere SpamAssassin
- Lærer kun fra **bekreftet** spam
- Ingen antakelser om at INBOX = legitimt
- Reduserer falske positiver drastisk

#### 2. Progressiv Blokkering
- Avsendere med 1-4 svartelistede e-poster: Ingen handling (kanskje legitim)
- Avsendere med 5+ svartelistede e-poster: **BLOKKERT** (klart spam)

#### 3. Raskere Over Tid
- SpamAssassin blokkerer spam tidligere og tidligere
- Mindre spam når igjennom til INBOX
- Systemet blir mer effektivt med tiden

#### 4. Mindre Ressursbruk
- Ingen ham-learning = færre sa-learn kjøringer
- Kun DNSBL-sjekk på INBOX (rask DNS-oppslag)
- Database-oppdateringer kun for blokkeringer

### Eksempel-Scenario

**Før v3.0:**
```
INBOX: 1000 e-poster
→ Lær alle 1000 som "ham"
→ Hvis 50 er spam: SpamAssassin lærer FEIL
→ Falske positiver øker
```

**Etter v3.0:**
```
INBOX: 1000 e-poster
→ Sjekk alle 1000 mot DNSBL
→ Finn 10 avsendere på svartelister:
  - sender1: 2 e-poster (ingen handling)
  - sender2: 7 e-poster (BLOKKER)
  - sender3: 12 e-poster (BLOKKER)
→ SpamAssassin lærer INGENTING fra INBOX
→ Kun bekreftet spam fra .Spam-mapper læres
```

### Testing og Verifisering

#### Test 1: Kjør Learning Cycle
```bash
./spam_trainer.py --learn
```

**Forventet output:**
```
📧 Learning from X spam folders...
✅ Learned 753 spam emails total

🔍 Checking Y ham folders for blacklisted senders...
   (NOT learning as ham - only checking DNSBL)
   Blocking senders with 5+ emails from blacklisted IPs

[1/Y] Checking: /var/qmail/mailnames/user@domain/.INBOX/cur
  Checking 100 emails for blacklisted senders...
  🚫 Blocked 2 senders with 5+ blacklisted emails

✅ No repeat offenders found (threshold: 5+ emails)
```

#### Test 2: Verifiser Database
```bash
sqlite3 /tmp/spamtrainer.db "SELECT * FROM sender_tracking WHERE reported = 1 ORDER BY spam_count DESC LIMIT 10;"
```

**Forventet:**
- Liste over blokkerte avsendere
- `reported = 1` for alle
- `spam_count >= 5` for hver

#### Test 3: HTML Report
```bash
./spam_trainer.py --html-report
```

**Forventet:**
- Rapport viser `ham_learned: 0`
- `senders_blocked: X` (nye feltet)
- DNSBL effectiveness metrics

### Potensielle Problemer og Løsninger

#### Problem 1: For Mange Blokkeringer
**Symptom:** 100+ avsendere blokkeres
**Løsning:** Øk `blacklist_threshold` til 10-15

```yaml
learning:
  blacklist_threshold: 10  # Strengere
```

#### Problem 2: For Få Blokkeringer
**Symptom:** Ingen avsendere blokkeres, men spam i INBOX
**Løsning:** Sjekk DNSBL-servere og senk threshold

```yaml
learning:
  blacklist_threshold: 3  # Mildere

reporting:
  dnsbl_servers:
    - zen.spamhaus.org  # Mest pålitelig
    - bl.spamcop.net
    # ... flere servere ...
```

#### Problem 3: Falske Negative
**Symptom:** Spam når igjennom selv etter blokkering
**Årsak:** Nye spammere som ikke er på DNSBL ennå
**Løsning:** Flytt spam til .Spam-mappe → systemet lærer → blokkerer fremtidige

### Overvåking og Metrics

**Nye metrics å følge med på:**

1. **Blokkeringsrate**
   - Antall avsendere blokkert per dag
   - Forventes: 5-20 per dag i starten, deretter 1-5

2. **DNSBL Hit Rate**
   - % av INBOX-e-poster fra svartelistede IP-er
   - Forventes: 5-15% i starten, deretter <5%

3. **Spam i INBOX**
   - Overvåk manuelt: Mindre spam over tid?
   - Forventes: 80%+ reduksjon innen 2 uker

4. **Ham Learned**
   - Alltid 0 i v3.0
   - Hvis > 0: Systemet bruker gammel logikk!

### Migrering fra v2.0

**Steg 1:** Backup eksisterende database
```bash
cp /tmp/spamtrainer.db /tmp/spamtrainer.db.v2.backup
```

**Steg 2:** Oppdater config.yaml
```bash
# Endre learn_ham: true → false
# Legg til blacklist_threshold: 5
```

**Steg 3:** Kjør første learning cycle
```bash
./spam_trainer.py --learn
```

**Steg 4:** Verifiser at ham_learned = 0
```bash
./spam_trainer.py --report
```

### Konklusjon

**Ny logikk er KRITISK for systemets effektivitet:**

✅ **Færre falske positiver** - ingen antakelser om INBOX  
✅ **Smartere blokkering** - kun bekreftet spam læres  
✅ **Progressiv forbedring** - systemet blir bedre over tid  
✅ **Mindre ressursbruk** - ingen unødvendig ham-learning  

**Systemet lærer KUN fra spam-mapper, sjekker KUN DNSBL på vanlige mapper.**

---

**Kontakt:** terje@smartesider.no  
**Dokumentasjon:** Se også `IMPLEMENTATION_STATUS_V3.md` og `QUICKSTART_V3.md`
