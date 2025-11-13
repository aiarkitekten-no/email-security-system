# ⏰ Cron Scheduling - Automatisk Kjøring

**Status:** ✅ Aktivert og testet

---

## Installerte Jobber

### 1. Learning Cycle (Hver Time)
```cron
0 * * * * /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --learn
```

**Når:** Hver time ved minutt 0 (00:00, 01:00, 02:00, etc.)

**Hva gjøres:**
- Scanner alle spam-mapper (.Spam, .Junk)
- Scanner trash-mapper (max 7 dager gamle)
- Lærer spam med sa-learn
- Rapporterer til Spamhaus API
- Sjekker ham-mapper for DNSBL-listede IP-er
- Blokkerer repeat offenders (5+ e-poster)

**Output:** Logges til `/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log`

### 2. HTML Rapport (Hver Natt kl 02:00)
```cron
0 2 * * * /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --html-report
```

**Når:** Daglig kl 02:00

**Hva gjøres:**
- Genererer HTML-rapport for siste 7 dager
- Lager 3 charts (spam trend, spam vs ham, top senders)
- **Sjekker server-IP og domener mot Spamhaus** 🆕
- Viser store røde varsler hvis blacklisted
- Sender e-post til: terje@smartesider.no

**Output:** Logges til samme loggfil + sendes som e-post

---

## Timeplan

```
00:00 - Learning cycle kjører
01:00 - Learning cycle kjører
02:00 - Learning cycle kjører + HTML rapport sendes 📧
03:00 - Learning cycle kjører
04:00 - Learning cycle kjører
...
23:00 - Learning cycle kjører
```

**Total:** 24 learning cycles per dag + 1 HTML rapport

---

## Loggfil

**Plassering:** `/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log`

### Overvåk Live
```bash
tail -f /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log
```

### Se Siste Kjøring
```bash
tail -100 /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log
```

### Søk Etter Feil
```bash
grep -i error /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log
grep -i warning /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log
```

### Se Blacklist Warnings
```bash
grep "BLACKLIST" /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log
```

---

## Verifisering

### 1. Sjekk At Cron Er Aktivert
```bash
crontab -l | grep spam_trainer
```

**Forventet output:**
```
0 * * * * /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --learn >> ...
0 2 * * * /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --html-report >> ...
```

### 2. Test Manuell Kjøring
```bash
# Test learning
/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --learn

# Test HTML rapport
/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --html-report
```

### 3. Sjekk Logg Etter Første Kjøring
```bash
# Vent til neste hele time, deretter:
tail -50 /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log
```

### 4. Verifiser E-post Mottas
**Første rapport:** Kl 02:00 i morgen  
**Til:** terje@smartesider.no  
**Innhold:** Charts, statistikk, blacklist warnings

---

## Logg Rotation

### Problem: Loggfil blir for stor

**Løsning 1: Manuell Rotation**
```bash
# Arkiver gammel logg
mv /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log \
   /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log.$(date +%Y%m%d)

# Komprimer
gzip /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log.*

# Slett gamle (>30 dager)
find /home/Terje/scripts/Laer-av-spamfolder/ -name "spam_trainer.log.*.gz" -mtime +30 -delete
```

**Løsning 2: Automatisk Rotation (Anbefalt)**
```bash
# Legg til i crontab
0 0 1 * * mv /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log \
              /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log.$(date +\%Y\%m\%d) && \
              gzip /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log.* 2>/dev/null
```

Roterer hver 1. i måneden.

---

## Debugging

### Cron Kjører Ikke
**Sjekk 1: Er cron daemon aktiv?**
```bash
systemctl status cron
# Eller:
service cron status
```

**Sjekk 2: Har scriptet execute permissions?**
```bash
ls -la /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py
# Skal vise: -rwxrwxr-x
```

**Sjekk 3: Tester cron environment**
```bash
# Kjør med samme environment som cron
env -i HOME=/home/Terje PATH=/usr/bin:/bin \
  /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --learn
```

### E-post Mottas Ikke
**Sjekk 1: SMTP konfigurert?**
```bash
grep smtp_host /home/Terje/scripts/Laer-av-spamfolder/config.yaml
# Skal vise: smtp_host: localhost
```

**Sjekk 2: Test manuell sending**
```bash
/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --html-report
# Se logg for feilmeldinger
```

**Sjekk 3: Sjekk spam-folder**
```bash
# E-posten kan ha gått til spam!
```

### Ingen Spam Læres
**Sjekk 1: Er det nye spam-e-poster?**
```bash
find /var/qmail/mailnames -type f -path "*/.Spam/cur/*" -mtime -1 | wc -l
# Viser antall nye spam-filer siste 24t
```

**Sjekk 2: Incremental learning**
```bash
sqlite3 /tmp/spamtrainer.db "SELECT COUNT(*) FROM learning_history"
# Viser totalt lærte e-poster
```

---

## Modifisering

### Endre Tidspunkt for HTML Rapport
```bash
# Åpne crontab
crontab -e

# Endre fra 02:00 til f.eks 06:00:
# Fra: 0 2 * * *
# Til:  0 6 * * *
```

### Endre Learning Frekvens
```bash
# Hver 2. time i stedet for hver time:
# Fra: 0 * * * *
# Til:  0 */2 * * *

# Hver 30. minutt:
# Til:  */30 * * * *
```

### Legg Til Ukentlig Oppsummering
```bash
crontab -e

# Legg til:
# Ukentlig rapport (søndager kl 08:00)
0 8 * * 0 /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --html-report --days 30
```

### Deaktiver Midlertidig
```bash
crontab -e

# Kommenter ut med #:
# 0 * * * * /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --learn
# 0 2 * * * /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --html-report
```

---

## Performance

### Forventet Kjøretid

**Learning Cycle (--learn):**
- Small mailbox (<100 spam): 5-30 sekunder
- Medium mailbox (100-500 spam): 1-3 minutter
- Large mailbox (500+ spam): 3-10 minutter

**HTML Report (--html-report):**
- Chart generation: 5-10 sekunder
- Blacklist check: 5-30 sekunder
- E-post sending: 1-5 sekunder
- **Total:** ~20-60 sekunder

### Disk Space
**Loggfil vekst:**
- ~1-5 KB per learning cycle
- ~10-20 KB per HTML rapport
- **Per dag:** ~50-150 KB
- **Per måned:** ~1.5-4.5 MB

**Anbefaling:** Roter logg månedlig.

---

## Monitoring

### Daily Check
```bash
# Se gårsdagens aktivitet
grep "$(date -d yesterday +%Y-%m-%d)" \
  /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log | \
  grep "Learning complete"
```

### Weekly Summary
```bash
# Antall spam lært siste 7 dager
sqlite3 /tmp/spamtrainer.db \
  "SELECT SUM(spam_learned) FROM daily_stats 
   WHERE date >= date('now', '-7 days')"
```

### Alert on Blacklisting
```bash
# Sjekk om server er blacklistet
grep "BLACKLIST DETECTED" \
  /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log | tail -1
```

---

## E-post Innhold

### HTML Rapport Inneholder:

1. **🚨 BLACKLIST WARNINGS** (hvis aktuelt)
   - Server IP status
   - Domenestatus
   - Spamhaus lister
   - Delisting instruksjoner

2. **📊 Statistics Cards**
   - Total spam learned
   - Ham learned
   - Spam percentage
   - Processing stats

3. **📈 Charts**
   - Spam detection trend (line chart)
   - Spam vs Ham distribution (pie chart)
   - Top spam senders (bar chart)

4. **📋 Tables**
   - Top 10 spam senders
   - Top 5 spam domains
   - DNSBL effectiveness

5. **🌐 Spamhaus Contributions**
   - Total submissions
   - Confirmed listings
   - Success rate
   - Recent submissions

6. **💡 Recommendations**
   - System health tips
   - Configuration suggestions

---

## Backup Strategy

### Database Backup (Anbefalt)
```bash
# Legg til i crontab:
# Backup database daglig kl 03:00
0 3 * * * cp /tmp/spamtrainer.db \
             /home/Terje/backups/spamtrainer-$(date +\%Y\%m\%d).db && \
          find /home/Terje/backups/ -name "spamtrainer-*.db" -mtime +30 -delete
```

### Config Backup
```bash
# Backup config monthly
0 0 1 * * cp /home/Terje/scripts/Laer-av-spamfolder/config.yaml \
             /home/Terje/backups/config-$(date +\%Y\%m).yaml
```

---

## Troubleshooting Commands

```bash
# 1. Check if jobs are running
ps aux | grep spam_trainer.py

# 2. Check last cron execution time
ls -l /home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log

# 3. Test email sending manually
echo "Test" | mail -s "Test" terje@smartesider.no

# 4. Check database size
ls -lh /tmp/spamtrainer.db

# 5. Check mail queue
mailq

# 6. Force immediate learning
/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --learn

# 7. Force immediate report
/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.py --html-report

# 8. Check system load during execution
top -b -n 1 | grep spam_trainer
```

---

## Success Indicators

**✅ System fungerer hvis:**
1. Loggfil oppdateres hver time
2. E-post mottas daglig kl ~02:05
3. Database vokser (flere learned emails)
4. Spam rate stabiliserer seg
5. Ingen kritiske errors i logg

**⚠️ Undersøk hvis:**
1. Loggfil ikke oppdateres
2. Ingen e-post mottas
3. Samme spam læres om og om igjen
4. Blacklist warnings i rapporten
5. Error messages i logg

---

## Current Status

**Installert:** 2025-11-12  
**Aktivert:** ✅ Ja  
**Neste Learning:** Neste hele time  
**Neste Rapport:** I morgen kl 02:00  
**Logg:** `/home/Terje/scripts/Laer-av-spamfolder/spam_trainer.log`  
**E-post til:** terje@smartesider.no

**🎉 Alt er klart! Systemet kjører nå automatisk.**
