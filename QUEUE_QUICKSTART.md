# Spamhaus Queue System - Quick Start

## 🎯 Hva Er Dette?

Et køsystem som håndterer Spamhaus rate limiting automatisk ved å:
1. **Legge submissions i kø** når rate limit treffes (429 error)
2. **Prosessere køen i bakgrunnen** via cron eller daemon
3. **Prioritere** etter trussel-nivå (CRITICAL først)
4. **Spre submissions** over tid for å unngå API-blokkering

## ⚡ Quick Setup (3 minutter)

### 1. Aktiver køsystem i config
```yaml
reporting:
  spamhaus_use_queue: true         # Aktiver kø
  spamhaus_max_per_run: 50         # Max per kjøring
  spamhaus_retry_after_429: 3600   # 1 time cooldown
```

### 2. Test at det fungerer
```bash
cd /home/Terje/scripts/Laer-av-spamfolder

# Sjekk kø-status
./process_spamhaus_queue.py --status

# Test køsystemet
python3 -c "
from spamhaus_queue import SpamhausQueue
q = SpamhausQueue()
q.add_submission('ip', {'source': {'object': '192.0.2.1'}}, 'HIGH')
print('✅ Lagt til test-submission i kø')
"

# Sjekk status igjen
./process_spamhaus_queue.py --status
# Skal vise: Pending: 1
```

### 3. Sett opp automatisk prosessering

**Alternativ A: Cron (anbefalt for normal drift)**
```bash
crontab -e

# Legg til:
*/30 * * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 50 >> /var/log/spamhaus_queue.log 2>&1
```

**Alternativ B: Daemon (for første gangs learn med mange e-poster)**
```bash
# Start i bakgrunn
nohup /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --daemon --interval 300 >> /var/log/spamhaus_queue.log 2>&1 &

# Sjekk at den kjører
ps aux | grep process_spamhaus_queue
```

### 4. Kjør første gangs learn
```bash
cd /home/Terje/scripts/Laer-av-spamfolder
./spam_trainer.py --learn

# Første 50 submits: går direkte til Spamhaus
# Resten: legges automatisk i kø
# Se output:
# "📥 Queued domain submission (queue ID: 123)"
```

## 📊 Overvåking

### Sjekk kø-status
```bash
./process_spamhaus_queue.py --status
```

Output:
```
📊 Overall:
  Pending:          487    ← Antall som venter
  Completed:        36     ← Antall prosessert

⏰ Oldest pending: 2h 34m ago    ← Eldste i køen

⚠️  Pending by Threat Level:
  CRITICAL  : 54    ← Høyeste prioritet
  HIGH      : 423
  MEDIUM    : 10
```

### View live log
```bash
tail -f /var/log/spamhaus_queue.log
```

### Prosesser manuelt (hvis cron ikke kjører enda)
```bash
# Prosesser 50 items
./process_spamhaus_queue.py --batch-size 50

# Prosesser med verbose output
./process_spamhaus_queue.py --batch-size 50 --verbose
```

## 🔧 Vanlige Scenarioer

### Scenario 1: Første gangs learn (1000+ e-poster)
```bash
# 1. Start daemon for kontinuerlig prosessering
nohup ./process_spamhaus_queue.py --daemon --interval 120 >> /var/log/spamhaus_queue.log 2>&1 &
echo $! > /tmp/spamhaus_daemon.pid

# 2. Kjør learn
./spam_trainer.py --learn
# Første 50: direkte submit
# Resten (950+): kølagt

# 3. Overvåk fremgang
watch -n 60 './process_spamhaus_queue.py --status'

# 4. Når køen er tom (kan ta 12-24 timer):
kill $(cat /tmp/spamhaus_daemon.pid)
rm /tmp/spamhaus_daemon.pid

# 5. Bytt til cron for daglig drift
```

### Scenario 2: Daglig drift (< 50 nye spam/dag)
```bash
# Cron kjører hver 30. minutt
# Køen forblir tom eller nesten tom
# Alt prosesseres innen få timer
```

### Scenario 3: Spamhaus rate limit hit
```
[2025-11-13 10:30] INFO: Submitted 50 items before rate limit
[2025-11-13 10:30] WARNING: ⚠️ Spamhaus rate limit hit (429), pausing for 3600s (1h)
[2025-11-13 10:30] INFO: Future submissions will be queued
[2025-11-13 10:30] INFO: 📥 Queued domain submission (queue ID: 51)
[2025-11-13 10:30] INFO: 📥 Queued url submission (queue ID: 52)
...
[2025-11-13 11:30] INFO: Spamhaus rate limit cooldown expired, resuming submissions
```

## 📈 Forventet Ytelse

### Første gangs learn (stor kø)
- **Spamhaus limit:** ~50-100 submissions/time
- **1000 e-poster i kø:** ~10-20 timer å tømme
- **Med daemon (interval 120s):** ~12-16 timer
- **Med cron (hver 30min):** ~20-24 timer

### Daglig drift (lav kø)
- **< 50 nye spam/dag:** Ingen kø, alt prosesseres direkte
- **50-100 nye spam/dag:** Liten kø, tømt innen 1-2 timer
- **> 100 nye spam/dag:** Kø bygges opp, daemon anbefales

## 🛠️ Troubleshooting

### Problem: Køen vokser, ikke tømmes
```bash
# 1. Sjekk at cron kjører
grep "process_spamhaus_queue" /var/log/cron

# 2. Sjekk for errors
tail -50 /var/log/spamhaus_queue.log

# 3. Test manuell kjøring
./process_spamhaus_queue.py --batch-size 10 --verbose

# 4. Sjekk API key
grep "spamhaus_api_key" config.yaml
```

### Problem: "Rate limit" i hver log-melding
**Dette er normalt!** Spamhaus har strenge limits.

**Løsning:** Øk intervallet mellom kjøringer:
```crontab
# I stedet for hver 30. minutt:
0 * * * * ...  # Hver time i stedet
```

### Problem: "Failed to queue submission"
```bash
# Sjekk at spamhaus_queue.py finnes
ls -la spamhaus_queue.py

# Sjekk database-rettigheter
ls -la spamhaus_queue.db

# Recreate database
rm spamhaus_queue.db
python3 -c "from spamhaus_queue import SpamhausQueue; SpamhausQueue()"
```

## 📋 Kommandoreferanse

### Status
```bash
./process_spamhaus_queue.py --status
```

### Prosesser kø
```bash
# Standard (50 items)
./process_spamhaus_queue.py

# Custom batch size
./process_spamhaus_queue.py --batch-size 100

# Verbose
./process_spamhaus_queue.py --batch-size 50 --verbose
```

### Daemon mode
```bash
# Start
./process_spamhaus_queue.py --daemon --interval 300

# Med custom interval (sekunder)
./process_spamhaus_queue.py --daemon --interval 600  # Hver 10. minutt
```

### Cleanup
```bash
# Fjern completed items > 7 dager
./process_spamhaus_queue.py --cleanup 7

# Fjern completed items > 30 dager
./process_spamhaus_queue.py --cleanup 30
```

## 🎯 Best Practices

1. **Start med cron** (enklest): `*/30 * * * *` for vanlig drift
2. **Bruk daemon** ved første gangs learn med 1000+ e-poster
3. **Overvåk køen** de første dagene: `--status` daglig
4. **Rydd opp** ukentlig: `--cleanup 7`
5. **Sjekk logs** ved problemer: `/var/log/spamhaus_queue.log`

## ✅ Ferdig!

Køsystemet er nå satt opp og vil automatisk:
- Fange opp rate-limited submissions
- Prosessere dem i bakgrunnen
- Respektere Spamhaus API limits
- Fortsette fra der det slapp ved neste kjøring

**Neste steg:** Kjør `spam_trainer.py --learn` og se køen i aksjon! 🚀
