# Spamhaus Queue Processing - Crontab Setup
# ==========================================

## Anbefalt Oppsett for SmarteSider

### Scenario 1: Normal Drift (etter første gangs learn)
# Prosesser kø hver 30. minutt (lavt volum)
```crontab
*/30 * * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 50 >> /var/log/spamhaus_queue.log 2>&1
```

### Scenario 2: Nattkjøring (mer aggressiv)
# Prosesser større batch midt på natten når API-er har lavere trafikk
```crontab
# Hver dag kl 01:00 - 06:00, hver time med større batch
0 1-6 * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 200 >> /var/log/spamhaus_queue.log 2>&1
```

### Scenario 3: Kombinert (anbefalt for produksjon)
```crontab
# Dagtid: småbatches hver 30. minutt
*/30 7-23 * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 50 >> /var/log/spamhaus_queue.log 2>&1

# Nattetid: større batches hver time
0 0-6 * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 200 >> /var/log/spamhaus_queue.log 2>&1

# Daglig opprydding av gamle ferdige submissions
0 4 * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --cleanup 7 >> /var/log/spamhaus_queue.log 2>&1
```

### Scenario 4: Første gangs learn (masse e-poster)
# Kjør daemon i bakgrunn som prosesserer kontinuerlig med pauser
```bash
# Start daemon (kjør én gang i screen/tmux):
nohup /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --daemon --interval 120 >> /var/log/spamhaus_queue.log 2>&1 &

# Eller som systemd service (se nedenfor)
```

---

## Systemd Service (anbefalt for daemon mode)

Opprett: `/etc/systemd/system/spamhaus-queue.service`

```ini
[Unit]
Description=Spamhaus Queue Processor Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/Terje/scripts/Laer-av-spamfolder
ExecStart=/usr/bin/python3 /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --daemon --interval 300
Restart=always
RestartSec=10
StandardOutput=append:/var/log/spamhaus_queue.log
StandardError=append:/var/log/spamhaus_queue.log

[Install]
WantedBy=multi-user.target
```

Aktiver service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable spamhaus-queue
sudo systemctl start spamhaus-queue
sudo systemctl status spamhaus-queue
```

---

## Manuell Kjøring

### Sjekk kø-status
```bash
./process_spamhaus_queue.py --status
```

Output:
```
============================================================
  SPAMHAUS SUBMISSION QUEUE STATUS
============================================================

📊 Overall:
  Total items:      523
  Pending:          487
  Processing:       0
  Completed:        36
  Failed:           0

⏰ Oldest pending: 2h 34m ago

📦 Pending by Type:
  domain    : 234
  url       : 189
  email     : 54
  ip        : 10

⚠️  Pending by Threat Level:
  CRITICAL  : 54
  HIGH      : 423
  MEDIUM    : 10

📅 Today's Activity:
  Queued:           523
  Processed:        36
  Failed:           0
  Rate Limited:     1
============================================================
```

### Kjør én batch manuelt
```bash
# Standard (50 items)
./process_spamhaus_queue.py

# Større batch
./process_spamhaus_queue.py --batch-size 100

# Verbose output
./process_spamhaus_queue.py --batch-size 50 --verbose
```

### Rydd opp i gamle ferdige submissions
```bash
# Fjern completed items eldre enn 7 dager
./process_spamhaus_queue.py --cleanup 7

# Fjern completed items eldre enn 30 dager
./process_spamhaus_queue.py --cleanup 30
```

---

## Logging

### View live log
```bash
tail -f /var/log/spamhaus_queue.log
```

### Søk etter rate limit events
```bash
grep "rate limit" /var/log/spamhaus_queue.log
```

### Tell submissions siste time
```bash
grep "✅ Submitted" /var/log/spamhaus_queue.log | tail -n 50
```

---

## Konfigurasjon (config.yaml)

```yaml
reporting:
  spamhaus_enabled: true
  spamhaus_api_key: "YOUR_API_KEY"
  
  # Rate limiting
  spamhaus_max_per_run: 50         # Max før pause i denne kjøringen
  spamhaus_retry_after_429: 3600   # 1 time cooldown etter 429
  spamhaus_use_queue: true         # Aktiver kø-system
```

**Tips:**
- `spamhaus_max_per_run: 50` - Konservativt, trygt for daglig drift
- `spamhaus_max_per_run: 100` - Mer aggressivt for nattkjøring
- `spamhaus_retry_after_429: 3600` - 1 time (anbefalt)
- `spamhaus_retry_after_429: 7200` - 2 timer (mer forsiktig)

---

## Hvordan Det Fungerer

### Flow Diagram
```
spam_trainer.py (--learn)
     │
     ├─> Email 1-50: Submit direkte til Spamhaus ✅
     ├─> Email 51: Rate limit hit! 📥 Legger til i kø
     ├─> Email 52-1000: 📥 Alle legges i kø
     │
     └─> Ferdig med learn
     
(30 minutter senere - cron trigger)

process_spamhaus_queue.py
     │
     ├─> Henter 50 items fra kø
     ├─> Email 51-100: Submit til Spamhaus ✅
     └─> Ferdig (fortsetter neste cron-runde)
```

### Database
Køen bruker SQLite: `/home/Terje/scripts/Laer-av-spamfolder/spamhaus_queue.db`

Tabeller:
- `submission_queue` - Pending submissions
- `queue_stats` - Daglig statistikk

### Prioritering
Submissions prosesseres i prioritert rekkefølge:

1. **CRITICAL** (virus/malware emails) - prioritet 90
2. **HIGH** (domains, URLs) - prioritet 70
3. **MEDIUM** (IPs) - prioritet 50
4. **LOW** - prioritet 30

Innenfor samme prioritet: FIFO (først inn, først ut)

---

## Troubleshooting

### Køen vokser bare, ingen blir prosessert
```bash
# Sjekk status
./process_spamhaus_queue.py --status

# Sjekk om cron kjører
grep "process_spamhaus_queue" /var/log/syslog

# Test manuell kjøring
./process_spamhaus_queue.py --batch-size 10 --verbose
```

### Mange "rate limited" i loggen
Det er normalt! Øk intervallet mellom cron-kjøringer:
```crontab
# I stedet for hver 30. minutt:
*/30 * * * * ...

# Bruk hver time:
0 * * * * ...
```

### API key ugyldig
```bash
# Sjekk API key i config.yaml
grep "spamhaus_api_key" config.yaml

# Test manuelt
curl -H "Authorization: Bearer YOUR_KEY" \
  https://submit.spamhaus.org/portal/api/v1/lookup/threats-types
```

### Database låst (rare tilfeller)
```bash
# Hvis database er korrupt
rm spamhaus_queue.db
# Køen blir automatisk recreated, men pending items går tapt
```

---

## Monitorering

### Daglig rapport via cron
```crontab
# Send status hver morgen kl 08:00
0 8 * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --status | mail -s "Spamhaus Queue Status" terje@smartesider.no
```

### Prometheus metrics (fremtidig)
Kan legge til Prometheus exporter for å overvåke:
- Queue size
- Processing rate
- Rate limit hits
- Failed submissions

---

## Best Practices

1. **Start konservativt**: Bruk `--batch-size 50` til du ser mønsteret
2. **Natt er bedre**: Større batches på natten (mindre trafikk på Spamhaus API)
3. **Overvåk køen**: Sjekk `--status` daglig første uken
4. **Rydd opp**: Kjør `--cleanup 7` ukentlig for å holde databasen liten
5. **Ikke panic ved rate limit**: Det er forventet ved første gangs learn!

---

## Eksempel: Første gangs learn (stor kø)

```bash
# Dag 1: Kjør learn (får 429 etter ~50 emails, resten går i kø)
cd /home/Terje/scripts/Laer-av-spamfolder
./spam_trainer.py --learn

# Sjekk hva som er i køen
./process_spamhaus_queue.py --status
# Output: Pending: 1247

# Start daemon for å prosessere kontinuerlig
nohup ./process_spamhaus_queue.py --daemon --interval 120 > /var/log/spamhaus_daemon.log 2>&1 &

# Sjekk fremgang hver time
watch -n 3600 './process_spamhaus_queue.py --status'

# Etter ~24-48 timer: Køen tom
# Stopp daemon (finn PID og kill)
ps aux | grep process_spamhaus_queue
kill <PID>

# Bytt til cron for daglig drift
crontab -e
# Legg til: */30 * * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 50
```

---

## Support

Ved problemer:
1. Sjekk `/var/log/spamhaus_queue.log`
2. Kjør `--status` for å se køtilstand
3. Test manuelt med `--verbose`
4. Sjekk Spamhaus API status: https://www.spamhaus.org/

God jobbing med køsystemet! 🚀
