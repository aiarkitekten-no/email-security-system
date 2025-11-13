#!/usr/bin/env python3
"""
Advanced SpamAssassin Learning System - v3.1
Automated spam detection and learning with comprehensive reporting
Virus & Phishing Protection with ClamAV
"""

import os
import sys
import sqlite3
import hashlib
import subprocess
import time
import socket
import argparse
import csv
import json
import yaml
import re
import requests
from datetime import datetime, timedelta
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import parseaddr
from email import message_from_bytes
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import dns.resolver
import logging
from logging.handlers import RotatingFileHandler

# v3.0 imports
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from jinja2 import Template
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from collections import Counter, defaultdict


class Config:
    """Configuration manager"""
    DEFAULT_CONFIG_PATHS = [
        '/etc/spamtrainer/config.yaml',
        '~/.config/spamtrainer/config.yaml',
        './config.yaml'
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = self._find_config(config_path)
        self.config = self._load_config()
    
    def _find_config(self, config_path: Optional[str]) -> str:
        if config_path and os.path.exists(config_path):
            return config_path
        for path in self.DEFAULT_CONFIG_PATHS:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                return expanded
        raise FileNotFoundError("No config file found. Please create config.yaml")
    
    def _load_config(self) -> dict:
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # v3.0: Validate configuration
        self._validate_config(config)
        return config
    
    def _validate_config(self, config: dict):
        """Validate configuration for required settings and paths (v3.0)"""
        errors = []
        warnings = []
        
        # Check required sections
        required_sections = ['general', 'learning', 'reporting']
        for section in required_sections:
            if section not in config:
                errors.append(f"Missing required section: [{section}]")
        
        if errors:
            raise ValueError(f"Config validation failed: {'; '.join(errors)}")
        
        # Validate maildir path
        maildir = config.get('general', {}).get('maildir_base')
        if maildir and not os.path.exists(maildir):
            warnings.append(f"Maildir does not exist: {maildir}")
        
        # Validate sa-learn binary
        sa_learn = config.get('general', {}).get('sa_learn_bin', '/usr/bin/sa-learn')
        if not os.path.exists(sa_learn):
            warnings.append(f"sa-learn binary not found: {sa_learn}")
        elif not os.access(sa_learn, os.X_OK):
            errors.append(f"sa-learn binary not executable: {sa_learn}")
        
        # Validate database path directory
        db_path = config.get('statistics', {}).get('database_path', '/tmp/spamtrainer.db')
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create database directory {db_dir}: {e}")
        
        # Validate backup directory
        backup_dir = config.get('bayes', {}).get('backup_dir')
        if backup_dir and not os.path.exists(backup_dir):
            try:
                os.makedirs(backup_dir, exist_ok=True)
            except Exception as e:
                warnings.append(f"Cannot create backup directory {backup_dir}: {e}")
        
        # Validate email settings if HTML reports enabled
        if config.get('reporting', {}).get('html_reports', False):
            report_to = config.get('reporting', {}).get('html_report_to')
            if not report_to or '@' not in report_to:
                warnings.append("HTML reports enabled but html_report_to is not a valid email")
        
        # Validate parallel workers
        workers = config.get('general', {}).get('parallel_workers', 0)
        if workers < 0:
            errors.append(f"parallel_workers must be >= 0, got {workers}")
        
        # Log warnings
        if warnings:
            print(f"⚠️  Configuration warnings:")
            for warning in warnings:
                print(f"   - {warning}")
        
        if errors:
            raise ValueError(f"Config validation failed: {'; '.join(errors)}")
    
    def get(self, section: str, key: str, default=None):
        return self.config.get(section, {}).get(key, default)
    
    def get_section(self, section: str) -> dict:
        return self.config.get(section, {})


class Logger:
    """Rotating file logger"""
    def __init__(self, config: Config):
        self.logger = self._setup(config)
    
    def _setup(self, config: Config):
        log_file = config.get('logging', 'log_file', '/tmp/spamtrainer.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        logger = logging.getLogger('spamtrainer')
        logger.setLevel(logging.INFO)
        
        handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)
        
        if not config.get('general', 'quiet_mode', False):
            console = logging.StreamHandler()
            console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            logger.addHandler(console)
        
        return logger
    
    def info(self, msg): self.logger.info(msg)
    def warning(self, msg): self.logger.warning(msg)
    def error(self, msg): self.logger.error(msg)
    def debug(self, msg): self.logger.debug(msg)


class ScanTracker:
    """Track scanned emails to avoid duplicate processing (v3.2.1)"""
    
    def __init__(self, db_path: str, logger: Logger):
        self.db_path = db_path
        self.logger = logger
        self.session_id = None
    
    def start_session(self, scan_mode: str = 'incremental') -> int:
        """Start a new scan session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_sessions (start_time, scan_mode, status)
            VALUES (?, ?, 'running')
        ''', (datetime.now().isoformat(), scan_mode))
        conn.commit()
        self.session_id = cursor.lastrowid
        conn.close()
        self.logger.info(f"📊 Scan session started: {self.session_id} (mode: {scan_mode})")
        return self.session_id
    
    def is_already_scanned(self, email_path: str, force_rescan: bool = False) -> Dict:
        """Check if email was already scanned
        
        Returns:
            {
                'scanned': bool,
                'needs_rescan': bool,
                'reason': str,
                'record': dict or None
            }
        """
        if force_rescan:
            return {'scanned': False, 'needs_rescan': True, 'reason': 'force-rescan'}
        
        # Extract message-id and filename
        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            message_id = msg.get('Message-ID', '').strip('<>')
            filename = os.path.basename(email_path)
            file_mtime = int(os.path.getmtime(email_path))
        except Exception as e:
            self.logger.error(f"Error reading email {email_path}: {e}")
            return {'scanned': False, 'needs_rescan': False, 'reason': 'error'}
        
        if not message_id:
            # No Message-ID, use filename as fallback
            message_id = f"no-msgid-{filename}"
        
        # Check database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM scanned_emails 
            WHERE message_id = ? OR email_filename = ?
        ''', (message_id, filename))
        
        record = cursor.fetchone()
        conn.close()
        
        if not record:
            # Never scanned before
            return {
                'scanned': False,
                'needs_rescan': False,
                'reason': 'new-email',
                'record': None
            }
        
        # Convert to dict
        columns = ['id', 'message_id', 'email_path', 'email_filename', 'mailbox',
                   'first_scanned', 'last_scanned', 'email_date', 'file_mtime',
                   'virus_scanned', 'virus_found', 'virus_name',
                   'phishing_scanned', 'phishing_detected', 'phishing_score',
                   'spam_scanned', 'spam_score', 'sender', 'subject', 'recipient',
                   'scan_count', 'rescan_reason']
        record_dict = dict(zip(columns, record))
        
        # Check if file was modified since last scan
        if record_dict['file_mtime'] and record_dict['file_mtime'] < file_mtime:
            return {
                'scanned': True,
                'needs_rescan': True,
                'reason': 'file-modified',
                'record': record_dict
            }
        
        # Already scanned and not modified
        return {
            'scanned': True,
            'needs_rescan': False,
            'reason': 'already-scanned',
            'record': record_dict
        }
    
    def record_scan(self, email_path: str, scan_results: Dict):
        """Record scan results for an email"""
        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            message_id = msg.get('Message-ID', '').strip('<>')
            filename = os.path.basename(email_path)
            file_mtime = int(os.path.getmtime(email_path))
            
            if not message_id:
                message_id = f"no-msgid-{filename}"
            
            # Extract metadata
            sender = msg.get('From', '')
            subject = msg.get('Subject', '')
            recipient = msg.get('To', '')
            email_date = msg.get('Date', '')
            mailbox = self._extract_mailbox_from_path(email_path)
            
            now = datetime.now().isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if exists
            cursor.execute('SELECT id, scan_count FROM scanned_emails WHERE message_id = ?', 
                         (message_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing
                email_id, scan_count = existing
                cursor.execute('''
                    UPDATE scanned_emails SET
                        last_scanned = ?,
                        file_mtime = ?,
                        virus_scanned = ?,
                        virus_found = ?,
                        virus_name = ?,
                        phishing_scanned = ?,
                        phishing_detected = ?,
                        phishing_score = ?,
                        spam_scanned = ?,
                        spam_score = ?,
                        scan_count = scan_count + 1,
                        rescan_reason = ?
                    WHERE id = ?
                ''', (
                    now, file_mtime,
                    scan_results.get('virus_scanned', 0),
                    scan_results.get('virus_found', 0),
                    scan_results.get('virus_name'),
                    scan_results.get('phishing_scanned', 0),
                    scan_results.get('phishing_detected', 0),
                    scan_results.get('phishing_score', 0),
                    scan_results.get('spam_scanned', 0),
                    scan_results.get('spam_score', 0.0),
                    scan_results.get('rescan_reason', 'periodic'),
                    email_id
                ))
            else:
                # Insert new
                cursor.execute('''
                    INSERT INTO scanned_emails (
                        message_id, email_path, email_filename, mailbox,
                        first_scanned, last_scanned, email_date, file_mtime,
                        virus_scanned, virus_found, virus_name,
                        phishing_scanned, phishing_detected, phishing_score,
                        spam_scanned, spam_score,
                        sender, subject, recipient, scan_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    message_id, email_path, filename, mailbox,
                    now, now, email_date, file_mtime,
                    scan_results.get('virus_scanned', 0),
                    scan_results.get('virus_found', 0),
                    scan_results.get('virus_name'),
                    scan_results.get('phishing_scanned', 0),
                    scan_results.get('phishing_detected', 0),
                    scan_results.get('phishing_score', 0),
                    scan_results.get('spam_scanned', 0),
                    scan_results.get('spam_score', 0.0),
                    sender, subject, recipient
                ))
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            self.logger.error(f"Error recording scan for {email_path}: {e}")
    
    def end_session(self, stats: Dict):
        """End current scan session with statistics"""
        if not self.session_id:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scan_sessions SET
                end_time = ?,
                duration_seconds = ?,
                total_emails_found = ?,
                new_emails_scanned = ?,
                skipped_already_scanned = ?,
                rescanned_modified = ?,
                viruses_found = ?,
                phishing_found = ?,
                spam_found = ?,
                status = 'completed'
            WHERE id = ?
        ''', (
            datetime.now().isoformat(),
            stats.get('duration_seconds', 0),
            stats.get('total_emails_found', 0),
            stats.get('new_emails_scanned', 0),
            stats.get('skipped_already_scanned', 0),
            stats.get('rescanned_modified', 0),
            stats.get('viruses_found', 0),
            stats.get('phishing_found', 0),
            stats.get('spam_found', 0),
            self.session_id
        ))
        conn.commit()
        conn.close()
        
        self.logger.info(f"✅ Scan session {self.session_id} completed")
        self.logger.info(f"   New: {stats.get('new_emails_scanned', 0)}, "
                        f"Skipped: {stats.get('skipped_already_scanned', 0)}, "
                        f"Re-scanned: {stats.get('rescanned_modified', 0)}")
    
    def get_statistics(self) -> Dict:
        """Get overall scanning statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total scanned emails
        cursor.execute('SELECT COUNT(*) FROM scanned_emails')
        total_scanned = cursor.fetchone()[0]
        
        # Threats found
        cursor.execute('SELECT COUNT(*) FROM scanned_emails WHERE virus_found = 1')
        total_viruses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scanned_emails WHERE phishing_detected = 1')
        total_phishing = cursor.fetchone()[0]
        
        # Recent session stats
        cursor.execute('''
            SELECT 
                AVG(new_emails_scanned),
                AVG(skipped_already_scanned),
                AVG(duration_seconds)
            FROM scan_sessions 
            WHERE status = 'completed'
            ORDER BY start_time DESC 
            LIMIT 10
        ''')
        recent = cursor.fetchone()
        
        conn.close()
        
        return {
            'total_emails_tracked': total_scanned,
            'total_viruses_found': total_viruses,
            'total_phishing_found': total_phishing,
            'avg_new_per_scan': recent[0] if recent and recent[0] else 0,
            'avg_skipped_per_scan': recent[1] if recent and recent[1] else 0,
            'avg_scan_time_seconds': recent[2] if recent and recent[2] else 0
        }
    
    def _extract_mailbox_from_path(self, email_path: str) -> str:
        """Extract mailbox identifier from email path"""
        # Example: /var/qmail/mailnames/domain.no/user/Maildir/.Spam/cur/file
        # Returns: user@domain.no/.Spam
        parts = email_path.split('/')
        try:
            if 'mailnames' in parts:
                idx = parts.index('mailnames')
                domain = parts[idx + 1]
                user = parts[idx + 2]
                folder = parts[idx + 4] if len(parts) > idx + 4 else 'INBOX'
                return f"{user}@{domain}/{folder}"
        except:
            pass
        return 'unknown'


class Database:
    """SQLite statistics database"""
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.db_path = config.get('statistics', 'database_path', '/tmp/spamtrainer.db')
        self._init_db()
    
    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS learning_history
                     (id INTEGER PRIMARY KEY, timestamp TEXT, email_hash TEXT UNIQUE,
                      message_type TEXT, sender TEXT, subject TEXT, learned BOOLEAN)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS sender_tracking
                     (id INTEGER PRIMARY KEY, sender_email TEXT UNIQUE, sender_ip TEXT,
                      spam_count INTEGER, ham_count INTEGER, first_seen TEXT, 
                      last_seen TEXT, reported BOOLEAN, blocked BOOLEAN)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS daily_stats
                     (date TEXT PRIMARY KEY, spam_learned INTEGER, ham_learned INTEGER,
                      emails_processed INTEGER, senders_reported INTEGER, ips_blocked INTEGER)''')
        
        # v3.1: Threat detection table
        c.execute('''CREATE TABLE IF NOT EXISTS threat_detections
                     (id INTEGER PRIMARY KEY, timestamp TEXT, recipient TEXT,
                      sender TEXT, subject TEXT, threat_type TEXT, threat_name TEXT,
                      threat_level TEXT, threat_details TEXT, action_taken TEXT)''')
        
        # v3.2.1: Scan tracking tables (incremental scanning)
        c.execute('''CREATE TABLE IF NOT EXISTS scanned_emails
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      message_id TEXT UNIQUE NOT NULL,
                      email_path TEXT NOT NULL,
                      email_filename TEXT NOT NULL,
                      mailbox TEXT NOT NULL,
                      first_scanned TEXT NOT NULL,
                      last_scanned TEXT NOT NULL,
                      email_date TEXT,
                      file_mtime INTEGER,
                      virus_scanned INTEGER DEFAULT 0,
                      virus_found INTEGER DEFAULT 0,
                      virus_name TEXT,
                      phishing_scanned INTEGER DEFAULT 0,
                      phishing_detected INTEGER DEFAULT 0,
                      phishing_score INTEGER DEFAULT 0,
                      spam_scanned INTEGER DEFAULT 0,
                      spam_score REAL DEFAULT 0.0,
                      sender TEXT,
                      subject TEXT,
                      recipient TEXT,
                      scan_count INTEGER DEFAULT 1,
                      rescan_reason TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS scan_sessions
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      start_time TEXT NOT NULL,
                      end_time TEXT,
                      duration_seconds REAL,
                      total_emails_found INTEGER DEFAULT 0,
                      new_emails_scanned INTEGER DEFAULT 0,
                      skipped_already_scanned INTEGER DEFAULT 0,
                      rescanned_modified INTEGER DEFAULT 0,
                      viruses_found INTEGER DEFAULT 0,
                      phishing_found INTEGER DEFAULT 0,
                      spam_found INTEGER DEFAULT 0,
                      scan_mode TEXT,
                      threat_detection_enabled INTEGER,
                      status TEXT DEFAULT 'running',
                      error_message TEXT)''')
        
        # Create indexes for better query performance (v3.0)
        c.execute('CREATE INDEX IF NOT EXISTS idx_learning_hash ON learning_history(email_hash)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_learning_type ON learning_history(message_type)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_learning_timestamp ON learning_history(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_sender_email ON sender_tracking(sender_email)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_sender_spam_count ON sender_tracking(spam_count DESC)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_sender_reported ON sender_tracking(reported)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_daily_date ON daily_stats(date DESC)')
        
        # v3.1: Threat detection indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_detections(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_threat_recipient ON threat_detections(recipient)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_detections(threat_type)')
        
        # v3.2.1: Scan tracking indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_scanned_filename ON scanned_emails(email_filename)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_scanned_mailbox ON scanned_emails(mailbox)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_scanned_last_scanned ON scanned_emails(last_scanned)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_scanned_virus_found ON scanned_emails(virus_found)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_scanned_phishing_detected ON scanned_emails(phishing_detected)')

        
        conn.commit()
        conn.close()
        self.logger.info(f"Database initialized: {self.db_path}")
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def is_email_learned(self, email_hash: str):
        """Check if email has already been learned (v3.0 incremental learning)"""
        try:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute('SELECT 1 FROM learning_history WHERE email_hash = ? LIMIT 1', (email_hash,))
            result = c.fetchone() is not None
            conn.close()
            return result
        except Exception as e:
            self.logger.error(f"Failed to check learned status: {e}")
            return False
    
    def log_learning(self, email_hash: str, msg_type: str, sender: str, subject: str):
        try:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute('''INSERT OR IGNORE INTO learning_history 
                         (timestamp, email_hash, message_type, sender, subject, learned)
                         VALUES (?, ?, ?, ?, ?, 1)''',
                      (datetime.now().isoformat(), email_hash, msg_type, sender, subject))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to log: {e}")
    
    def update_sender_stats(self, sender: str, sender_ip: str, is_spam: bool):
        try:
            conn = self.get_connection()
            c = conn.cursor()
            now = datetime.now().isoformat()
            
            c.execute('SELECT id FROM sender_tracking WHERE sender_email = ?', (sender,))
            if c.fetchone():
                c.execute('''UPDATE sender_tracking SET 
                             spam_count = spam_count + ?, ham_count = ham_count + ?,
                             last_seen = ? WHERE sender_email = ?''',
                          (1 if is_spam else 0, 0 if is_spam else 1, now, sender))
            else:
                c.execute('''INSERT INTO sender_tracking 
                             (sender_email, sender_ip, spam_count, ham_count, 
                              first_seen, last_seen, reported, blocked)
                             VALUES (?, ?, ?, ?, ?, ?, 0, 0)''',
                          (sender, sender_ip, 1 if is_spam else 0, 
                           0 if is_spam else 1, now, now))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to update stats: {e}")
    
    def update_daily_stats(self, spam=0, ham=0, processed=0, reported=0, blocked=0):
        try:
            conn = self.get_connection()
            c = conn.cursor()
            today = datetime.now().date().isoformat()
            
            c.execute('SELECT date FROM daily_stats WHERE date = ?', (today,))
            if c.fetchone():
                c.execute('''UPDATE daily_stats SET 
                             spam_learned = spam_learned + ?,
                             ham_learned = ham_learned + ?,
                             emails_processed = emails_processed + ?,
                             senders_reported = senders_reported + ?,
                             ips_blocked = ips_blocked + ?
                             WHERE date = ?''',
                          (spam, ham, processed, reported, blocked, today))
            else:
                c.execute('''INSERT INTO daily_stats VALUES (?, ?, ?, ?, ?, ?)''',
                          (today, spam, ham, processed, reported, blocked))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to update daily stats: {e}")
    
    def get_statistics(self, days=7):
        conn = self.get_connection()
        c = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).date().isoformat()
        c.execute('''SELECT SUM(spam_learned), SUM(ham_learned), SUM(emails_processed),
                     SUM(senders_reported), SUM(ips_blocked)
                     FROM daily_stats WHERE date >= ?''', (cutoff,))
        row = c.fetchone()
        conn.close()
        return {
            'spam_learned': row[0] or 0,
            'ham_learned': row[1] or 0,
            'emails_processed': row[2] or 0,
            'senders_reported': row[3] or 0,
            'ips_blocked': row[4] or 0,
            'days': days
        }
    
    def get_repeat_offenders(self, threshold=5, days=7):
        conn = self.get_connection()
        c = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        c.execute('''SELECT sender_email, sender_ip, spam_count
                     FROM sender_tracking
                     WHERE spam_count >= ? AND last_seen >= ? AND reported = 0
                     ORDER BY spam_count DESC''', (threshold, cutoff))
        results = [{'email': r[0], 'ip': r[1], 'spam_count': r[2]} for r in c.fetchall()]
        conn.close()
        return results
    
    def mark_sender_reported(self, sender_email):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('UPDATE sender_tracking SET reported = 1 WHERE sender_email = ?', (sender_email,))
        conn.commit()
        conn.close()


class SpamAssassinLearner:
    """Main learning engine"""
    def __init__(self, config: Config, logger: Logger, database: Database, spamhaus_reporter=None):
        self.config = config
        self.logger = logger
        self.database = database
        self.spamhaus = spamhaus_reporter  # NEW v3.0
        self.sa_learn = config.get('general', 'sa_learn_bin', '/usr/bin/sa-learn')
        self.dry_run = config.get('general', 'dry_run', False)
        
        # v3.1: Threat detection instances
        self.virus_scanner = None
        self.phishing_detector = None
        self.threat_handler = None
        self.threat_db_manager = None  # NEW: External threat databases
    
    def set_threat_scanners(self, virus_scanner, phishing_detector, threat_handler, threat_db_manager=None):
        """Set threat detection instances (called by SpamTrainerApp)"""
        self.virus_scanner = virus_scanner
        self.phishing_detector = phishing_detector
        self.threat_handler = threat_handler
        self.threat_db_manager = threat_db_manager
    
    def set_scan_tracker(self, scan_tracker):
        """Set scan tracker for incremental scanning (v3.2.1)"""
        self.scan_tracker = scan_tracker
        self.scan_mode = 'incremental'  # 'incremental', 'full', 'force-rescan'
    
    def get_email_hash(self, path):
        try:
            with open(path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ""
    
    def extract_sender(self, path):
        try:
            with open(path, 'rb') as f:
                msg = message_from_bytes(f.read())
            return parseaddr(msg.get('From', ''))[1], ''
        except:
            return '', ''
    
    def scan_all_folders_for_threats(self, folders: List[str]):
        """
        v3.1: Scan all email folders for virus and phishing threats
        This runs BEFORE spam learning to protect users immediately
        """
        if not self.config.get('threat_detection', 'enabled', True):
            return
        
        if not self.virus_scanner or not self.phishing_detector or not self.threat_handler:
            self.logger.warning("Threat scanners not initialized, skipping threat detection")
            return
        
        # v3.2.1: Start scan tracking session
        force_rescan = getattr(self, 'force_rescan', False)
        scan_mode = 'force-rescan' if force_rescan else 'incremental'
        
        if hasattr(self, 'scan_tracker') and self.scan_tracker:
            session_id = self.scan_tracker.start_session(scan_mode)
            start_time = time.time()
        
        print(f"\n🦠 Scanning for virus & phishing threats...")
        print(f"   ClamAV: {'✓ Enabled' if self.virus_scanner.enabled else '✗ Disabled'}")
        print(f"   Phishing: {'✓ Enabled' if self.phishing_detector.enabled else '✗ Disabled'}")
        
        threats_found = 0
        emails_scanned = 0
        skipped_count = 0
        rescanned_count = 0
        
        for idx, folder in enumerate(folders, 1):
            if not os.path.exists(folder):
                continue
            
            try:
                files = os.listdir(folder)
                file_paths = [os.path.join(folder, f) for f in files if os.path.isfile(os.path.join(folder, f))]
                
                if not file_paths:
                    continue
                
                for email_path in file_paths:
                    # v3.2.1: Check if already scanned
                    if hasattr(self, 'scan_tracker') and self.scan_tracker:
                        scan_check = self.scan_tracker.is_already_scanned(email_path, force_rescan)
                        
                        if scan_check['scanned'] and not scan_check['needs_rescan']:
                            skipped_count += 1
                            continue
                        
                        if scan_check['needs_rescan']:
                            rescanned_count += 1
                    
                    emails_scanned += 1
                    
                    # Progress indicator for large scans
                    if (emails_scanned + skipped_count) % 100 == 0:
                        print(f"   Scanned {emails_scanned} emails, skipped {skipped_count}, found {threats_found} threats...", end='\r')
                    
                    try:
                        # 1. Virus scan
                        virus_result = self.virus_scanner.scan_email(email_path)
                        
                        # 2. Phishing analysis
                        phishing_result = self.phishing_detector.analyze_email(email_path)
                        
                        # v3.2.1: Record scan results
                        if hasattr(self, 'scan_tracker') and self.scan_tracker:
                            scan_results = {
                                'virus_scanned': 1,
                                'virus_found': 1 if virus_result.get('infected') else 0,
                                'virus_name': virus_result.get('virus_name'),
                                'phishing_scanned': 1,
                                'phishing_detected': 1 if phishing_result.get('phishing') else 0,
                                'phishing_score': phishing_result.get('score', 0),
                                'rescan_reason': scan_check.get('reason') if 'scan_check' in locals() else 'new'
                            }
                            self.scan_tracker.record_scan(email_path, scan_results)
                        
                        # 3. Handle threats (add warning to subject)
                        if virus_result.get('infected') or phishing_result.get('phishing'):
                            if self.threat_handler.handle_threat(email_path, virus_result, phishing_result):
                                threats_found += 1
                    
                    except Exception as e:
                        self.logger.debug(f"Error scanning {email_path}: {e}")
            
            except PermissionError:
                self.logger.warning(f"Permission denied: {folder}")
            except Exception as e:
                self.logger.error(f"Error scanning folder {folder}: {e}")
        
        # v3.2.1: End scan tracking session
        if hasattr(self, 'scan_tracker') and self.scan_tracker:
            stats = {
                'duration_seconds': time.time() - start_time,
                'total_emails_found': emails_scanned + skipped_count,
                'new_emails_scanned': emails_scanned - rescanned_count,
                'skipped_already_scanned': skipped_count,
                'rescanned_modified': rescanned_count,
                'viruses_found': threats_found,
                'phishing_found': threats_found,
                'spam_found': 0
            }
            self.scan_tracker.end_session(stats)
        
        if threats_found > 0:
            print(f"\n⚠️  Found and tagged {threats_found} threats in {emails_scanned} emails (skipped {skipped_count} already scanned)")
            self.logger.warning(f"Threats detected: {threats_found}/{emails_scanned} emails")
        else:
            print(f"✅ No threats found in {emails_scanned} emails (skipped {skipped_count} already scanned)\n")

    
    def learn_spam(self, folder):

        if not os.path.exists(folder):
            self.logger.warning(f"Folder does not exist: {folder}")
            return 0
        
        count = 0
        errors = 0
        skipped = 0
        
        try:
            files = os.listdir(folder)
        except PermissionError:
            self.logger.warning(f"Permission denied accessing: {folder}")
            return 0
        
        # Filter to actual files
        file_paths = [os.path.join(folder, f) for f in files if os.path.isfile(os.path.join(folder, f))]
        total_files = len(file_paths)
        
        if total_files == 0:
            return 0
        
        # v3.0: Incremental learning - filter out already learned emails
        incremental = self.config.get('general', 'incremental_learning', True)
        if incremental and not self.dry_run:
            new_file_paths = []
            for filepath in file_paths:
                email_hash = self.get_email_hash(filepath)
                if email_hash and not self.database.is_email_learned(email_hash):
                    new_file_paths.append(filepath)
                else:
                    skipped += 1
            
            file_paths = new_file_paths
            total_files = len(file_paths)
            
            if skipped > 0:
                self.logger.debug(f"Skipped {skipped} already learned emails")
            
            if total_files == 0:
                return 0
        
        # Batch learning: process files in batches of 50 for better performance
        batch_size = 50
        use_batch = self.config.get('general', 'batch_learning', True) and not self.dry_run
        
        if use_batch and total_files > 10:
            # Batch mode - much faster for large volumes
            for batch_start in range(0, total_files, batch_size):
                batch_end = min(batch_start + batch_size, total_files)
                batch = file_paths[batch_start:batch_end]
                
                if total_files > 100:
                    print(f"  Progress: {batch_end}/{total_files} files ({100*batch_end//total_files}%)", end='\r')
                
                try:
                    # Learn entire batch at once - MUCH faster
                    result = subprocess.run([self.sa_learn, '--spam'] + batch,
                                          capture_output=True, timeout=120, text=True)
                    if result.returncode == 0:
                        # Parse output to see how many were learned
                        # sa-learn output: "Learned tokens from X message(s)"
                        match = re.search(r'Learned tokens from (\d+)', result.stdout)
                        if match:
                            batch_count = int(match.group(1))
                            count += batch_count
                        else:
                            count += len(batch)  # Assume all succeeded
                        
                        # Log each file to database (in batch for speed)
                        for filepath in batch:
                            email_hash = self.get_email_hash(filepath)
                            if email_hash:
                                sender, ip = self.extract_sender(filepath)
                                self.database.log_learning(email_hash, 'spam', sender, '')
                                self.database.update_sender_stats(sender, ip, True)
                    else:
                        errors += len(batch)
                        self.logger.warning(f"Batch sa-learn failed: {result.stderr[:200]}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.error(f"Timeout learning batch {batch_start}-{batch_end}")
                    errors += len(batch)
                except Exception as e:
                    self.logger.error(f"Failed to learn batch: {e}")
                    errors += len(batch)
        else:
            # Individual file mode - slower but more granular (used for small folders or dry-run)
            for idx, filepath in enumerate(file_paths, 1):
                if total_files > 100 and idx % 50 == 0:
                    print(f"  Progress: {idx}/{total_files} files ({100*idx//total_files}%)", end='\r')
                
                email_hash = self.get_email_hash(filepath)
                if not email_hash:
                    continue
                
                if self.dry_run:
                    self.logger.debug(f"[DRY RUN] Would learn spam: {filepath}")
                    count += 1
                else:
                    try:
                        result = subprocess.run([self.sa_learn, '--spam', filepath],
                                              capture_output=True, timeout=30, text=True)
                        if result.returncode == 0:
                            count += 1
                            sender, ip = self.extract_sender(filepath)
                            self.database.log_learning(email_hash, 'spam', sender, '')
                            self.database.update_sender_stats(sender, ip, True)
                        else:
                            errors += 1
                            if errors <= 3:
                                self.logger.warning(f"sa-learn failed: {result.stderr[:100]}")
                    except subprocess.TimeoutExpired:
                        self.logger.error(f"Timeout learning {os.path.basename(filepath)}")
                        errors += 1
                    except Exception as e:
                        errors += 1
                        if errors <= 3:
                            self.logger.error(f"Failed to learn: {e}")
        
        if total_files > 100:
            print()  # Clear progress line
        
        if errors > 3:
            self.logger.warning(f"Total errors in {folder}: {errors}")
        
        # v3.0: Report spam to Spamhaus API
        if count > 0 and self.spamhaus and self.spamhaus.enabled:
            self._report_spam_to_spamhaus(file_paths[:count])  # Report learned emails
        
        return count
    
    def _report_spam_to_spamhaus(self, file_paths: List[str]):
        """
        Report spam emails to Spamhaus API (v3.0)
        Implements #1 (RAW email), #2 (IP), #3 (Domain), #4 (URLs)
        """
        if not self.spamhaus or not file_paths:
            return
        
        reported_count = 0
        max_reports = 50  # Limit reports per batch to avoid rate limiting
        
        for filepath in file_paths[:max_reports]:
            try:
                # #1: Submit RAW email (most powerful)
                result = self.spamhaus.submit_raw_email(filepath)
                if result and result.get('status') != 208:
                    reported_count += 1
                
                # #2 & #3: Extract and submit IP + Domain
                sender, ip = self.extract_sender(filepath)
                if ip:
                    self.spamhaus.submit_ip(ip, f"Spam from {sender}")
                if sender and '@' in sender:
                    domain = sender.split('@')[1]
                    self.spamhaus.submit_domain(domain, f"Spam domain: {domain}")
                
                # #4: Extract and submit URLs
                urls = self.spamhaus.extract_urls_from_email(filepath)
                for url in urls[:5]:  # Max 5 URLs per email
                    self.spamhaus.submit_url(url, "Suspicious URL in spam email")
                
            except Exception as e:
                self.logger.debug(f"Error reporting to Spamhaus: {e}")
        
        if reported_count > 0:
            self.logger.info(f"📤 Reported {reported_count} spam emails to Spamhaus")
    
    def learn_spam_from_trash(self, folder, max_age_days=7):
        """
        Learn spam from trash folder - only recent deletions (v3.0)
        Users often delete spam directly without moving to .Spam first
        
        Args:
            folder: Trash folder path
            max_age_days: Only learn from emails modified within this timeframe
        
        Returns:
            Number of spam emails learned
        """
        if not os.path.exists(folder):
            self.logger.warning(f"Trash folder does not exist: {folder}")
            return 0
        
        files = os.listdir(folder)
        if not files:
            return 0
        
        count = 0
        skipped_old = 0
        skipped_learned = 0
        cutoff_time = time.time() - (max_age_days * 86400)
        
        # Filter files by modification time and learning status
        file_paths = []
        for f in files:
            filepath = os.path.join(folder, f)
            if not os.path.isfile(filepath):
                continue
            
            # Check file age
            try:
                mtime = os.path.getmtime(filepath)
                if mtime < cutoff_time:
                    skipped_old += 1
                    continue
            except Exception as e:
                self.logger.debug(f"Error checking mtime for {filepath}: {e}")
                continue
            
            # Check if already learned
            email_hash = self.get_email_hash(filepath)
            if self.database.is_email_learned(email_hash):
                skipped_learned += 1
                continue
            
            file_paths.append(filepath)
        
        if not file_paths:
            if skipped_old > 0:
                print(f"  ⏭️  Skipped {skipped_old} emails older than {max_age_days} days")
            if skipped_learned > 0:
                print(f"  ⏭️  Skipped {skipped_learned} already learned emails")
            return 0
        
        print(f"  📝 Learning {len(file_paths)} recent spam emails from trash...")
        
        # Use batch learning
        if self.config.get('general', 'batch_learning', True):
            batch_size = 50
            for i in range(0, len(file_paths), batch_size):
                batch = file_paths[i:i + batch_size]
                try:
                    result = subprocess.run(
                        [self.sa_learn, '--spam'] + batch,
                        capture_output=True, text=True, timeout=300
                    )
                    if result.returncode == 0:
                        # Parse "Learned tokens from X message(s)"
                        match = re.search(r'(\d+) message\(s\)', result.stdout)
                        if match:
                            learned = int(match.group(1))
                            count += learned
                            
                            # Log each learned email
                            for filepath in batch[:learned]:
                                sender, ip = self.extract_sender(filepath)
                                subject = self.extract_subject(filepath)
                                email_hash = self.get_email_hash(filepath)
                                self.database.log_learning(email_hash, 'spam', sender, subject)
                                if sender and ip:
                                    self.database.update_sender_stats(sender, ip, True)
                except Exception as e:
                    self.logger.error(f"Batch learning failed for trash: {e}")
        
        # Report to Spamhaus
        if count > 0 and self.spamhaus and self.spamhaus.enabled:
            self._report_spam_to_spamhaus(file_paths[:count])
        
        if skipped_old > 0:
            print(f"  ⏭️  Skipped {skipped_old} old emails")
        if skipped_learned > 0:
            print(f"  ⏭️  Skipped {skipped_learned} already learned")
        
        return count
    
    def check_ham_folder_for_blacklisted(self, folder):
        """
        v3.0: NEW LOGIC - Check ham folders for blacklisted senders, do NOT learn as ham
        Only block if threshold+ emails from DNSBL-listed senders found
        """
        if not os.path.exists(folder):
            self.logger.warning(f"Folder does not exist: {folder}")
            return 0
        
        try:
            files = os.listdir(folder)
        except PermissionError:
            self.logger.warning(f"Permission denied accessing: {folder}")
            return 0
        
        # Check up to max_ham emails per folder
        max_check = self.config.get('general', 'max_ham_per_folder', 100)
        file_paths = [os.path.join(folder, f) for f in files if os.path.isfile(os.path.join(folder, f))][:max_check]
        
        if len(file_paths) == 0:
            return 0
        
        # Get threshold from config (default: 5)
        blacklist_threshold = self.config.get('learning', 'blacklist_threshold', 5)
        
        blacklisted_senders = {}  # sender -> count
        total_checked = 0
        
        print(f"  Checking {len(file_paths)} emails for blacklisted senders...")
        
        for filepath in file_paths:
            try:
                sender, ip = self.extract_sender(filepath)
                if sender and ip:
                    total_checked += 1
                    
                    # Check if sender IP is on DNSBL
                    if self.reporter.check_dnsbl(ip, sender):
                        if sender not in blacklisted_senders:
                            blacklisted_senders[sender] = 0
                        blacklisted_senders[sender] += 1
                        
            except Exception as e:
                self.logger.debug(f"Error checking {filepath}: {e}")
                continue
        
        # Block senders with threshold+ emails from DNSBL
        blocked_count = 0
        for sender, count in blacklisted_senders.items():
            if count >= blacklist_threshold:
                self.logger.warning(f"⚠️  BLOCKING sender {sender} - {count} emails from DNSBL-listed IP (threshold: {blacklist_threshold})")
                self.database.update_sender_stats(sender, '', True)  # Mark as reported/blocked
                blocked_count += 1
        
        if blocked_count > 0:
            print(f"  🚫 Blocked {blocked_count} senders with {blacklist_threshold}+ blacklisted emails")
        
        if len(blacklisted_senders) > 0:
            self.logger.info(f"Found {len(blacklisted_senders)} blacklisted senders in {folder}, blocked {blocked_count}")
        
        return blocked_count
    
    def learn_ham(self, folder):
        """
        DEPRECATED - v3.0: Ham folders should NOT be learned from
        Use check_ham_folder_for_blacklisted() instead
        """
        self.logger.warning("learn_ham() called but ham learning is disabled in v3.0")
        return 0
        
        # OLD CODE BELOW - KEPT FOR REFERENCE
        if not os.path.exists(folder):
            self.logger.warning(f"Folder does not exist: {folder}")
            return 0
        
        count = 0
        errors = 0
        skipped = 0
        
        try:
            files = os.listdir(folder)
        except PermissionError:
            self.logger.warning(f"Permission denied accessing: {folder}")
            return 0
        
        # Only learn from first N emails per folder to avoid overwhelming
        max_ham = self.config.get('general', 'max_ham_per_folder', 100)
        
        # Filter to actual files and limit count
        file_paths = [os.path.join(folder, f) for f in files if os.path.isfile(os.path.join(folder, f))][:max_ham]
        total_files = len(file_paths)
        
        if total_files == 0:
            return 0
        
        # v3.0: Incremental learning - filter out already learned emails
        incremental = self.config.get('general', 'incremental_learning', True)
        if incremental and not self.dry_run:
            new_file_paths = []
            for filepath in file_paths:
                email_hash = self.get_email_hash(filepath)
                if email_hash and not self.database.is_email_learned(email_hash):
                    new_file_paths.append(filepath)
                else:
                    skipped += 1
            
            file_paths = new_file_paths
            total_files = len(file_paths)
            
            if skipped > 0:
                self.logger.debug(f"Skipped {skipped} already learned ham emails")
            
            if total_files == 0:
                return 0
        
        # Batch learning: process files in batches of 50
        batch_size = 50
        use_batch = self.config.get('general', 'batch_learning', True) and not self.dry_run
        
        if use_batch and total_files > 10:
            # Batch mode - much faster
            for batch_start in range(0, total_files, batch_size):
                batch_end = min(batch_start + batch_size, total_files)
                batch = file_paths[batch_start:batch_end]
                
                if total_files > 50:
                    print(f"  Progress: {batch_end}/{total_files} files ({100*batch_end//total_files}%)", end='\r')
                
                try:
                    result = subprocess.run([self.sa_learn, '--ham'] + batch,
                                          capture_output=True, timeout=120, text=True)
                    if result.returncode == 0:
                        match = re.search(r'Learned tokens from (\d+)', result.stdout)
                        if match:
                            batch_count = int(match.group(1))
                            count += batch_count
                        else:
                            count += len(batch)
                        
                        for filepath in batch:
                            email_hash = self.get_email_hash(filepath)
                            if email_hash:
                                sender, ip = self.extract_sender(filepath)
                                self.database.log_learning(email_hash, 'ham', sender, '')
                                self.database.update_sender_stats(sender, ip, False)
                    else:
                        errors += len(batch)
                        self.logger.warning(f"Batch sa-learn failed: {result.stderr[:200]}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.error(f"Timeout learning batch {batch_start}-{batch_end}")
                    errors += len(batch)
                except Exception as e:
                    self.logger.error(f"Failed to learn batch: {e}")
                    errors += len(batch)
        else:
            # Individual mode for small folders or dry-run
            for idx, filepath in enumerate(file_paths, 1):
                if total_files > 50 and idx % 25 == 0:
                    print(f"  Progress: {idx}/{total_files} files ({100*idx//total_files}%)", end='\r')
                
                email_hash = self.get_email_hash(filepath)
                if not email_hash:
                    continue
                
                if self.dry_run:
                    self.logger.debug(f"[DRY RUN] Would learn ham: {filepath}")
                    count += 1
                else:
                    try:
                        result = subprocess.run([self.sa_learn, '--ham', filepath],
                                              capture_output=True, timeout=30, text=True)
                        if result.returncode == 0:
                            count += 1
                            sender, ip = self.extract_sender(filepath)
                            self.database.log_learning(email_hash, 'ham', sender, '')
                            self.database.update_sender_stats(sender, ip, False)
                        else:
                            errors += 1
                            if errors <= 3:
                                self.logger.warning(f"sa-learn failed: {result.stderr[:100]}")
                    except subprocess.TimeoutExpired:
                        self.logger.error(f"Timeout learning {os.path.basename(filepath)}")
                        errors += 1
                    except Exception as e:
                        errors += 1
                        if errors <= 3:
                            self.logger.error(f"Failed to learn: {e}")
        
        if total_files > 50:
            print()  # Clear progress line
        
        if errors > 3:
            self.logger.warning(f"Total errors in {folder}: {errors}")
        
        return count
    
    def run_learning_cycle(self):
        self.logger.info("Starting learning cycle")
        maildir = self.config.get('general', 'maildir_base', '/var/vmail')
        learn_ham = self.config.get('general', 'learn_ham', True)
        
        if not os.path.exists(maildir):
            self.logger.error(f"Maildir base does not exist: {maildir}")
            return {'spam_learned': 0, 'ham_learned': 0}
        
        spam_count = 0
        ham_count = 0
        spam_folders = []
        ham_folders = []
        trash_folders = []
        
        print("🔍 Discovering mailboxes...")
        
        # First pass: discover all folders
        for root, dirs, files in os.walk(maildir):
            if root.endswith('/cur'):
                if '.Spam' in root or '.Junk' in root:
                    spam_folders.append(root)
                elif '.Trash' in root:
                    trash_folders.append(root)
                elif not any(bad in root for bad in ['.Drafts', '.Templates']):
                    if '.INBOX' in root or '.Sent' in root:
                        ham_folders.append(root)
        
        self.logger.info(f"Found {len(spam_folders)} spam folders, {len(ham_folders)} ham folders, {len(trash_folders)} trash folders")
        
        # v3.1: NEW - Scan all folders for virus/phishing threats FIRST
        if self.config.get('threat_detection', 'enabled', True):
            self.scan_all_folders_for_threats(spam_folders + ham_folders + trash_folders)
        
        # Learn from spam folders
        if spam_folders:
            print(f"\n📧 Learning from {len(spam_folders)} spam folders...")
            for idx, folder in enumerate(spam_folders, 1):
                print(f"[{idx}/{len(spam_folders)}] Processing: {folder}")
                folder_spam = self.learn_spam(folder)
                if folder_spam > 0:
                    self.logger.info(f"Learned {folder_spam} spam from {folder}")
                spam_count += folder_spam
            
            print(f"✅ Learned {spam_count} spam emails total\n")
        
        # v3.0: NEW - Scan trash folders for recently deleted spam
        trash_spam_count = 0
        if trash_folders and self.config.get('learning', 'scan_trash', True):
            print(f"\n🗑️  Scanning {len(trash_folders)} trash folders for deleted spam...")
            max_age_days = self.config.get('learning', 'trash_max_age_days', 7)
            print(f"   (Learning from emails deleted within last {max_age_days} days)")
            
            for idx, folder in enumerate(trash_folders, 1):
                print(f"[{idx}/{len(trash_folders)}] Processing: {folder}")
                folder_spam = self.learn_spam_from_trash(folder, max_age_days)
                if folder_spam > 0:
                    self.logger.info(f"Learned {folder_spam} spam from trash: {folder}")
                trash_spam_count += folder_spam
            
            if trash_spam_count > 0:
                print(f"✅ Learned {trash_spam_count} spam from trash folders\n")
            else:
                print(f"✅ No recent spam found in trash folders\n")
        
        spam_count += trash_spam_count
        
        # v3.0: NEW LOGIC - Check ham folders for blacklisted senders, do NOT learn as ham
        # This makes SpamAssassin smarter by only learning from confirmed spam
        blocked_senders = 0
        if ham_folders:
            print(f"� Checking {len(ham_folders)} ham folders for blacklisted senders...")
            print(f"   (NOT learning as ham - only checking DNSBL and blocking repeat offenders)")
            for idx, folder in enumerate(ham_folders, 1):
                print(f"[{idx}/{len(ham_folders)}] Checking: {folder}")
                blocked = self.check_ham_folder_for_blacklisted(folder)
                if blocked > 0:
                    self.logger.info(f"Blocked {blocked} senders from {folder}")
                blocked_senders += blocked
            
            if blocked_senders > 0:
                print(f"🚫 Blocked {blocked_senders} senders with 5+ blacklisted emails\n")
            else:
                print(f"✅ No repeat offenders found in ham folders\n")
        
        self.database.update_daily_stats(spam=spam_count, ham=0, processed=len(spam_folders) + len(ham_folders) + len(trash_folders))
        
        self.logger.info(f"Learning complete: {spam_count} spam learned, {blocked_senders} senders blocked from {len(spam_folders) + len(ham_folders) + len(trash_folders)} folders")
        return {'spam_learned': spam_count, 'ham_learned': 0, 'senders_blocked': blocked_senders}


class SpamReporter:
    """Report spam to external services"""
    def __init__(self, config: Config, logger: Logger, database: Database):
        self.config = config
        self.logger = logger
        self.database = database
    
    def check_dnsbl(self, ip, sender=None):
        """
        Check if IP is on DNSBL blacklists
        v3.0: Returns True if listed on any DNSBL, False otherwise
        """
        if not dns or not ip:
            return False
        
        listed = []
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        # Extended DNSBL list (v3.0) - Load from config
        dnsbl_servers = self.config.get('reporting', 'dnsbl_servers', [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'b.barracudacentral.org',
            'psbl.surriel.com',
            'dnsbl-1.uceprotect.net',
            'bl.spameatingmonkey.net'
        ])
        
        for dnsbl in dnsbl_servers:
            try:
                query = f"{reversed_ip}.{dnsbl}"
                dns.resolver.resolve(query, 'A')
                listed.append(dnsbl)
                self.logger.debug(f"IP {ip} listed on {dnsbl}")
            except dns.resolver.NXDOMAIN:
                # Not listed - this is good
                pass
            except dns.resolver.NoNameservers:
                self.logger.warning(f"No nameservers available for {dnsbl}")
            except dns.resolver.Timeout:
                self.logger.warning(f"Timeout querying {dnsbl}")
            except Exception as e:
                self.logger.debug(f"Error checking {dnsbl}: {e}")
        
        # Return True if listed on any DNSBL
        return len(listed) > 0
    
    def process_repeat_offenders(self):
        threshold = self.config.get('reporting', 'threshold_count', 5)
        days = self.config.get('reporting', 'threshold_days', 7)
        
        offenders = self.database.get_repeat_offenders(threshold, days)
        reported = 0
        
        for offender in offenders:
            self.logger.info(f"Repeat offender: {offender['email']} ({offender['spam_count']} spam)")
            
            if self.config.get('reporting', 'enabled', True):
                # Mark as reported (actual reporting would go here)
                self.database.mark_sender_reported(offender['email'])
                reported += 1
        
        if reported > 0:
            self.database.update_daily_stats(reported=reported)
        
        return reported


class SelfMonitor:
    """Monitor own server IP and domains for blacklisting (v3.0)"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.server_ip = "167.235.12.13"
        self.vhosts_path = "/var/www/vhosts"
    
    def check_server_blacklist_status(self):
        """
        Check if server IP or domains are blacklisted on Spamhaus
        Returns dict with warnings if any issues found
        """
        warnings = []
        
        # Check server IP
        ip_status = self._check_ip_blacklist(self.server_ip)
        if ip_status:
            warnings.append(ip_status)
        
        # Check all domains in vhosts
        domains = self._discover_vhost_domains()
        for domain in domains:
            domain_status = self._check_domain_blacklist(domain)
            if domain_status:
                warnings.append(domain_status)
        
        return warnings
    
    def _check_ip_blacklist(self, ip):
        """Check IP against Spamhaus DNSBL"""
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            
            # Spamhaus ZEN (combines SBL, XBL, PBL)
            dnsbl_servers = [
                ('zen.spamhaus.org', 'Spamhaus ZEN (SBL+XBL+PBL)'),
                ('sbl.spamhaus.org', 'Spamhaus SBL (Spam Block List)'),
                ('xbl.spamhaus.org', 'Spamhaus XBL (Exploits Block List)'),
                ('pbl.spamhaus.org', 'Spamhaus PBL (Policy Block List)')
            ]
            
            listed_on = []
            for dnsbl, name in dnsbl_servers:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    result = dns.resolver.resolve(query, 'A')
                    response_code = str(result[0])
                    
                    # Decode Spamhaus response codes
                    # 127.255.255.254 = Query via public/open resolver (not actually listed)
                    # Skip this code - it's not a real listing
                    if response_code == '127.255.255.254':
                        self.logger.debug(f"IP {ip} query returned code {response_code} on {dnsbl} (open resolver query)")
                        continue
                    
                    listed_on.append({
                        'list': name,
                        'code': response_code,
                        'checked': datetime.now().isoformat()
                    })
                    self.logger.warning(f"⚠️ SERVER IP {ip} LISTED ON {name} (code: {response_code})")
                except dns.resolver.NXDOMAIN:
                    # Not listed - good!
                    pass
                except Exception as e:
                    self.logger.debug(f"Error checking {dnsbl}: {e}")
            
            if listed_on:
                return {
                    'type': 'ip',
                    'target': ip,
                    'listed_on': listed_on,
                    'severity': 'critical',
                    'message': f'🚨 SERVER IP {ip} IS BLACKLISTED',
                    'action': 'Check https://www.spamhaus.org/lookup/ and request delisting'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking IP blacklist: {e}")
            return None
    
    def _check_domain_blacklist(self, domain):
        """Check domain against Spamhaus DBL"""
        try:
            # Spamhaus DBL (Domain Block List)
            query = f"{domain}.dbl.spamhaus.org"
            
            try:
                result = dns.resolver.resolve(query, 'A')
                response_code = str(result[0])
                
                # Skip 127.255.255.254 (open resolver query indicator)
                if response_code == '127.255.255.254':
                    self.logger.debug(f"Domain {domain} query returned code {response_code} (open resolver query)")
                    return None
                
                # Decode response code
                reasons = {
                    '127.0.1.2': 'spam domain',
                    '127.0.1.4': 'phishing domain',
                    '127.0.1.5': 'malware domain',
                    '127.0.1.6': 'botnet C&C domain',
                    '127.0.1.102': 'abused legit spam',
                    '127.0.1.103': 'abused spammed redirector',
                    '127.0.1.104': 'abused legit phishing',
                    '127.0.1.105': 'abused legit malware',
                    '127.0.1.106': 'abused legit botnet C&C'
                }
                
                reason = reasons.get(response_code, f'unknown (code: {response_code})')
                
                self.logger.warning(f"⚠️ DOMAIN {domain} LISTED ON Spamhaus DBL: {reason}")
                
                return {
                    'type': 'domain',
                    'target': domain,
                    'listed_on': [{
                        'list': 'Spamhaus DBL (Domain Block List)',
                        'code': response_code,
                        'reason': reason,
                        'checked': datetime.now().isoformat()
                    }],
                    'severity': 'critical',
                    'message': f'🚨 DOMAIN {domain} IS BLACKLISTED',
                    'action': f'Check https://www.spamhaus.org/dbl/ - Reason: {reason}'
                }
                
            except dns.resolver.NXDOMAIN:
                # Not listed - good!
                return None
                
        except Exception as e:
            self.logger.debug(f"Error checking domain {domain}: {e}")
            return None
    
    def _discover_vhost_domains(self):
        """Discover all domains from /var/www/vhosts/*/conf/httpd.conf"""
        domains = []
        
        if not os.path.exists(self.vhosts_path):
            self.logger.warning(f"vhosts path not found: {self.vhosts_path}")
            return domains
        
        try:
            for vhost_dir in os.listdir(self.vhosts_path):
                vhost_path = os.path.join(self.vhosts_path, vhost_dir)
                
                if not os.path.isdir(vhost_path):
                    continue
                
                # Check if it looks like a domain name
                if '.' in vhost_dir and not vhost_dir.startswith('.'):
                    domains.append(vhost_dir)
            
            self.logger.info(f"Discovered {len(domains)} domains in {self.vhosts_path}")
            
        except Exception as e:
            self.logger.error(f"Error discovering vhost domains: {e}")
        
        return domains


class SpamhausReporter:
    """
    Spamhaus API Integration (v3.3)
    Reports spam to Spamhaus Threat Intel API with rate limiting
    """
    API_BASE = "https://submit.spamhaus.org/portal/api/v1"
    
    def __init__(self, config: Config, logger: Logger, database: Database):
        self.config = config
        self.logger = logger
        self.database = database
        self.api_key = config.get('reporting', 'spamhaus_api_key', '')
        self.enabled = config.get('reporting', 'spamhaus_enabled', False)
        
        # Rate limiting (NEW v3.3)
        self.rate_limit_hit = False
        self.rate_limit_until = 0
        self.submission_count = 0
        self.max_submissions_per_run = config.get('reporting', 'spamhaus_max_per_run', 50)
        self.retry_after_429 = config.get('reporting', 'spamhaus_retry_after_429', 3600)  # 1 hour
        
        # Queue system for rate-limited submissions (NEW v3.3.1)
        self.use_queue = config.get('reporting', 'spamhaus_use_queue', True)
        self.queue = None
        if self.use_queue:
            try:
                from spamhaus_queue import SpamhausQueue
                self.queue = SpamhausQueue()
                self.logger.info("Spamhaus queue system enabled")
            except ImportError:
                self.logger.warning("Could not import SpamhausQueue, queue disabled")
                self.use_queue = False
        
        if self.enabled and not self.api_key:
            self.logger.warning("Spamhaus reporting enabled but no API key configured")
            self.enabled = False
        
        # Cache threat types
        self.threat_types = None
        if self.enabled:
            self._load_threat_types()
    
    def _get_headers(self):
        """Get API request headers with authentication"""
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def _check_rate_limit(self) -> bool:
        """Check if we've hit rate limit (NEW v3.3)"""
        import time
        
        # Check if we're in cooldown period
        if self.rate_limit_hit and time.time() < self.rate_limit_until:
            remaining = int(self.rate_limit_until - time.time())
            self.logger.debug(f"Spamhaus rate limit active, {remaining}s remaining")
            return False
        
        # Reset if cooldown expired
        if self.rate_limit_hit and time.time() >= self.rate_limit_until:
            self.rate_limit_hit = False
            self.submission_count = 0
            self.logger.info("Spamhaus rate limit cooldown expired, resuming submissions")
        
        # Check submission count
        if self.submission_count >= self.max_submissions_per_run:
            self.logger.warning(f"Reached max submissions per run ({self.max_submissions_per_run}), pausing Spamhaus reporting")
            return False
        
        return True
    
    def _handle_429_response(self):
        """Handle 429 Too Many Requests (NEW v3.3)"""
        import time
        
        if not self.rate_limit_hit:
            self.rate_limit_hit = True
            self.rate_limit_until = time.time() + self.retry_after_429
            self.logger.warning(f"⚠️ Spamhaus rate limit hit (429), pausing for {self.retry_after_429}s ({self.retry_after_429//3600}h)")
            self.logger.info(f"Submitted {self.submission_count} items before rate limit")
            
            if self.use_queue and self.queue:
                self.logger.info("Future submissions will be queued for later processing")
    
    def _queue_submission(self, submission_type: str, payload: dict, 
                         threat_level: str = 'MEDIUM', email_path: str = None) -> bool:
        """
        Add submission to queue for later processing (NEW v3.3.1)
        Returns True if queued successfully
        """
        if not self.use_queue or not self.queue:
            return False
        
        try:
            queue_id = self.queue.add_submission(
                submission_type=submission_type,
                data=payload,
                threat_level=threat_level,
                email_path=email_path,
                reason=payload.get('reason', 'Spam detected')
            )
            self.logger.info(f"📥 Queued {submission_type} submission (queue ID: {queue_id})")
            return True
        except Exception as e:
            self.logger.error(f"Failed to queue submission: {e}")
            return False
    
    def _load_threat_types(self):
        """Load available threat types from Spamhaus API (#7)"""
        try:
            response = requests.get(
                f'{self.API_BASE}/lookup/threats-types',
                headers=self._get_headers(),
                timeout=10
            )
            if response.status_code == 200:
                self.threat_types = response.json()
                self.logger.info(f"Loaded {len(self.threat_types)} Spamhaus threat types")
            else:
                self.logger.warning(f"Failed to load threat types: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error loading Spamhaus threat types: {e}")
    
    def _classify_threat(self, email_content: str = None, subject: str = None) -> str:
        """
        Classify spam type based on content (#7)
        Returns appropriate threat_type code
        """
        if not email_content and not subject:
            return "source-of-spam"
        
        text = (subject or '') + ' ' + (email_content or '')
        text = text.lower()
        
        # Simple keyword-based classification
        if any(word in text for word in ['password', 'verify', 'account', 'suspended', 'click here', 'urgent']):
            return "phishing"
        elif any(word in text for word in ['malware', 'virus', 'infected', 'trojan']):
            return "malware"
        elif any(word in text for word in ['bitcoin', 'crypto', 'investment', 'forex', 'lottery']):
            return "fraud"
        else:
            return "source-of-spam"
    
    def submit_ip(self, ip: str, reason: str = "Spam source detected by automated system") -> Optional[Dict]:
        """
        Submit spam IP to Spamhaus (#2)
        Returns submission result or None
        """
        if not self.enabled or not ip:
            return None
        
        # Check rate limit first
        if not self._check_rate_limit():
            # If rate limited, queue for later
            if self.use_queue and self.queue:
                payload = {
                    "threat_type": "source-of-spam",
                    "reason": reason[:255],
                    "source": {"object": ip}
                }
                self._queue_submission('ip', payload, threat_level='MEDIUM')
            return None
        
        try:
            payload = {
                "threat_type": "source-of-spam",
                "reason": reason[:255],  # Max 255 chars
                "source": {
                    "object": ip
                }
            }
            
            response = requests.post(
                f'{self.API_BASE}/submissions/add/ip',
                headers=self._get_headers(),
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                self.submission_count += 1
                self.logger.info(f"✅ Submitted IP {ip} to Spamhaus (ID: {result.get('id', 'unknown')})")
                return result
            elif response.status_code == 208:
                self.logger.debug(f"IP {ip} already reported to Spamhaus")
                return {"status": 208, "message": "already reported"}
            elif response.status_code == 429:
                self._handle_429_response()
                # Queue this submission
                if self.use_queue and self.queue:
                    self._queue_submission('ip', payload, threat_level='MEDIUM')
                return None
            else:
                self.logger.warning(f"Failed to submit IP {ip}: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error submitting IP to Spamhaus: {e}")
            return None
    
    def submit_domain(self, domain: str, reason: str = "Spam domain detected") -> Optional[Dict]:
        """
        Submit spam domain to Spamhaus (#3)
        Returns submission result or None
        """
        if not self.enabled or not domain:
            return None
        
        # Check rate limit first
        if not self._check_rate_limit():
            if self.use_queue and self.queue:
                payload = {
                    "threat_type": "source-of-spam",
                    "reason": reason[:255],
                    "source": {"object": domain}
                }
                self._queue_submission('domain', payload, threat_level='HIGH')
            return None
        
        try:
            payload = {
                "threat_type": "source-of-spam",
                "reason": reason[:255],
                "source": {
                    "object": domain
                }
            }
            
            response = requests.post(
                f'{self.API_BASE}/submissions/add/domain',
                headers=self._get_headers(),
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                self.submission_count += 1
                self.logger.info(f"✅ Submitted domain {domain} to Spamhaus (ID: {result.get('id', 'unknown')})")
                return result
            elif response.status_code == 208:
                self.logger.debug(f"Domain {domain} already reported")
                return {"status": 208, "message": "already reported"}
            elif response.status_code == 429:
                self._handle_429_response()
                if self.use_queue and self.queue:
                    self._queue_submission('domain', payload, threat_level='HIGH')
                return None
            else:
                self.logger.warning(f"Failed to submit domain: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error submitting domain to Spamhaus: {e}")
            return None
    
    def submit_url(self, url: str, reason: str = "Malicious URL detected") -> Optional[Dict]:
        """
        Submit malicious URL to Spamhaus (#4)
        Returns submission result or None
        """
        if not self.enabled or not url:
            return None
        
        # Check rate limit first
        if not self._check_rate_limit():
            if self.use_queue and self.queue:
                payload = {
                    "threat_type": "phishing",
                    "reason": reason[:255],
                    "source": {"object": url}
                }
                self._queue_submission('url', payload, threat_level='HIGH')
            return None
        
        try:
            payload = {
                "threat_type": "phishing",  # URLs are typically phishing
                "reason": reason[:255],
                "source": {
                    "object": url
                }
            }
            
            response = requests.post(
                f'{self.API_BASE}/submissions/add/url',
                headers=self._get_headers(),
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                self.submission_count += 1
                self.logger.info(f"✅ Submitted URL to Spamhaus (ID: {result.get('id', 'unknown')})")
                return result
            elif response.status_code == 208:
                return {"status": 208, "message": "already reported"}
            elif response.status_code == 429:
                self._handle_429_response()
                if self.use_queue and self.queue:
                    self._queue_submission('url', payload, threat_level='HIGH')
                return None
            else:
                self.logger.warning(f"Failed to submit URL: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error submitting URL to Spamhaus: {e}")
            return None
    
    def submit_raw_email(self, email_path: str, threat_type: str = None) -> Optional[Dict]:
        """
        Submit RAW email to Spamhaus (#1 - Most Powerful)
        Reads email file and sends complete content
        Returns submission result or None
        """
        if not self.enabled or not os.path.exists(email_path):
            return None
        
        # Check rate limit first - but prepare payload for potential queueing
        try:
            # Read raw email (max 150KB as per Spamhaus limit)
            with open(email_path, 'rb') as f:
                raw_content = f.read(150 * 1024)  # Read max 150KB
            
            # Decode to string
            try:
                raw_email_str = raw_content.decode('utf-8', errors='ignore')
            except:
                raw_email_str = raw_content.decode('latin-1', errors='ignore')
            
            # Parse for classification if not provided
            if not threat_type:
                # Quick parse to get subject for classification
                try:
                    msg = BytesParser(policy=policy.default).parsebytes(raw_content)
                    subject = msg.get('Subject', '')
                    threat_type = self._classify_threat(subject=subject)
                except:
                    threat_type = "source-of-spam"
            
            payload = {
                "threat_type": threat_type,
                "reason": "Spam email detected by SpamTrainer v3.0 automated system",
                "source": {
                    "object": raw_email_str
                }
            }
            
            # Check rate limit - if hit, queue and return
            if not self._check_rate_limit():
                if self.use_queue and self.queue:
                    self._queue_submission('email', payload, threat_level='CRITICAL', email_path=email_path)
                return None
            
            response = requests.post(
                f'{self.API_BASE}/submissions/add/email',
                headers=self._get_headers(),
                json=payload,
                timeout=60  # Longer timeout for email uploads
            )
            
            if response.status_code == 200:
                result = response.json()
                self.submission_count += 1
                self.logger.info(f"✅ Submitted RAW email to Spamhaus (ID: {result.get('id', 'unknown')})")
                return result
            elif response.status_code == 208:
                self.logger.debug(f"Email already reported to Spamhaus")
                return {"status": 208, "message": "already reported"}
            elif response.status_code == 429:
                self._handle_429_response()
                if self.use_queue and self.queue:
                    self._queue_submission('email', payload, threat_level='CRITICAL', email_path=email_path)
                return None
            else:
                self.logger.warning(f"Failed to submit email: {response.status_code} - {response.text[:200]}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error submitting email to Spamhaus: {e}")
            return None
    
    def extract_urls_from_email(self, email_path: str) -> List[str]:
        """
        Extract all URLs from email for URL submission (#4)
        Returns list of URLs found
        """
        urls = []
        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            # Get email body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_content()
            else:
                body = msg.get_content()
            
            # Extract URLs with regex
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            found_urls = re.findall(url_pattern, body)
            urls.extend(found_urls)
            
        except Exception as e:
            self.logger.debug(f"Error extracting URLs: {e}")
        
        return list(set(urls))  # Unique URLs only
    
    def get_submission_stats(self) -> Optional[Dict]:
        """
        Get submission statistics from Spamhaus (#6)
        Returns {"total": X, "matched": Y} or None
        """
        if not self.enabled:
            return None
        
        try:
            response = requests.get(
                f'{self.API_BASE}/submissions/count',
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                stats = response.json()
                self.logger.info(f"Spamhaus stats: {stats['total']} total, {stats['matched']} matched")
                return stats
            else:
                self.logger.warning(f"Failed to get Spamhaus stats: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting Spamhaus stats: {e}")
            return None
    
    def get_submission_list(self, items: int = 100, page: int = 1) -> Optional[List[Dict]]:
        """
        Get list of recent submissions (#5 - Feedback Loop)
        Returns list of submissions or None
        """
        if not self.enabled:
            return None
        
        try:
            response = requests.get(
                f'{self.API_BASE}/submissions/list?items={items}&page={page}',
                headers=self._get_headers(),
                timeout=15
            )
            
            if response.status_code == 200:
                submissions = response.json()
                self.logger.info(f"Retrieved {len(submissions)} Spamhaus submissions")
                return submissions
            else:
                self.logger.warning(f"Failed to get submission list: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting submission list: {e}")
            return None


class VirusScanner:
    """ClamAV virus scanner integration"""
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get('threat_detection', 'clamav_enabled', True)
        
        if self.enabled:
            try:
                import pyclamd
                self.clam = pyclamd.ClamdUnixSocket('/var/run/clamav/clamd.ctl')
                # Test connection
                if not self.clam.ping():
                    self.logger.warning("ClamAV daemon not responding, virus scanning disabled")
                    self.enabled = False
            except ImportError:
                self.logger.warning("pyclamd not installed, virus scanning disabled")
                self.enabled = False
            except Exception as e:
                self.logger.warning(f"ClamAV initialization failed: {e}, virus scanning disabled")
                self.enabled = False
    
    def scan_email(self, email_path: str) -> Dict:
        """Scan email for viruses"""
        if not self.enabled:
            return {'infected': False}
        
        try:
            result = self.clam.scan_file(email_path)
            
            if result and email_path in result:
                status, virus_name = result[email_path]
                if status == 'FOUND':
                    threat_level = self._classify_threat(virus_name)
                    self.logger.warning(f"⚠️  Virus detected: {virus_name} in {email_path}")
                    return {
                        'infected': True,
                        'virus_name': virus_name,
                        'threat_level': threat_level,
                        'threat_type': 'virus'
                    }
            
            return {'infected': False}
        
        except Exception as e:
            self.logger.error(f"Error scanning {email_path}: {e}")
            return {'infected': False}
    
    def _classify_threat(self, virus_name: str) -> str:
        """Classify threat level based on virus name"""
        virus_lower = virus_name.lower()
        
        if 'trojan' in virus_lower or 'backdoor' in virus_lower:
            return 'CRITICAL'
        elif 'phishing' in virus_lower or 'phish' in virus_lower:
            return 'HIGH'
        elif 'malware' in virus_lower or 'ransom' in virus_lower:
            return 'HIGH'
        elif 'suspicious' in virus_lower:
            return 'MEDIUM'
        else:
            return 'MEDIUM'


class PhishingDetector:
    """Advanced phishing detection"""
    
    # Phishing keywords with weights
    PHISHING_KEYWORDS = {
        'urgent': 25, 'verify': 30, 'suspend': 35, 'confirm': 25,
        'update': 20, 'click here': 30, 'account': 15, 'password': 30,
        'security': 20, 'expir': 30, 'unusual activity': 40,
        'locked': 35, 'reactivate': 30, 'validate': 30,
        'billing': 20, 'payment': 20, 'invoice': 15,
        'reset': 25, 'immediately': 30, 'action required': 35
    }
    
    # URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
        'is.gd', 'buff.ly', 'adf.ly', 'shorte.st'
    ]
    
    def __init__(self, config: Config, logger: Logger, db_manager: 'ThreatDatabaseManager' = None):
        self.config = config
        self.logger = logger
        self.enabled = config.get('threat_detection', 'phishing_enabled', True)
        self.threshold = config.get('threat_detection', 'phishing_threshold', 70)  # Get from config
        self.db_manager = db_manager  # External threat databases
    
    def analyze_email(self, email_path: str) -> Dict:
        """Comprehensive phishing analysis"""
        if not self.enabled:
            return {'phishing': False, 'score': 0}
        
        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            subject = msg.get('Subject', '')
            sender = msg.get('From', '')
            body = self._extract_body(msg)
            
            # Initialize scores
            total_score = 0
            indicators = []
            
            # 1. Keyword analysis
            keyword_score, found_keywords = self._analyze_keywords(subject, body)
            total_score += keyword_score
            if found_keywords:
                indicators.append(f"suspicious-keywords: {', '.join(found_keywords[:3])}")
            
            # 2. URL analysis
            url_score, url_issues = self._analyze_urls(body)
            total_score += url_score
            indicators.extend(url_issues)
            
            # 3. Sender analysis
            sender_score, sender_issues = self._analyze_sender(sender, msg)
            total_score += sender_score
            indicators.extend(sender_issues)
            
            # 4. Urgency detection
            urgency_score = self._detect_urgency(subject, body)
            total_score += urgency_score
            
            # Determine threat level
            is_phishing = total_score >= self.threshold  # Use configurable threshold
            threat_level = self._score_to_threat_level(total_score)
            
            if is_phishing:
                self.logger.warning(f"🎣 Phishing detected (score: {total_score}): {subject}")
            
            return {
                'phishing': is_phishing,
                'score': total_score,
                'threat_level': threat_level,
                'threat_type': 'phishing',
                'indicators': indicators,
                'subject': subject,
                'sender': sender
            }
        
        except Exception as e:
            self.logger.error(f"Error analyzing {email_path}: {e}")
            return {'phishing': False, 'score': 0}
    
    def _extract_body(self, msg) -> str:
        """Extract email body text"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    try:
                        body += part.get_content()
                    except:
                        pass
                elif part.get_content_type() == 'text/html':
                    try:
                        html_content = part.get_content()
                        # Simple HTML stripping (basic)
                        body += re.sub(r'<[^>]+>', '', html_content)
                    except:
                        pass
        else:
            try:
                body = msg.get_content()
            except:
                pass
        return body[:10000]  # Limit to 10KB
    
    def _analyze_keywords(self, subject: str, body: str) -> Tuple[int, List[str]]:
        """Analyze phishing keywords"""
        text = (subject + ' ' + body).lower()
        score = 0
        found = []
        
        for keyword, weight in self.PHISHING_KEYWORDS.items():
            if keyword in text:
                score += weight
                found.append(keyword)
        
        return score, found
    
    def _analyze_urls(self, body: str) -> Tuple[int, List[str]]:
        """Analyze URLs in email with external database checking"""
        score = 0
        issues = []
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\')]+|www\.[^\s<>"\')]+'
        urls = re.findall(url_pattern, body, re.IGNORECASE)
        
        # Check external threat databases first (if enabled)
        if self.db_manager and urls:
            try:
                db_results = self.db_manager.check_urls(urls[:20])  # Max 20 URLs
                for url, result in db_results.items():
                    if result.get('is_threat'):
                        threat_score = result.get('threat_score', 0)
                        score += threat_score
                        databases = ', '.join(result.get('databases', []))
                        issues.append(f"external-db-threat:{databases}")
                        self.logger.warning(f"🚨 External DB detected threat: {url}")
            except Exception as e:
                self.logger.error(f"Error checking URLs with external databases: {e}")
        
        # Local pattern matching
        for url in urls[:20]:  # Check max 20 URLs
            url_lower = url.lower()
            
            # URL shorteners
            if any(shortener in url_lower for shortener in self.URL_SHORTENERS):
                score += 30
                issues.append("url-shortener")
            
            # IP address in URL
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 60
                issues.append("ip-address-url")
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            if any(url_lower.endswith(tld) for tld in suspicious_tlds):
                score += 40
                issues.append("suspicious-tld")
        
        return score, list(set(issues))  # Remove duplicates
    
    def _analyze_sender(self, sender: str, msg) -> Tuple[int, List[str]]:
        """Analyze sender authenticity"""
        score = 0
        issues = []
        
        # Check for display name spoofing
        if '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip()
            email_addr = sender.split('<')[1].split('>')[0].strip()
            
            # Common spoofed names
            suspicious_names = ['paypal', 'bank', 'amazon', 'microsoft', 'apple', 
                              'google', 'facebook', 'ebay', 'netflix']
            
            display_lower = display_name.lower()
            email_lower = email_addr.lower()
            
            for name in suspicious_names:
                if name in display_lower and name not in email_lower:
                    score += 50
                    issues.append(f"display-name-spoof:{name}")
                    break
        
        return score, issues
    
    def _detect_urgency(self, subject: str, body: str) -> int:
        """Detect urgency/pressure tactics"""
        text = (subject + ' ' + body).lower()
        
        # Whitelist legitimate urgency contexts
        legitimate_contexts = [
            'renewal', 'subscription', 'license', 'invoice', 
            'receipt', 'order confirmation', 'payment received',
            'days left until', 'expires in'  # Normal expiration notices
        ]
        
        # If it's a legitimate notice, reduce urgency scoring
        is_legitimate = any(context in text for context in legitimate_contexts)
        
        urgency_phrases = [
            'act now', 'urgent action required', 'immediate action required',
            'within 24 hours', 'account suspended', 'limited time offer',
            'hurry', 'last chance', 'verify immediately', 'confirm now',
            'click here now', 'respond immediately'
        ]
        
        score = 0
        matches = 0
        for phrase in urgency_phrases:
            if phrase in text:
                matches += 1
                score += 10 if is_legitimate else 15  # Lower score for legitimate
        
        # Cap based on context
        max_score = 30 if is_legitimate else 60
        return min(score, max_score)
    
    def _score_to_threat_level(self, score: int) -> str:
        """Convert score to threat level"""
        if score >= 100:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'


class ThreatHandler:
    """Handle detected threats with subject prepending, X-headers, body injection, and quarantine"""
    def __init__(self, config: Config, logger: Logger, database: Database):
        self.config = config
        self.logger = logger
        self.database = database
        self.enabled = config.get('threat_detection', 'enabled', True)
        
        # Warning prefixes from config
        self.prefixes = {
            'virus': config.get('warning', 'prefix_virus', '[⚠️ VIRUS]'),
            'phishing': config.get('warning', 'prefix_phishing', '[🚨 PHISHING]'),
            'malware': config.get('warning', 'prefix_malware', '[⚠️ MALWARE]'),
            'suspicious': config.get('warning', 'prefix_suspicious', '[⚠️ MISTENKELIG]')
        }
        
        # New v3.3: Threat handling modes
        self.x_headers_enabled = config.get('threat_handling', 'x_headers_enabled', True)
        self.body_injection_enabled = config.get('threat_handling', 'body_injection_enabled', False)
        self.quarantine_enabled = config.get('threat_handling', 'quarantine_enabled', False)
        self.notification_enabled = config.get('threat_handling', 'notification_enabled', False)
        self.notification_smtp_host = config.get('threat_handling', 'notification_smtp_host', 'localhost')
        self.notification_smtp_port = config.get('threat_handling', 'notification_smtp_port', 25)
        self.notification_from = config.get('threat_handling', 'notification_from', 'security@smartesider.no')
    
    def handle_threat(self, email_path: str, virus_result: Dict, phishing_result: Dict) -> bool:
        """Process threat detection results with multiple handling methods"""
        if not self.enabled:
            return False
        
        # Determine if action needed
        threat_detected = virus_result.get('infected', False) or phishing_result.get('phishing', False)
        
        if not threat_detected:
            return False
        
        # Determine threat type and level
        if virus_result.get('infected'):
            threat_type = virus_result.get('threat_type', 'virus')
            threat_level = virus_result.get('threat_level', 'MEDIUM')
            threat_name = virus_result.get('virus_name', 'Unknown')
            threat_details = f"Virus: {threat_name}"
            threat_score = 100 if threat_level == 'CRITICAL' else 85
        else:
            threat_type = phishing_result.get('threat_type', 'phishing')
            threat_level = phishing_result.get('threat_level', 'MEDIUM')
            threat_name = f"Phishing (score: {phishing_result.get('score', 0)})"
            threat_details = f"Phishing indicators: {', '.join(phishing_result.get('indicators', [])[:3])}"
            threat_score = phishing_result.get('score', 70)
        
        actions_taken = []
        
        # 1. Add X-Headers (Løsning 1)
        if self.x_headers_enabled:
            if self._add_x_headers(email_path, threat_type, threat_name, threat_level, threat_score, virus_result, phishing_result):
                actions_taken.append('x_headers')
        
        # 2. Prepend subject (existing functionality)
        if self._prepend_subject(email_path, threat_type, threat_name):
            actions_taken.append('subject_prepend')
        
        # 3. Inject warning in body (Løsning 4)
        if self.body_injection_enabled:
            if self._inject_warning_banner(email_path, threat_type, threat_name, threat_details, threat_level):
                actions_taken.append('body_injection')
        
        # 4. Move to quarantine (Løsning 5)
        quarantined = False
        if self.quarantine_enabled and threat_score >= 80:  # Only quarantine high-risk threats
            if self._quarantine_email(email_path, threat_type, threat_name):
                actions_taken.append('quarantine')
                quarantined = True
        
        # 5. Send notification email (Løsning 5)
        if self.notification_enabled and (quarantined or threat_score >= 70):
            recipient = self._extract_recipient_from_path(email_path)
            if self._send_threat_notification(recipient, email_path, threat_type, threat_name, threat_details, threat_level, quarantined):
                actions_taken.append('notification')
        
        if actions_taken:
            # Log to database
            self._log_threat(email_path, threat_type, threat_level, threat_name, threat_details, ', '.join(actions_taken))
            self.logger.info(f"✅ Threat handled: {os.path.basename(email_path)} - Actions: {', '.join(actions_taken)}")
            return True
        
        return False
    
    def _prepend_subject(self, email_path: str, threat_type: str, threat_name: str) -> bool:
        """Add warning to email subject"""
        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            original_subject = msg.get('Subject', 'No Subject')
            
            # Choose prefix
            prefix = self.prefixes.get(threat_type, self.prefixes['suspicious'])
            
            # Check if already tagged
            if prefix in original_subject:
                self.logger.debug(f"Subject already tagged: {original_subject}")
                return False
            
            # Create new subject
            new_subject = f"{prefix} {original_subject}"
            
            # Replace header
            if 'Subject' in msg:
                msg.replace_header('Subject', new_subject)
            else:
                msg['Subject'] = new_subject
            
            # Write back to file
            with open(email_path, 'wb') as f:
                f.write(msg.as_bytes())
            
            self.logger.info(f"Subject tagged: {original_subject} -> {new_subject}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error prepending subject for {email_path}: {e}")
            return False
    
    def _add_x_headers(self, email_path: str, threat_type: str, threat_name: str, 
                       threat_level: str, threat_score: int, virus_result: Dict, 
                       phishing_result: Dict) -> bool:
        """Add X-Headers with threat information (Løsning 1)"""
        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            # Add threat headers
            msg['X-Threat-Scanned'] = 'spam_trainer v3.3'
            msg['X-Threat-Detection-Date'] = datetime.now().isoformat()
            
            if virus_result.get('infected'):
                msg['X-Virus-Scanned'] = 'clamav'
                msg['X-Virus-Status'] = 'INFECTED'
                msg['X-Virus-Name'] = virus_result.get('virus_name', 'Unknown')
                msg['X-Virus-Threat-Level'] = threat_level
            else:
                msg['X-Virus-Status'] = 'CLEAN'
            
            if phishing_result.get('phishing'):
                msg['X-Phishing-Score'] = str(phishing_result.get('score', 0))
                msg['X-Phishing-Status'] = 'DETECTED'
                indicators = phishing_result.get('indicators', [])
                if indicators:
                    msg['X-Phishing-Indicators'] = ', '.join(indicators[:5])
            else:
                msg['X-Phishing-Status'] = 'CLEAN'
            
            msg['X-Threat-Score'] = str(threat_score)
            msg['X-Threat-Type'] = threat_type
            msg['X-Threat-Level'] = threat_level
            
            # Write back
            with open(email_path, 'wb') as f:
                f.write(msg.as_bytes())
            
            self.logger.debug(f"X-Headers added to {os.path.basename(email_path)}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error adding X-headers: {e}")
            return False
    
    def _inject_warning_banner(self, email_path: str, threat_type: str, threat_name: str, 
                               threat_details: str, threat_level: str) -> bool:
        """Inject HTML warning banner in email body (Løsning 4)"""
        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            # Find HTML part
            html_part = None
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    html_part = part
                    break
            
            if not html_part:
                self.logger.debug(f"No HTML part found in {os.path.basename(email_path)}")
                return False
            
            html_content = html_part.get_content()
            
            # Check if banner already injected
            if '<!-- THREAT-BANNER-INJECTED -->' in html_content:
                return False
            
            # Create warning banner
            banner_color = '#dc3545' if threat_level in ['CRITICAL', 'HIGH'] else '#ff9800'
            emoji = '🚨' if threat_level in ['CRITICAL', 'HIGH'] else '⚠️'
            
            banner_html = f'''
<!-- THREAT-BANNER-INJECTED -->
<div style="background:{banner_color};color:white;padding:20px;margin:20px 0;
            border:5px solid #bd2130;font-family:Arial,sans-serif;border-radius:10px;">
    <h1 style="margin:0;font-size:24px;">{emoji} ADVARSEL: FARLIG E-POST</h1>
    <p style="font-size:18px;margin:10px 0;">
        Denne e-posten inneholder trusler og kan være farlig!
    </p>
    <ul style="font-size:16px;margin:10px 0;">
        <li><strong>IKKE</strong> klikk på lenker</li>
        <li><strong>IKKE</strong> åpne vedlegg</li>
        <li><strong>SLETT</strong> denne e-posten umiddelbart</li>
    </ul>
    <p style="font-size:14px;margin-top:15px;background:rgba(0,0,0,0.2);padding:10px;border-radius:5px;">
        <strong>Type:</strong> {threat_type.upper()}<br>
        <strong>Trussel:</strong> {threat_name}<br>
        <strong>Nivå:</strong> {threat_level}<br>
        <strong>Detektert:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </p>
    <p style="font-size:12px;margin-top:15px;opacity:0.8;">
        Beskyttet av SmarteSider Sikkerhetssystem - spam_trainer.py v3.3
    </p>
</div>
'''
            
            # Inject after <body> tag
            if '<body' in html_content:
                # Find end of <body> tag
                import re
                body_match = re.search(r'<body[^>]*>', html_content, re.IGNORECASE)
                if body_match:
                    insert_pos = body_match.end()
                    modified_html = html_content[:insert_pos] + banner_html + html_content[insert_pos:]
                else:
                    modified_html = banner_html + html_content
            else:
                # No body tag, prepend
                modified_html = banner_html + html_content
            
            html_part.set_content(modified_html)
            
            # Write back
            with open(email_path, 'wb') as f:
                f.write(msg.as_bytes())
            
            self.logger.info(f"Warning banner injected in {os.path.basename(email_path)}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error injecting warning banner: {e}")
            return False
    
    def _quarantine_email(self, email_path: str, threat_type: str, threat_name: str) -> bool:
        """Move email to .Quarantine folder (Løsning 5)"""
        try:
            # Determine maildir base path
            # Path format: /path/to/Maildir/cur/filename or /path/to/Maildir/.Folder/cur/filename
            path_parts = email_path.split('/')
            
            # Find Maildir base
            maildir_base = None
            for i, part in enumerate(path_parts):
                if part == 'Maildir':
                    maildir_base = '/'.join(path_parts[:i+1])
                    break
            
            if not maildir_base:
                self.logger.error(f"Could not determine Maildir base for {email_path}")
                return False
            
            # Create .Quarantine folder
            quarantine_path = os.path.join(maildir_base, '.Quarantine')
            quarantine_cur = os.path.join(quarantine_path, 'cur')
            quarantine_new = os.path.join(quarantine_path, 'new')
            quarantine_tmp = os.path.join(quarantine_path, 'tmp')
            
            os.makedirs(quarantine_cur, exist_ok=True)
            os.makedirs(quarantine_new, exist_ok=True)
            os.makedirs(quarantine_tmp, exist_ok=True)
            
            # Move file
            import shutil
            filename = os.path.basename(email_path)
            dest_path = os.path.join(quarantine_cur, filename)
            
            # Add quarantine info to filename (before the colon)
            if ':' in filename:
                base, flags = filename.rsplit(':', 1)
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                new_filename = f"{base}.QUARANTINE-{timestamp}:{flags}"
            else:
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                new_filename = f"{filename}.QUARANTINE-{timestamp}"
            
            dest_path = os.path.join(quarantine_cur, new_filename)
            
            shutil.move(email_path, dest_path)
            
            self.logger.info(f"Email quarantined: {filename} -> .Quarantine/{new_filename}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error quarantining email: {e}")
            return False
    
    def _send_threat_notification(self, recipient: str, email_path: str, threat_type: str,
                                   threat_name: str, threat_details: str, threat_level: str,
                                   quarantined: bool) -> bool:
        """Send notification email about threat (Løsning 5)"""
        try:
            # Extract original email info
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            original_sender = msg.get('From', 'Unknown')
            original_subject = msg.get('Subject', 'No Subject')
            original_date = msg.get('Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # Calculate email size
            file_size = os.path.getsize(email_path)
            file_size_kb = file_size / 1024
            
            # Count attachments
            attachments = []
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    attachments.append(part.get_filename() or 'unknown')
            
            # Build notification email
            notification = MIMEMultipart('alternative')
            notification['Subject'] = f"🚨 SIKKERHETSVARSEL: Farlig e-post {'i karantene' if quarantined else 'mottatt'}"
            notification['From'] = self.notification_from
            notification['To'] = recipient
            notification['Priority'] = 'urgent'
            notification['X-Priority'] = '1'
            
            # Plain text version
            text_content = f"""
KRITISK SIKKERHETSADVARSEL

{'En farlig e-post er automatisk flyttet til karantene.' if quarantined else 'En farlig e-post er mottatt i din inbox.'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📧 E-POST DETALJER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Fra: {original_sender}
Emne: {original_subject}
Mottatt: {original_date}
Størrelse: {file_size_kb:.1f} KB
Vedlegg: {len(attachments)} ({',' .join(attachments[:3]) if attachments else 'ingen'})

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ TRUSSEL OPPDAGET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Type: {threat_type.upper()}
Trussel: {threat_name}
Alvorlighetsgrad: {threat_level}
Detaljer: {threat_details}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ HVA DU MÅ GJØRE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. IKKE KLIKK på lenker i e-posten
2. IKKE ÅPNE vedlegg
3. SLETT e-posten umiddelbart
4. Rapporter til IT-avdeling hvis usikker

{'E-posten finnes i mappen ".Quarantine" i mailklienten din.' if quarantined else ''}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dette er en automatisk melding fra SmarteSider Sikkerhetssystem.
Ved spørsmål, kontakt support@smartesider.no

Powered by spam_trainer.py v3.3
"""
            
            # HTML version
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 20px auto; background: #f8f9fa; padding: 20px; border-radius: 10px; }}
        .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ background: white; padding: 20px; border-radius: 0 0 10px 10px; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-left: 5px solid #007bff; }}
        .threat-box {{ background: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin: 20px 0; }}
        .actions {{ background: #d1ecf1; border-left: 5px solid #17a2b8; padding: 15px; margin: 20px 0; }}
        .footer {{ text-align: center; font-size: 12px; color: #6c757d; margin-top: 20px; }}
        ul {{ margin: 10px 0; padding-left: 20px; }}
        li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 SIKKERHETSADVARSEL</h1>
            <p>{'Farlig e-post i karantene' if quarantined else 'Farlig e-post mottatt'}</p>
        </div>
        <div class="content">
            <p><strong>{'En farlig e-post er automatisk flyttet til karantene.' if quarantined else 'En farlig e-post er mottatt i din inbox.'}</strong></p>
            
            <div class="section">
                <h3>📧 E-post Detaljer</h3>
                <p>
                    <strong>Fra:</strong> {original_sender}<br>
                    <strong>Emne:</strong> {original_subject}<br>
                    <strong>Mottatt:</strong> {original_date}<br>
                    <strong>Størrelse:</strong> {file_size_kb:.1f} KB<br>
                    <strong>Vedlegg:</strong> {len(attachments)} {'(' + ', '.join(attachments[:3]) + ')' if attachments else '(ingen)'}
                </p>
            </div>
            
            <div class="threat-box">
                <h3>⚠️ Trussel Oppdaget</h3>
                <p>
                    <strong>Type:</strong> {threat_type.upper()}<br>
                    <strong>Trussel:</strong> {threat_name}<br>
                    <strong>Alvorlighetsgrad:</strong> {threat_level}<br>
                    <strong>Detaljer:</strong> {threat_details}
                </p>
            </div>
            
            <div class="actions">
                <h3>🛡️ Hva Du Må Gjøre</h3>
                <ul>
                    <li><strong>IKKE KLIKK</strong> på lenker i e-posten</li>
                    <li><strong>IKKE ÅPNE</strong> vedlegg</li>
                    <li><strong>SLETT</strong> e-posten umiddelbart</li>
                    <li>Rapporter til IT-avdeling hvis usikker</li>
                </ul>
                {'<p><em>E-posten finnes i mappen ".Quarantine" i mailklienten din.</em></p>' if quarantined else ''}
            </div>
            
            <div class="footer">
                <p>Dette er en automatisk melding fra SmarteSider Sikkerhetssystem.</p>
                <p>Ved spørsmål, kontakt support@smartesider.no</p>
                <p>Powered by spam_trainer.py v3.3</p>
            </div>
        </div>
    </div>
</body>
</html>
"""
            
            notification.attach(MIMEText(text_content, 'plain', 'utf-8'))
            notification.attach(MIMEText(html_content, 'html', 'utf-8'))
            
            # Send via SMTP
            smtp = smtplib.SMTP(self.notification_smtp_host, self.notification_smtp_port)
            smtp.send_message(notification)
            smtp.quit()
            
            self.logger.info(f"Threat notification sent to {recipient}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")
            return False
    
    def _log_threat(self, email_path: str, threat_type: str, threat_level: str, 
                    threat_name: str, threat_details: str, actions_taken: str = 'subject_prepend'):
        """Log threat to database"""
        try:
            # Extract email info
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            recipient = self._extract_recipient_from_path(email_path)
            sender = msg.get('From', 'unknown')
            subject = msg.get('Subject', 'No Subject')
            
            conn = sqlite3.connect(self.database.db_path)
            c = conn.cursor()
            
            c.execute('''INSERT INTO threat_detections 
                        (timestamp, recipient, sender, subject, threat_type, 
                         threat_name, threat_level, threat_details, action_taken)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (datetime.now().isoformat(), recipient, sender, subject,
                      threat_type, threat_name, threat_level, threat_details,
                      actions_taken))
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            self.logger.error(f"Error logging threat: {e}")
    
    def _extract_recipient_from_path(self, email_path: str) -> str:
        """Extract recipient email from maildir path"""
        # Path format: /var/qmail/mailnames/domain.com/user/Maildir/...
        parts = email_path.split('/')
        try:
            # Find domain and user
            if 'mailnames' in parts:
                idx = parts.index('mailnames')
                domain = parts[idx + 1]
                user = parts[idx + 2]
                return f"{user}@{domain}"
        except:
            pass
        return "unknown"


class GoogleSafeBrowsing:
    """Google Safe Browsing API v4 integration"""
    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    def __init__(self, api_key: str, logger: Logger):
        self.api_key = api_key
        self.logger = logger
        self.enabled = bool(api_key)
        self.cache = {}  # Simple in-memory cache
        self.cache_ttl = 86400  # 24 hours
    
    def check_urls(self, urls: List[str]) -> Dict[str, Dict]:
        """Check URLs against Google Safe Browsing
        Returns: {url: {'threat': bool, 'type': str, 'platform': str}}
        """
        if not self.enabled or not urls:
            return {}
        
        results = {}
        uncached_urls = []
        
        # Check cache first
        now = time.time()
        for url in urls:
            if url in self.cache:
                cached_time, cached_result = self.cache[url]
                if now - cached_time < self.cache_ttl:
                    results[url] = cached_result
                else:
                    uncached_urls.append(url)
            else:
                uncached_urls.append(url)
        
        if not uncached_urls:
            return results
        
        try:
            # Build request
            request_data = {
                "client": {
                    "clientId": "spam_trainer",
                    "clientVersion": "3.1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in uncached_urls[:500]]  # Max 500 per request
                }
            }
            
            response = requests.post(
                f"{self.API_URL}?key={self.api_key}",
                json=request_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                # Process matches
                for match in matches:
                    url = match['threat']['url']
                    result = {
                        'threat': True,
                        'type': match['threatType'],
                        'platform': match['platformType']
                    }
                    results[url] = result
                    self.cache[url] = (now, result)
                    self.logger.warning(f"🚨 Google Safe Browsing: {url} - {match['threatType']}")
                
                # Cache clean results
                for url in uncached_urls:
                    if url not in results:
                        result = {'threat': False}
                        results[url] = result
                        self.cache[url] = (now, result)
                
                self.logger.info(f"Google Safe Browsing: {len(matches)} threats in {len(uncached_urls)} URLs")
            
            elif response.status_code == 429:
                self.logger.warning("Google Safe Browsing rate limit exceeded")
            else:
                self.logger.error(f"Google Safe Browsing API error: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error checking Google Safe Browsing: {e}")
        
        return results


class PhishTank:
    """PhishTank API integration - works with or without API key!"""
    API_URL = "http://checkurl.phishtank.com/checkurl/"
    DATA_URL_WITH_KEY = "http://data.phishtank.com/data/{api_key}/online-valid.json"
    DATA_URL_PUBLIC = "http://data.phishtank.com/data/online-valid.json.bz2"  # Public feed (no auth!)
    
    def __init__(self, api_key: str, logger: Logger, cache_file: str = "/tmp/phishtank_cache.json"):
        self.api_key = api_key
        self.logger = logger
        self.enabled = True  # Always enabled! Can use public feed
        self.use_public_feed = not bool(api_key)  # Use public if no key
        self.cache_file = cache_file
        self.cache = {}
        self.last_update = 0
        self.update_interval = 21600  # 6 hours
        
        if self.use_public_feed:
            self.logger.info("PhishTank: Using PUBLIC feed (no API key)")
        
        self._load_cache()
    
    def _load_cache(self):
        """Load cached phishing database"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.cache = {entry['url']: entry for entry in data}
                    self.last_update = os.path.getmtime(self.cache_file)
                self.logger.info(f"PhishTank cache loaded: {len(self.cache)} entries")
        except Exception as e:
            self.logger.error(f"Error loading PhishTank cache: {e}")
    
    def _update_cache(self):
        """Download latest PhishTank database (API key OR public feed)"""
        now = time.time()
        
        # Check if cache is still valid
        if now - self.last_update < self.update_interval:
            return  # Cache still valid, don't update
        
        # If we have cached data, use it and update in background later
        if len(self.cache) > 0:
            # Cache exists but is old - set last_update to prevent spam retries
            self.last_update = now - self.update_interval + 3600  # Retry in 1 hour
        
        try:
            if self.use_public_feed:
                # PUBLIC FEED: No authentication needed!
                import bz2
                self.logger.info("Downloading PhishTank public feed (bz2)...")
                response = requests.get(self.DATA_URL_PUBLIC, timeout=60)
                
                if response.status_code == 200:
                    # Decompress bz2
                    decompressed = bz2.decompress(response.content)
                    data = json.loads(decompressed.decode('utf-8'))
                    
                    with open(self.cache_file, 'w') as f:
                        json.dump(data, f)
                    
                    self.cache = {entry['url']: entry for entry in data}
                    self.last_update = now
                    self.logger.info(f"✅ PhishTank PUBLIC feed updated: {len(data)} entries")
                elif response.status_code == 429:
                    # Rate limited - use existing cache and retry much later
                    self.logger.warning(f"PhishTank rate limited (429) - using cache, will retry in 6 hours")
                    self.last_update = now  # Don't retry immediately!
                else:
                    self.logger.warning(f"PhishTank public feed download failed: {response.status_code}")
                    self.last_update = now - self.update_interval + 1800  # Retry in 30 min
            else:
                # WITH API KEY
                url = self.DATA_URL_WITH_KEY.format(api_key=self.api_key)
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    with open(self.cache_file, 'w') as f:
                        json.dump(data, f)
                    
                    self.cache = {entry['url']: entry for entry in data}
                    self.last_update = now
                    self.logger.info(f"✅ PhishTank API updated: {len(data)} entries")
                else:
                    self.logger.warning(f"PhishTank API update failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error updating PhishTank: {e}")
    
    def check_urls(self, urls: List[str]) -> Dict[str, Dict]:
        """Check URLs against PhishTank
        Returns: {url: {'threat': bool, 'verified': bool, 'details': str}}
        """
        if not self.enabled or not urls:
            return {}
        
        # Update cache if needed
        self._update_cache()
        
        results = {}
        for url in urls:
            # Normalize URL
            normalized = url.lower().strip()
            
            if normalized in self.cache:
                entry = self.cache[normalized]
                results[url] = {
                    'threat': True,
                    'verified': entry.get('verified') == 'yes',
                    'details': entry.get('details', '')
                }
                self.logger.warning(f"🎣 PhishTank: {url} is phishing!")
            else:
                results[url] = {'threat': False}
        
        return results


class URLhaus:
    """URLhaus (abuse.ch) API integration"""
    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
    FEED_URL = "https://urlhaus.abuse.ch/downloads/json/"
    
    def __init__(self, logger: Logger, cache_file: str = "/tmp/urlhaus_cache.json"):
        self.logger = logger
        self.enabled = True  # No API key required
        self.cache_file = cache_file
        self.cache = {}
        self.last_update = 0
        self.update_interval = 3600  # 1 hour
        self._load_cache()
    
    def _load_cache(self):
        """Load cached URLhaus database"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    # Handle both list and dict formats
                    if isinstance(data, list):
                        self.cache = {entry['url']: entry for entry in data if isinstance(entry, dict) and 'url' in entry}
                    else:
                        self.cache = {}
                    self.last_update = os.path.getmtime(self.cache_file)
                self.logger.info(f"URLhaus cache loaded: {len(self.cache)} entries")
        except Exception as e:
            self.logger.error(f"Error loading URLhaus cache: {e}")
            self.cache = {}
    
    def _update_cache(self):
        """Download latest URLhaus feed (newline-delimited JSON format)"""
        now = time.time()
        if now - self.last_update < self.update_interval:
            return
        
        try:
            self.logger.info("Downloading URLhaus feed...")
            response = requests.get(self.FEED_URL, timeout=60)
            
            if response.status_code == 200:
                # URLhaus uses newline-delimited JSON (not standard JSON array)
                lines = response.text.strip().split('\n')
                data = []
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip comments
                        try:
                            entry = json.loads(line)
                            data.append(entry)
                        except json.JSONDecodeError:
                            continue  # Skip invalid lines
                
                if data:
                    with open(self.cache_file, 'w') as f:
                        json.dump(data, f)
                    
                    self.cache = {entry['url']: entry for entry in data if 'url' in entry}
                    self.last_update = now
                    self.logger.info(f"✅ URLhaus database updated: {len(self.cache)} entries")
                else:
                    self.logger.warning("URLhaus feed returned no valid entries")
            else:
                self.logger.warning(f"URLhaus update failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error updating URLhaus: {e}")
    
    def check_urls(self, urls: List[str]) -> Dict[str, Dict]:
        """Check URLs against URLhaus
        Returns: {url: {'threat': bool, 'malware': str, 'status': str}}
        """
        if not self.enabled or not urls:
            return {}
        
        # Update cache if needed
        self._update_cache()
        
        results = {}
        for url in urls:
            # Normalize URL
            normalized = url.lower().strip()
            
            if normalized in self.cache:
                entry = self.cache[normalized]
                results[url] = {
                    'threat': True,
                    'malware': entry.get('threat', 'malware'),
                    'status': entry.get('url_status', 'online')
                }
                self.logger.warning(f"🦠 URLhaus: {url} contains malware!")
            else:
                results[url] = {'threat': False}
        
        return results


class ThreatDatabaseManager:
    """Manages all external threat databases with parallel checking"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get('threat_databases', 'enabled', False)
        
        # Initialize databases
        self.google_sb = None
        self.phishtank = None
        self.urlhaus = None
        
        if self.enabled:
            # Get threat_databases config section
            threat_dbs = config.config.get('threat_databases', {})
            
            # Google Safe Browsing
            gsb_config = threat_dbs.get('google_safe_browsing', {})
            if gsb_config.get('enabled', False):
                api_key = gsb_config.get('api_key', '')
                if api_key:
                    self.google_sb = GoogleSafeBrowsing(api_key, logger)
                    logger.info("✅ Google Safe Browsing enabled")
            
            # PhishTank
            pt_config = threat_dbs.get('phishtank', {})
            if pt_config.get('enabled', False):
                api_key = pt_config.get('api_key', '')
                # PhishTank works with empty api_key (public feed)
                self.phishtank = PhishTank(api_key, logger)
                logger.info("✅ PhishTank enabled")
            
            # URLhaus
            uh_config = threat_dbs.get('urlhaus', {})
            if uh_config.get('enabled', False):
                self.urlhaus = URLhaus(logger)
                logger.info("✅ URLhaus enabled")
    
    def check_urls(self, urls: List[str]) -> Dict[str, Dict]:
        """Check URLs against all enabled databases
        Returns: {url: {'databases': [results], 'threat_score': int, 'is_threat': bool}}
        """
        if not self.enabled or not urls:
            return {}
        
        combined_results = {url: {'databases': [], 'threat_score': 0, 'is_threat': False} for url in urls}
        
        # Check Google Safe Browsing
        if self.google_sb:
            try:
                gsb_results = self.google_sb.check_urls(urls)
                for url, result in gsb_results.items():
                    if result.get('threat'):
                        combined_results[url]['databases'].append(f"Google:{result['type']}")
                        combined_results[url]['threat_score'] += 30  # High weight
            except Exception as e:
                self.logger.error(f"Google Safe Browsing check failed: {e}")
        
        # Check PhishTank
        if self.phishtank:
            try:
                pt_results = self.phishtank.check_urls(urls)
                for url, result in pt_results.items():
                    if result.get('threat'):
                        verified = "verified" if result.get('verified') else "unverified"
                        combined_results[url]['databases'].append(f"PhishTank:{verified}")
                        combined_results[url]['threat_score'] += 25  # High weight
            except Exception as e:
                self.logger.error(f"PhishTank check failed: {e}")
        
        # Check URLhaus
        if self.urlhaus:
            try:
                uh_results = self.urlhaus.check_urls(urls)
                for url, result in uh_results.items():
                    if result.get('threat'):
                        combined_results[url]['databases'].append(f"URLhaus:{result['malware']}")
                        combined_results[url]['threat_score'] += 20  # Medium-high weight
            except Exception as e:
                self.logger.error(f"URLhaus check failed: {e}")
        
        # Determine final threat status
        for url in urls:
            score = combined_results[url]['threat_score']
            combined_results[url]['is_threat'] = score >= 20  # Threshold
            
            if combined_results[url]['is_threat']:
                databases = ', '.join(combined_results[url]['databases'])
                self.logger.warning(f"🚨 URL threat detected: {url} (score: {score}, sources: {databases})")
        
        return combined_results


class StatisticsReporter:
    """Generate reports"""
    def __init__(self, config: Config, logger: Logger, database: Database):
        self.config = config
        self.logger = logger
        self.database = database
    
    def generate_report(self, days=7):
        stats = self.database.get_statistics(days)
        
        report = f"""
SpamAssassin Learning System Report
Period: Last {days} days
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== Statistics ===
Spam Learned: {stats['spam_learned']}
Ham Learned: {stats['ham_learned']}
Emails Processed: {stats['emails_processed']}
Senders Reported: {stats['senders_reported']}
IPs Blocked: {stats['ips_blocked']}
"""
        return report
    
    def generate_html_report(self, days=7):
        """Generate stunning HTML email report (v3.0)"""
        self.logger.info(f"Generating HTML report for last {days} days")
        
        # v3.0: Check own server for blacklisting
        self_monitor = SelfMonitor(self.config, self.logger)
        blacklist_warnings = self_monitor.check_server_blacklist_status()
        
        # Collect all statistics
        stats = self.database.get_statistics(days)
        conn = self.database.get_connection()
        c = conn.cursor()
        
        # Daily statistics for charts
        cutoff = (datetime.now() - timedelta(days=days)).date().isoformat()
        c.execute('''
            SELECT date, spam_learned, ham_learned, emails_processed
            FROM daily_stats 
            WHERE date >= ? 
            ORDER BY date ASC
        ''', (cutoff,))
        daily_data = c.fetchall()
        
        # Top spam senders
        c.execute('''
            SELECT sender_email, spam_count, last_seen, reported
            FROM sender_tracking 
            WHERE spam_count > 0
            ORDER BY spam_count DESC 
            LIMIT 10
        ''', ())
        top_spammers = c.fetchall()
        
        # Detection methods effectiveness
        c.execute('''
            SELECT 
                SUM(CASE WHEN reported = 1 THEN 1 ELSE 0 END) as dnsbl_detections,
                COUNT(*) as total_senders
            FROM sender_tracking
            WHERE spam_count > 0
        ''', ())
        detection_stats = c.fetchone()
        
        # Recent learning activity
        c.execute('''
            SELECT message_type, COUNT(*) as count
            FROM learning_history
            WHERE timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY message_type
        ''', (days,))
        learning_breakdown = dict(c.fetchall())
        
        conn.close()
        
        # v3.0: Get Spamhaus submission statistics (#6)
        spamhaus_stats = None
        spamhaus_submissions = []
        try:
            from spam_trainer import SpamhausReporter
            spamhaus = SpamhausReporter(self.config, self.logger, self.database)
            if spamhaus.enabled:
                spamhaus_stats = spamhaus.get_submission_stats()
                spamhaus_submissions = spamhaus.get_submission_list(items=10) or []
        except Exception as e:
            self.logger.debug(f"Could not fetch Spamhaus stats: {e}")
        
        # Generate charts
        charts = {}
        
        # Chart 1: Spam Trend (line chart)
        if daily_data:
            fig, ax = plt.subplots(figsize=(10, 4))
            dates = [datetime.fromisoformat(row[0]) for row in daily_data]
            spam_counts = [row[1] for row in daily_data]
            
            ax.plot(dates, spam_counts, color='#8b5cf6', linewidth=2, marker='o')
            ax.fill_between(dates, spam_counts, alpha=0.3, color='#8b5cf6')
            ax.set_xlabel('Date')
            ax.set_ylabel('Spam Emails Learned')
            ax.set_title('Spam Detection Trend')
            ax.grid(True, alpha=0.3)
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
            buf.seek(0)
            charts['spam_trend'] = buf.getvalue()
            plt.close()
        
        # Chart 2: Spam vs Ham (pie chart)
        if learning_breakdown:
            fig, ax = plt.subplots(figsize=(6, 6))
            spam_count = learning_breakdown.get('spam', 0)
            ham_count = learning_breakdown.get('ham', 0)
            
            if spam_count + ham_count > 0:
                colors = ['#ef4444', '#10b981']
                ax.pie([spam_count, ham_count], labels=['Spam', 'Ham'], 
                       autopct='%1.1f%%', colors=colors, startangle=90)
                ax.set_title('Spam vs Ham Distribution')
                
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
                buf.seek(0)
                charts['spam_vs_ham'] = buf.getvalue()
                plt.close()
        
        # Chart 3: Top Senders (bar chart)
        if top_spammers and len(top_spammers) > 0:
            fig, ax = plt.subplots(figsize=(10, 5))
            senders = [row[0][:30] + '...' if len(row[0]) > 30 else row[0] for row in top_spammers[:8]]
            counts = [row[1] for row in top_spammers[:8]]
            
            bars = ax.barh(senders, counts, color='#8b5cf6')
            ax.set_xlabel('Spam Count')
            ax.set_title('Top Spam Senders')
            ax.invert_yaxis()
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
            buf.seek(0)
            charts['top_senders'] = buf.getvalue()
            plt.close()
        
        # Load HTML template
        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'email_report_v3.html')
        if not os.path.exists(template_path):
            self.logger.error(f"HTML template not found: {template_path}")
            return None
        
        with open(template_path, 'r') as f:
            template_content = f.read()
        
        template = Template(template_content)
        
        # Calculate additional metrics
        total_learned = stats['spam_learned'] + stats['ham_learned']
        spam_percentage = (stats['spam_learned'] / total_learned * 100) if total_learned > 0 else 0
        dnsbl_effectiveness = (detection_stats[0] / detection_stats[1] * 100) if detection_stats[1] > 0 else 0
        
        # Pattern analysis - extract domains from top spammers
        spam_domains = Counter()
        for email, _, _, _ in top_spammers:
            if '@' in email:
                domain = email.split('@')[1]
                spam_domains[domain] += 1
        
        # Recommendations based on data
        recommendations = []
        if spam_percentage > 50:
            recommendations.append("⚠️ High spam rate detected. Consider enabling honeypot addresses.")
        if dnsbl_effectiveness < 30:
            recommendations.append("💡 DNSBL effectiveness is low. Review DNSBL server configuration.")
        if stats['spam_learned'] > stats['ham_learned'] * 3:
            recommendations.append("⚠️ Imbalanced learning detected. Increase ham training samples.")
        if not recommendations:
            recommendations.append("✅ System is operating optimally.")
        
        # Render HTML
        html_content = template.render(
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            period_days=days,
            blacklist_warnings=blacklist_warnings,  # NEW v3.0: Self-monitoring
            stats=stats,
            total_learned=total_learned,
            spam_percentage=spam_percentage,
            top_spammers=top_spammers,
            spam_domains=spam_domains.most_common(5),
            dnsbl_effectiveness=dnsbl_effectiveness,
            recommendations=recommendations,
            has_spam_trend='spam_trend' in charts,
            has_spam_vs_ham='spam_vs_ham' in charts,
            has_top_senders='top_senders' in charts,
            spamhaus_stats=spamhaus_stats,  # NEW v3.0
            spamhaus_submissions=spamhaus_submissions[:5]  # Top 5 submissions
        )
        
        return html_content, charts
    
    def send_html_report(self, days=7):
        """Send HTML report via email (v3.0)"""
        report_to = self.config.get('reporting', 'html_report_to')
        if not report_to:
            self.logger.error("html_report_to not configured")
            return False
        
        self.logger.info(f"Sending HTML report to {report_to}")
        
        result = self.generate_html_report(days)
        if not result:
            return False
        
        html_content, charts = result
        
        # Create multipart message
        msg = MIMEMultipart('related')
        msg['Subject'] = f'SpamAssassin Report - {datetime.now().strftime("%Y-%m-%d")}'
        msg['From'] = self.config.get('reporting', 'email_from', 'spamtrainer@localhost')
        msg['To'] = report_to
        
        # Attach HTML
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # Attach charts as inline images
        for chart_name, chart_data in charts.items():
            img = MIMEImage(chart_data)
            img.add_header('Content-ID', f'<{chart_name}>')
            img.add_header('Content-Disposition', 'inline', filename=f'{chart_name}.png')
            msg.attach(img)
        
        # Send email
        try:
            smtp_host = self.config.get('reporting', 'smtp_host', 'localhost')
            smtp_port = self.config.get('reporting', 'smtp_port', 25)
            
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.send_message(msg)
            
            self.logger.info(f"HTML report sent successfully to {report_to}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send HTML report: {e}")
            return False
    
    def export_to_json(self, output_path, days=30):
        stats = self.database.get_statistics(days)
        with open(output_path, 'w') as f:
            json.dump({
                'generated': datetime.now().isoformat(),
                'period_days': days,
                'statistics': stats
            }, f, indent=2)
        self.logger.info(f"Exported to {output_path}")
    
    def export_to_csv(self, output_path, days=30):
        conn = self.database.get_connection()
        c = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).date().isoformat()
        c.execute('SELECT * FROM daily_stats WHERE date >= ? ORDER BY date DESC', (cutoff,))
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['date', 'spam_learned', 'ham_learned', 'emails_processed', 
                           'senders_reported', 'ips_blocked'])
            writer.writerows(c.fetchall())
        
        conn.close()
        self.logger.info(f"Exported to {output_path}")


class SpamTrainerApp:
    """Main application"""
    def __init__(self, config_path=None):
        self.config = Config(config_path)
        self.logger = Logger(self.config)
        self.database = Database(self.config, self.logger)
        
        # v3.2.1: Scan tracker for incremental scanning
        self.scan_tracker = ScanTracker(self.database.db_path, self.logger)
        
        # v3.1: Threat databases (initialize first)
        self.threat_db_manager = ThreatDatabaseManager(self.config, self.logger)
        
        # v3.1: Threat detection
        self.virus_scanner = VirusScanner(self.config, self.logger)
        self.phishing_detector = PhishingDetector(self.config, self.logger, self.threat_db_manager)
        self.threat_handler = ThreatHandler(self.config, self.logger, self.database)
        
        self.spamhaus = SpamhausReporter(self.config, self.logger, self.database)  # Init first
        self.learner = SpamAssassinLearner(self.config, self.logger, self.database, self.spamhaus)  # Pass spamhaus
        
        # v3.1: Connect threat scanners to learner
        self.learner.set_threat_scanners(self.virus_scanner, self.phishing_detector, 
                                        self.threat_handler, self.threat_db_manager)
        
        # v3.2.1: Connect scan tracker to learner
        self.learner.set_scan_tracker(self.scan_tracker)
        
        self.reporter = SpamReporter(self.config, self.logger, self.database)
        self.stats = StatisticsReporter(self.config, self.logger, self.database)


    
    def show_status(self):
        """Display system status and configuration"""
        print("\n" + "="*70)
        print("SYSTEM STATUS")
        print("="*70)
        
        # Configuration
        print("\n📋 Configuration:")
        config_path = self.config.config_path
        print(f"   Config file: {config_path}")
        print(f"   Config exists: {'✓' if os.path.exists(config_path) else '✗'}")
        
        maildir = self.config.get('general', 'maildir_base', '/var/vmail')
        print(f"\n📁 Mail Directory:")
        print(f"   Path: {maildir}")
        print(f"   Exists: {'✓' if os.path.exists(maildir) else '✗ NOT FOUND'}")
        if os.path.exists(maildir):
            try:
                size = sum(os.path.getsize(os.path.join(dirpath, f))
                          for dirpath, dirnames, filenames in os.walk(maildir)
                          for f in filenames) / (1024**3)
                print(f"   Size: {size:.2f} GB")
            except:
                print(f"   Size: Unable to calculate")
        
        # Scan for mailboxes
        print(f"\n📬 Mailboxes Detected:")
        if os.path.exists(maildir):
            spam_folders = []
            ham_folders = []
            for root, dirs, files in os.walk(maildir):
                if root.endswith('/cur'):
                    if '.Spam' in root or '.Junk' in root:
                        spam_count = len([f for f in os.listdir(root) if os.path.isfile(os.path.join(root, f))])
                        spam_folders.append((root, spam_count))
                    elif not any(bad in root for bad in ['.Trash', '.Drafts', '.Templates']):
                        if '.INBOX' in root or '.Sent' in root:
                            ham_count = len([f for f in os.listdir(root) if os.path.isfile(os.path.join(root, f))])
                            ham_folders.append((root, ham_count))
            
            print(f"   Spam folders: {len(spam_folders)}")
            total_spam = sum(count for _, count in spam_folders)
            print(f"   Total spam emails: {total_spam}")
            print(f"   Ham folders: {len(ham_folders)}")
            total_ham = sum(count for _, count in ham_folders)
            print(f"   Total ham emails: {total_ham}")
            
            if spam_folders:
                print(f"\n   Top spam folders:")
                for folder, count in sorted(spam_folders, key=lambda x: x[1], reverse=True)[:5]:
                    print(f"      {count:5d} emails - {folder}")
        else:
            print(f"   ✗ Cannot scan - maildir not found")
        
        # Database stats
        print(f"\n💾 Database:")
        db_path = self.config.get('general', 'database_path', '/var/lib/spamtrainer/stats.db')
        print(f"   Path: {db_path}")
        print(f"   Exists: {'✓' if os.path.exists(db_path) else '✗ (will be created)'}")
        
        if os.path.exists(db_path):
            try:
                conn = self.database.get_connection()
                c = conn.cursor()
                
                # Total learning history
                c.execute('SELECT COUNT(*), MAX(learned_at) FROM learning_history')
                count, last = c.fetchone()
                print(f"   Total learned: {count}")
                print(f"   Last learning: {last or 'Never'}")
                
                # Recent stats
                stats = self.database.get_statistics(7)
                print(f"\n📊 Last 7 Days:")
                print(f"   Spam learned: {stats['spam_learned']}")
                print(f"   Ham learned: {stats['ham_learned']}")
                print(f"   Emails processed: {stats['emails_processed']}")
                print(f"   Senders reported: {stats['senders_reported']}")
                
                conn.close()
            except Exception as e:
                print(f"   Error reading database: {e}")
        
        # SpamAssassin
        print(f"\n🛡️  SpamAssassin:")
        sa_learn = self.config.get('general', 'sa_learn_bin', '/usr/bin/sa-learn')
        print(f"   sa-learn: {sa_learn}")
        print(f"   Exists: {'✓' if os.path.exists(sa_learn) else '✗ NOT FOUND'}")
        
        if os.path.exists(sa_learn):
            try:
                result = subprocess.run([sa_learn, '--version'], capture_output=True, text=True, timeout=5)
                version = result.stdout.strip().split('\n')[0] if result.returncode == 0 else 'Unknown'
                print(f"   Version: {version}")
            except:
                print(f"   Version: Unable to detect")
        
        # Settings
        print(f"\n⚙️  Settings:")
        print(f"   Dry run: {self.config.get('general', 'dry_run', False)}")
        print(f"   Learn ham: {self.config.get('general', 'learn_ham', True)}")
        print(f"   Max ham per folder: {self.config.get('general', 'max_ham_per_folder', 100)}")
        print(f"   Reporting enabled: {self.config.get('reporting', 'enabled', True)}")
        
        print("\n" + "="*70 + "\n")
    
    def show_scan_stats(self):
        """Display scan tracking statistics (v3.2.1)"""
        print("\n" + "="*70)
        print("📊 SCAN TRACKING STATISTICS")
        print("="*70)
        
        try:
            stats = self.scan_tracker.get_statistics()
            
            print(f"\n📧 Total Emails Tracked: {stats['total_emails_tracked']:,}")
            print(f"\n⚠️  Threats Found:")
            print(f"   Viruses: {stats['total_viruses_found']}")
            print(f"   Phishing: {stats['total_phishing_found']}")
            
            print(f"\n📈 Recent Scans (last 10 average):")
            print(f"   New per scan: {stats['avg_new_per_scan']:.1f} emails")
            print(f"   Skipped per scan: {stats['avg_skipped_per_scan']:.1f} emails")
            print(f"   Scan time: {stats['avg_scan_time_seconds']:.1f} seconds")
            
            if stats['avg_new_per_scan'] > 0 and stats['avg_skipped_per_scan'] > 0:
                total_avg = stats['avg_new_per_scan'] + stats['avg_skipped_per_scan']
                skip_ratio = (stats['avg_skipped_per_scan'] / total_avg) * 100
                print(f"\n🚀 Efficiency: {skip_ratio:.1f}% of emails skipped (incremental scanning)")
                
                # Calculate theoretical speedup
                if stats['avg_new_per_scan'] > 0:
                    speedup = total_avg / stats['avg_new_per_scan']
                    print(f"   Speedup: {speedup:.1f}x faster than full scan")
            
            # Recent sessions
            conn = sqlite3.connect(self.database.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT start_time, new_emails_scanned, skipped_already_scanned, 
                       rescanned_modified, viruses_found, phishing_found, duration_seconds
                FROM scan_sessions 
                WHERE status = 'completed'
                ORDER BY start_time DESC 
                LIMIT 5
            ''')
            sessions = cursor.fetchall()
            conn.close()
            
            if sessions:
                print(f"\n📅 Recent Scan Sessions:")
                print(f"{'DATE':<20} {'NEW':<8} {'SKIPPED':<10} {'THREATS':<10} {'TIME'}")
                print("-" * 70)
                for session in sessions:
                    start_time, new, skipped, rescanned, viruses, phishing, duration = session
                    date_str = start_time[:16].replace('T', ' ')
                    threats = viruses + phishing
                    print(f"{date_str:<20} {new:<8} {skipped:<10} {threats:<10} {duration:.1f}s")
            
            print("\n" + "="*70)
        
        except Exception as e:
            print(f"\n❌ Error loading scan statistics: {e}")
            self.logger.error(f"Error in show_scan_stats: {e}")
    
    def list_mailboxes(self):
        """List all detected mailboxes with detailed information"""
        print("\n" + "="*70)
        print("MAILBOX DETECTION REPORT")
        print("="*70)
        
        maildir = self.config.get('general', 'maildir_base', '/var/vmail')
        
        if not os.path.exists(maildir):
            print(f"\n❌ Error: Maildir not found: {maildir}")
            return
        
        print(f"\n📁 Scanning: {maildir}\n")
        
        spam_folders = []
        ham_folders = []
        
        print("🔍 Discovering mailboxes (this may take a moment)...\n")
        
        for root, dirs, files in os.walk(maildir):
            if root.endswith('/cur'):
                try:
                    file_count = len([f for f in os.listdir(root) if os.path.isfile(os.path.join(root, f))])
                    
                    if '.Spam' in root or '.Junk' in root:
                        spam_folders.append((root, file_count))
                    elif not any(bad in root for bad in ['.Trash', '.Drafts', '.Templates']):
                        if '.INBOX' in root or '.Sent' in root:
                            ham_folders.append((root, file_count))
                except PermissionError:
                    continue
        
        # Sort by email count descending
        spam_folders.sort(key=lambda x: x[1], reverse=True)
        ham_folders.sort(key=lambda x: x[1], reverse=True)
        
        # Display spam folders
        print("=" * 70)
        print("📧 SPAM FOLDERS")
        print("=" * 70)
        
        if spam_folders:
            total_spam = sum(count for _, count in spam_folders)
            print(f"\nFound {len(spam_folders)} spam folders with {total_spam} total emails\n")
            
            print(f"{'COUNT':<10} {'MAILBOX PATH'}")
            print("-" * 70)
            
            for folder, count in spam_folders:
                # Shorten path for display
                display_path = folder.replace(maildir, '~')
                if len(display_path) > 55:
                    display_path = '...' + display_path[-52:]
                print(f"{count:<10} {display_path}")
        else:
            print("\n⚠️  No spam folders detected")
        
        # Display ham folders
        print("\n" + "=" * 70)
        print("📬 HAM (LEGITIMATE) FOLDERS")
        print("=" * 70)
        
        if ham_folders:
            total_ham = sum(count for _, count in ham_folders)
            max_per = self.config.get('general', 'max_ham_per_folder', 100)
            print(f"\nFound {len(ham_folders)} ham folders with {total_ham} total emails")
            print(f"(Learning limited to {max_per} emails per folder)\n")
            
            print(f"{'COUNT':<10} {'WILL LEARN':<12} {'MAILBOX PATH'}")
            print("-" * 70)
            
            for folder, count in ham_folders:
                will_learn = min(count, max_per)
                display_path = folder.replace(maildir, '~')
                if len(display_path) > 45:
                    display_path = '...' + display_path[-42:]
                print(f"{count:<10} {will_learn:<12} {display_path}")
        else:
            print("\n⚠️  No ham folders detected")
        
        # Summary
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        
        total_spam = sum(count for _, count in spam_folders)
        total_ham = sum(count for _, count in ham_folders)
        max_per = self.config.get('general', 'max_ham_per_folder', 100)
        will_learn_ham = sum(min(count, max_per) for _, count in ham_folders)
        
        print(f"\n  Spam folders:  {len(spam_folders):<6}  ({total_spam} emails)")
        print(f"  Ham folders:   {len(ham_folders):<6}  ({total_ham} emails, will learn {will_learn_ham})")
        print(f"  Total folders: {len(spam_folders) + len(ham_folders)}")
        
        if spam_folders or ham_folders:
            print(f"\n  💡 Run './spam_trainer.py --dry-run --learn' to test learning")
            print(f"     Run './spam_trainer.py --learn' to start actual learning")
        
        print("\n" + "="*70 + "\n")
    
    def run_full_cycle(self):
        self.logger.info("=== Starting Full Cycle ===")
        stats = self.learner.run_learning_cycle()
        
        if self.config.get('reporting', 'enabled', True):
            reported = self.reporter.process_repeat_offenders()
            self.logger.info(f"Reported {reported} repeat offenders")
        
        self.logger.info("=== Cycle Complete ===")
        return stats
    
    def show_menu(self):
        while True:
            print("\n" + "="*60)
            print("Advanced SpamAssassin Learning System")
            print("="*60)
            print("1. Run learning cycle")
            print("2. Show statistics (7 days)")
            print("3. Show statistics (30 days)")
            print("4. Export to JSON")
            print("5. Export to CSV")
            print("6. Process repeat offenders")
            print("7. Generate report")
            print("0. Exit")
            print("="*60)
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.run_full_cycle()
            elif choice == '2':
                print(self.stats.generate_report(7))
            elif choice == '3':
                print(self.stats.generate_report(30))
            elif choice == '4':
                path = input("Output path [stats.json]: ") or "stats.json"
                self.stats.export_to_json(path, 30)
            elif choice == '5':
                path = input("Output path [stats.csv]: ") or "stats.csv"
                self.stats.export_to_csv(path, 30)
            elif choice == '6':
                reported = self.reporter.process_repeat_offenders()
                print(f"\nReported {reported} offenders")
            elif choice == '7':
                print(self.stats.generate_report(7))
            elif choice == '0':
                print("Exiting...")
                break
            else:
                print("Invalid option")
            
            input("\nPress Enter to continue...")


def main():
    parser = argparse.ArgumentParser(description='Advanced SpamAssassin Learning System')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--cron', action='store_true', help='Cron mode (quiet)')
    parser.add_argument('--learn', action='store_true', help='Run learning only')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--html-report', action='store_true', help='Generate and send HTML email report')
    parser.add_argument('--status', action='store_true', help='Show system status')
    parser.add_argument('--list-mailboxes', action='store_true', help='List all detected mailboxes')
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode')
    parser.add_argument('--force-rescan', action='store_true', help='Force re-scan all emails (v3.2.1)')
    parser.add_argument('--scan-stats', action='store_true', help='Show scan tracking statistics (v3.2.1)')
    
    args = parser.parse_args()
    
    try:
        app = SpamTrainerApp(args.config)
        
        if args.dry_run:
            app.config.config['general']['dry_run'] = True
            app.learner.dry_run = True
        
        if args.force_rescan:
            app.learner.force_rescan = True
        
        if args.cron:
            app.config.config['general']['quiet_mode'] = True
            app.run_full_cycle()
        elif args.status:
            app.show_status()
        elif args.list_mailboxes:
            app.list_mailboxes()
        elif args.scan_stats:
            app.show_scan_stats()
        elif args.learn:
            app.learner.run_learning_cycle()
        elif args.report:
            print(app.stats.generate_report())
        elif args.html_report:
            if app.stats.send_html_report():
                print("✅ HTML report sent successfully")
            else:
                print("❌ Failed to send HTML report")
        else:
            app.show_menu()
    
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
