#!/usr/bin/env python3
"""
Spamhaus Submission Queue System
Handles rate-limited submissions by queuing and processing in batches
"""

import sqlite3
import json
import time
import os
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path


class SpamhausQueue:
    """
    Queue system for Spamhaus submissions
    - Stores failed/rate-limited submissions
    - Processes queue in background with rate limiting
    - Prioritizes by age and threat level
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            script_dir = Path(__file__).parent
            db_path = script_dir / 'spamhaus_queue.db'
        
        self.db_path = str(db_path)
        self._init_database()
    
    def _init_database(self):
        """Create queue database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS submission_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_type TEXT NOT NULL,  -- 'ip', 'domain', 'url', 'email'
                submission_data TEXT NOT NULL,  -- JSON payload
                threat_level TEXT,              -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
                priority INTEGER DEFAULT 50,    -- 0-100, higher = more urgent
                created_at TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                last_attempt TEXT,
                status TEXT DEFAULT 'pending',  -- 'pending', 'processing', 'completed', 'failed'
                result TEXT,                    -- JSON result from API
                email_path TEXT,                -- Reference to original email
                reason TEXT                     -- Human-readable reason
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_queue_status 
            ON submission_queue(status, priority DESC, created_at ASC)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_queue_type 
            ON submission_queue(submission_type, status)
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS queue_stats (
                date TEXT PRIMARY KEY,
                queued INTEGER DEFAULT 0,
                processed INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0,
                rate_limited INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_submission(self, submission_type: str, data: Dict, 
                      threat_level: str = 'MEDIUM', email_path: str = None,
                      reason: str = None) -> int:
        """
        Add submission to queue
        Returns queue ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Calculate priority based on threat level
        priority_map = {
            'CRITICAL': 90,
            'HIGH': 70,
            'MEDIUM': 50,
            'LOW': 30
        }
        priority = priority_map.get(threat_level, 50)
        
        cursor.execute('''
            INSERT INTO submission_queue 
            (submission_type, submission_data, threat_level, priority, 
             created_at, email_path, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            submission_type,
            json.dumps(data),
            threat_level,
            priority,
            datetime.now().isoformat(),
            email_path,
            reason
        ))
        
        queue_id = cursor.lastrowid
        
        # Update stats
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('''
            INSERT INTO queue_stats (date, queued)
            VALUES (?, 1)
            ON CONFLICT(date) DO UPDATE SET queued = queued + 1
        ''', (today,))
        
        conn.commit()
        conn.close()
        
        return queue_id
    
    def get_pending_submissions(self, limit: int = 50, 
                               submission_type: str = None) -> List[Dict]:
        """
        Get pending submissions, ordered by priority
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = '''
            SELECT * FROM submission_queue
            WHERE status = 'pending'
        '''
        params = []
        
        if submission_type:
            query += ' AND submission_type = ?'
            params.append(submission_type)
        
        query += ' ORDER BY priority DESC, created_at ASC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def mark_processing(self, queue_id: int):
        """Mark submission as being processed"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE submission_queue
            SET status = 'processing', 
                attempts = attempts + 1,
                last_attempt = ?
            WHERE id = ?
        ''', (datetime.now().isoformat(), queue_id))
        
        conn.commit()
        conn.close()
    
    def mark_completed(self, queue_id: int, result: Dict = None):
        """Mark submission as completed"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE submission_queue
            SET status = 'completed',
                result = ?
            WHERE id = ?
        ''', (json.dumps(result) if result else None, queue_id))
        
        # Update stats
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('''
            INSERT INTO queue_stats (date, processed)
            VALUES (?, 1)
            ON CONFLICT(date) DO UPDATE SET processed = processed + 1
        ''', (today,))
        
        conn.commit()
        conn.close()
    
    def mark_failed(self, queue_id: int, error: str = None, retry: bool = True):
        """Mark submission as failed, optionally retry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get current attempts
        cursor.execute('SELECT attempts FROM submission_queue WHERE id = ?', (queue_id,))
        row = cursor.fetchone()
        attempts = row[0] if row else 0
        
        # Fail permanently after 5 attempts
        if attempts >= 5 or not retry:
            status = 'failed'
            cursor.execute('''
                INSERT INTO queue_stats (date, failed)
                VALUES (?, 1)
                ON CONFLICT(date) DO UPDATE SET failed = failed + 1
            ''', (datetime.now().strftime('%Y-%m-%d'),))
        else:
            status = 'pending'  # Retry later
        
        cursor.execute('''
            UPDATE submission_queue
            SET status = ?,
                result = ?
            WHERE id = ?
        ''', (status, json.dumps({'error': error}) if error else None, queue_id))
        
        conn.commit()
        conn.close()
    
    def mark_rate_limited(self, queue_id: int):
        """Mark submission as rate-limited, will retry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE submission_queue
            SET status = 'pending'
            WHERE id = ?
        ''', (queue_id,))
        
        # Update stats
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('''
            INSERT INTO queue_stats (date, rate_limited)
            VALUES (?, 1)
            ON CONFLICT(date) DO UPDATE SET rate_limited = rate_limited + 1
        ''', (today,))
        
        conn.commit()
        conn.close()
    
    def get_queue_stats(self) -> Dict:
        """Get current queue statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Overall counts
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) as processing,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM submission_queue
        ''')
        overall = cursor.fetchone()
        
        # By type
        cursor.execute('''
            SELECT submission_type, COUNT(*) as count
            FROM submission_queue
            WHERE status = 'pending'
            GROUP BY submission_type
        ''')
        by_type = dict(cursor.fetchall())
        
        # By threat level
        cursor.execute('''
            SELECT threat_level, COUNT(*) as count
            FROM submission_queue
            WHERE status = 'pending'
            GROUP BY threat_level
        ''')
        by_threat = dict(cursor.fetchall())
        
        # Today's stats
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('''
            SELECT queued, processed, failed, rate_limited
            FROM queue_stats
            WHERE date = ?
        ''', (today,))
        today_stats = cursor.fetchone()
        
        conn.close()
        
        return {
            'total': overall[0] or 0,
            'pending': overall[1] or 0,
            'processing': overall[2] or 0,
            'completed': overall[3] or 0,
            'failed': overall[4] or 0,
            'by_type': by_type,
            'by_threat_level': by_threat,
            'today': {
                'queued': today_stats[0] if today_stats else 0,
                'processed': today_stats[1] if today_stats else 0,
                'failed': today_stats[2] if today_stats else 0,
                'rate_limited': today_stats[3] if today_stats else 0
            }
        }
    
    def cleanup_old_completed(self, days: int = 7):
        """Remove completed submissions older than X days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = datetime.now().timestamp() - (days * 86400)
        cutoff_str = datetime.fromtimestamp(cutoff).isoformat()
        
        cursor.execute('''
            DELETE FROM submission_queue
            WHERE status = 'completed' AND created_at < ?
        ''', (cutoff_str,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
    
    def get_oldest_pending_age(self) -> Optional[int]:
        """Get age in seconds of oldest pending submission"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT created_at FROM submission_queue
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
        ''')
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            created = datetime.fromisoformat(row[0])
            age = (datetime.now() - created).total_seconds()
            return int(age)
        
        return None


if __name__ == '__main__':
    # Test queue
    queue = SpamhausQueue()
    
    # Add test submissions
    queue.add_submission('ip', {'ip': '192.0.2.1'}, threat_level='HIGH')
    queue.add_submission('domain', {'domain': 'evil.com'}, threat_level='CRITICAL')
    
    # Get stats
    stats = queue.get_queue_stats()
    print("Queue Statistics:")
    print(f"  Total: {stats['total']}")
    print(f"  Pending: {stats['pending']}")
    print(f"  Completed: {stats['completed']}")
    print(f"  Failed: {stats['failed']}")
    
    if stats['by_threat_level']:
        print("\nBy Threat Level:")
        for level, count in stats['by_threat_level'].items():
            print(f"  {level}: {count}")
