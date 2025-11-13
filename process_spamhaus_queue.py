#!/usr/bin/env python3
"""
Spamhaus Queue Processor
Processes queued Spamhaus submissions with rate limiting

Usage:
  # Process up to 50 submissions
  ./process_spamhaus_queue.py
  
  # Process specific number
  ./process_spamhaus_queue.py --batch-size 100
  
  # Run in daemon mode (continuous processing)
  ./process_spamhaus_queue.py --daemon --interval 300
  
  # Show queue status
  ./process_spamhaus_queue.py --status
  
Add to crontab for automatic processing:
  # Process queue every 30 minutes
  */30 * * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 50
  
  # Process overnight (more aggressive)
  0 1-6 * * * /home/Terje/scripts/Laer-av-spamfolder/process_spamhaus_queue.py --batch-size 200
"""

import sys
import os
import time
import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

# Add script directory to path
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

from spamhaus_queue import SpamhausQueue
import yaml


class QueueProcessor:
    """Process queued Spamhaus submissions"""
    
    def __init__(self, config_path: str = None, batch_size: int = 50):
        self.queue = SpamhausQueue()
        self.batch_size = batch_size
        
        # Setup logging
        self.logger = logging.getLogger('QueueProcessor')
        self.logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
        
        # Load config
        if config_path is None:
            config_path = script_dir / 'config.yaml'
        
        self.config = self._load_config(config_path)
        self.api_key = self.config.get('reporting', {}).get('spamhaus_api_key', '')
        
        if not self.api_key:
            self.logger.error("No Spamhaus API key configured!")
            sys.exit(1)
        
        # Rate limiting
        self.max_per_batch = self.config.get('reporting', {}).get('spamhaus_max_per_run', 50)
        self.delay_between_submissions = 2  # seconds between each API call
        
        self.api_base = "https://submit.spamhaus.org/portal/api/v1"
    
    def _load_config(self, config_path: Path) -> dict:
        """Load YAML config"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            self.logger.warning(f"Could not load config: {e}")
            return {}
    
    def _get_headers(self):
        """Get API headers"""
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def process_batch(self, max_submissions: int = None) -> dict:
        """
        Process one batch of submissions
        Returns stats dict
        """
        import requests
        
        if max_submissions is None:
            max_submissions = self.batch_size
        
        stats = {
            'processed': 0,
            'succeeded': 0,
            'failed': 0,
            'rate_limited': 0,
            'skipped': 0
        }
        
        # Get pending submissions
        pending = self.queue.get_pending_submissions(limit=max_submissions)
        
        if not pending:
            self.logger.info("No pending submissions in queue")
            return stats
        
        self.logger.info(f"Processing {len(pending)} queued submissions...")
        
        for item in pending:
            queue_id = item['id']
            submission_type = item['submission_type']
            data = json.loads(item['submission_data'])
            
            # Mark as processing
            self.queue.mark_processing(queue_id)
            
            try:
                # Determine endpoint
                endpoint_map = {
                    'ip': 'ip',
                    'domain': 'domain',
                    'url': 'url',
                    'email': 'email'
                }
                endpoint = endpoint_map.get(submission_type)
                
                if not endpoint:
                    self.logger.error(f"Unknown submission type: {submission_type}")
                    self.queue.mark_failed(queue_id, f"Unknown type: {submission_type}", retry=False)
                    stats['failed'] += 1
                    continue
                
                # Submit to API
                url = f"{self.api_base}/submissions/add/{endpoint}"
                
                self.logger.debug(f"Submitting {submission_type}: {data.get('source', {}).get('object', 'N/A')[:50]}")
                
                response = requests.post(
                    url,
                    headers=self._get_headers(),
                    json=data,
                    timeout=60
                )
                
                stats['processed'] += 1
                
                if response.status_code == 200:
                    result = response.json()
                    self.queue.mark_completed(queue_id, result)
                    stats['succeeded'] += 1
                    self.logger.info(f"✅ Submitted {submission_type} (ID: {result.get('id', 'unknown')})")
                
                elif response.status_code == 208:
                    # Already reported - count as success
                    self.queue.mark_completed(queue_id, {'status': 208, 'message': 'already reported'})
                    stats['succeeded'] += 1
                    self.logger.debug(f"Already reported: {submission_type}")
                
                elif response.status_code == 429:
                    # Rate limited - put back in queue
                    self.queue.mark_rate_limited(queue_id)
                    stats['rate_limited'] += 1
                    self.logger.warning(f"⚠️ Rate limited, stopping batch. Remaining items queued for later.")
                    break  # Stop processing this batch
                
                else:
                    # Other error
                    error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                    self.queue.mark_failed(queue_id, error_msg, retry=True)
                    stats['failed'] += 1
                    self.logger.warning(f"Failed to submit {submission_type}: {error_msg}")
                
                # Rate limiting delay
                time.sleep(self.delay_between_submissions)
            
            except Exception as e:
                self.queue.mark_failed(queue_id, str(e), retry=True)
                stats['failed'] += 1
                self.logger.error(f"Error processing queue item {queue_id}: {e}")
        
        return stats
    
    def show_status(self):
        """Show queue status"""
        stats = self.queue.get_queue_stats()
        
        print("\n" + "="*60)
        print("  SPAMHAUS SUBMISSION QUEUE STATUS")
        print("="*60)
        
        print(f"\n📊 Overall:")
        print(f"  Total items:      {stats['total']}")
        print(f"  Pending:          {stats['pending']}")
        print(f"  Processing:       {stats['processing']}")
        print(f"  Completed:        {stats['completed']}")
        print(f"  Failed:           {stats['failed']}")
        
        if stats['pending'] > 0:
            oldest_age = self.queue.get_oldest_pending_age()
            if oldest_age:
                hours = oldest_age // 3600
                minutes = (oldest_age % 3600) // 60
                print(f"\n⏰ Oldest pending: {hours}h {minutes}m ago")
        
        if stats['by_type']:
            print(f"\n📦 Pending by Type:")
            for submission_type, count in sorted(stats['by_type'].items()):
                print(f"  {submission_type:10s}: {count}")
        
        if stats['by_threat_level']:
            print(f"\n⚠️  Pending by Threat Level:")
            for level, count in sorted(stats['by_threat_level'].items(), 
                                      key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x[0], 4)):
                print(f"  {level:10s}: {count}")
        
        print(f"\n📅 Today's Activity:")
        print(f"  Queued:           {stats['today']['queued']}")
        print(f"  Processed:        {stats['today']['processed']}")
        print(f"  Failed:           {stats['today']['failed']}")
        print(f"  Rate Limited:     {stats['today']['rate_limited']}")
        
        print("\n" + "="*60 + "\n")
    
    def run_daemon(self, interval: int = 300):
        """
        Run in daemon mode - process queue continuously
        interval: seconds between batch runs
        """
        self.logger.info(f"Starting daemon mode (interval: {interval}s)")
        
        try:
            while True:
                stats = self.process_batch()
                
                if stats['processed'] > 0:
                    self.logger.info(
                        f"Batch complete: {stats['succeeded']} succeeded, "
                        f"{stats['failed']} failed, "
                        f"{stats['rate_limited']} rate limited"
                    )
                
                # Show status every 10 batches or if pending
                queue_stats = self.queue.get_queue_stats()
                if queue_stats['pending'] > 0:
                    self.logger.info(f"{queue_stats['pending']} items still pending")
                
                # Wait for next interval
                self.logger.info(f"Waiting {interval}s until next batch...")
                time.sleep(interval)
        
        except KeyboardInterrupt:
            self.logger.info("Daemon stopped by user")


def main():
    parser = argparse.ArgumentParser(
        description='Process Spamhaus submission queue',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--batch-size', type=int, default=50,
                       help='Number of items to process per batch (default: 50)')
    
    parser.add_argument('--daemon', action='store_true',
                       help='Run in daemon mode (continuous processing)')
    
    parser.add_argument('--interval', type=int, default=300,
                       help='Interval between batches in daemon mode (seconds, default: 300)')
    
    parser.add_argument('--status', action='store_true',
                       help='Show queue status and exit')
    
    parser.add_argument('--cleanup', type=int, metavar='DAYS',
                       help='Clean up completed items older than DAYS')
    
    parser.add_argument('--config', type=str,
                       help='Path to config.yaml (default: ./config.yaml)')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Show status only
    if args.status:
        processor = QueueProcessor(config_path=args.config, batch_size=args.batch_size)
        processor.show_status()
        return
    
    # Cleanup only
    if args.cleanup:
        queue = SpamhausQueue()
        deleted = queue.cleanup_old_completed(days=args.cleanup)
        print(f"Cleaned up {deleted} completed items older than {args.cleanup} days")
        return
    
    # Create processor
    processor = QueueProcessor(config_path=args.config, batch_size=args.batch_size)
    
    if args.verbose:
        processor.logger.setLevel(logging.DEBUG)
    
    # Daemon mode
    if args.daemon:
        processor.run_daemon(interval=args.interval)
    else:
        # Single batch
        stats = processor.process_batch()
        print(f"\nProcessed: {stats['processed']}")
        print(f"Succeeded: {stats['succeeded']}")
        print(f"Failed: {stats['failed']}")
        print(f"Rate Limited: {stats['rate_limited']}")
        
        # Show remaining
        queue_stats = processor.queue.get_queue_stats()
        if queue_stats['pending'] > 0:
            print(f"\nStill pending: {queue_stats['pending']} items")
            print(f"Run again or add to crontab for automatic processing")


if __name__ == '__main__':
    main()
