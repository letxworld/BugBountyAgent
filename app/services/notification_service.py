"""
BugBountyAgent - Notification Service
=======================================
This service handles all notifications including:
- Email alerts
- Telegram messages
- Webhook calls
- Console output
- Dashboard updates
"""

import os
import json
import requests
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

from app.core import get_config, log_info, log_error, log_warning, get_timestamp


@dataclass
class Notification:
    """Notification data structure."""
    type: str  # email, telegram, webhook, console, dashboard
    title: str
    message: str
    severity: str  # info, warning, error, critical, success
    data: Optional[Dict[str, Any]] = None
    timestamp: str = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = get_timestamp()


class NotificationService:
    """
    Service for sending notifications through multiple channels.
    """
    
    def __init__(self):
        self.enabled = get_config('notifications.enabled', True)
        self.methods = get_config('notifications.methods', ['console'])
        
        # Email config
        self.email_enabled = 'email' in self.methods
        self.smtp_server = get_config('notifications.email.smtp_server', 'smtp.gmail.com')
        self.smtp_port = get_config('notifications.email.smtp_port', 587)
        self.from_email = get_config('notifications.email.from', 'agent@bugbountyagent.com')
        self.to_email = get_config('notifications.email.to', '')
        
        # Telegram config
        self.telegram_enabled = 'telegram' in self.methods
        self.telegram_bot_token = get_config('notifications.telegram.bot_token', '')
        self.telegram_chat_id = get_config('notifications.telegram.chat_id', '')
        
        # Webhook config
        self.webhook_enabled = 'webhook' in self.methods
        self.webhook_url = get_config('notifications.webhook.url', '')
        self.webhook_headers = get_config('notifications.webhook.headers', {})
        
        # Dashboard config
        self.dashboard_enabled = 'dashboard' in self.methods
        
        log_info("NotificationService initialized")
    
    # ============================================================
    # Main Notification Method
    # ============================================================
    
    def send(self, notification: Notification) -> bool:
        """
        Send a notification through all enabled channels.
        
        Args:
            notification: Notification to send
            
        Returns:
            bool: Success status
        """
        if not self.enabled:
            return False
        
        success = True
        
        # Console (always enabled)
        if 'console' in self.methods:
            if not self._send_console(notification):
                success = False
        
        # Email
        if self.email_enabled and self.to_email:
            if not self._send_email(notification):
                success = False
        
        # Telegram
        if self.telegram_enabled and self.telegram_bot_token:
            if not self._send_telegram(notification):
                success = False
        
        # Webhook
        if self.webhook_enabled and self.webhook_url:
            if not self._send_webhook(notification):
                success = False
        
        # Dashboard (via callback)
        if self.dashboard_enabled:
            if not self._send_dashboard(notification):
                success = False
        
        return success
    
    def send_bulk(self, notifications: List[Notification]) -> Dict[str, int]:
        """
        Send multiple notifications.
        
        Returns:
            Dict: { 'sent': count, 'failed': count }
        """
        sent = 0
        failed = 0
        
        for notification in notifications:
            if self.send(notification):
                sent += 1
            else:
                failed += 1
        
        return {'sent': sent, 'failed': failed}
    
    # ============================================================
    # Notification Builders
    # ============================================================
    
    def notify_scan_started(self, target: str, scan_id: str) -> Notification:
        """Create notification for scan start."""
        return Notification(
            type='info',
            title='🚀 Scan Started',
            message=f'Scan {scan_id} started on {target}',
            severity='info',
            data={'target': target, 'scan_id': scan_id}
        )
    
    def notify_scan_completed(self, target: str, scan_id: str, findings: int) -> Notification:
        """Create notification for scan completion."""
        return Notification(
            type='success',
            title='✅ Scan Completed',
            message=f'Scan {scan_id} completed on {target}. Found {findings} findings.',
            severity='success',
            data={'target': target, 'scan_id': scan_id, 'findings': findings}
        )
    
    def notify_finding_critical(self, finding) -> Notification:
        """Create notification for critical finding."""
        return Notification(
            type='critical',
            title='🔴 Critical Finding',
            message=f'Critical finding on {finding.target.url}: {finding.title}',
            severity='critical',
            data={'finding': finding.to_dict()}
        )
    
    def notify_finding_high(self, finding) -> Notification:
        """Create notification for high severity finding."""
        return Notification(
            type='warning',
            title='🟠 High Finding',
            message=f'High severity finding on {finding.target.url}: {finding.title}',
            severity='warning',
            data={'finding': finding.to_dict()}
        )
    
    def notify_chain_complete(self, chain) -> Notification:
        """Create notification for complete attack chain."""
        return Notification(
            type='success',
            title='🔗 Attack Chain Complete',
            message=f'Attack chain {chain.name} completed on {chain.target.url}',
            severity='success',
            data={'chain': chain.to_dict()}
        )
    
    def notify_error(self, error: str, context: str = '') -> Notification:
        """Create notification for error."""
        return Notification(
            type='error',
            title='❌ Error',
            message=f'Error: {error}',
            severity='error',
            data={'error': error, 'context': context}
        )
    
    def notify_report_ready(self, report_path: str, target: str) -> Notification:
        """Create notification for report ready."""
        return Notification(
            type='info',
            title='📄 Report Ready',
            message=f'Report for {target} is ready: {report_path}',
            severity='info',
            data={'report_path': report_path, 'target': target}
        )
    
    # ============================================================
    # Channel Implementations
    # ============================================================
    
    def _send_console(self, notification: Notification) -> bool:
        """Send notification to console."""
        emoji_map = {
            'info': 'ℹ️',
            'warning': '⚠️',
            'error': '❌',
            'critical': '🔴',
            'success': '✅'
        }
        
        emoji = emoji_map.get(notification.severity, '📬')
        
        print(f"[{notification.timestamp}] {emoji} {notification.title}")
        print(f"   {notification.message}")
        
        if notification.data:
            print(f"   Data: {json.dumps(notification.data, default=str)[:200]}...")
        
        return True
    
    def _send_email(self, notification: Notification) -> bool:
        """Send notification via email."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            
            if not self.to_email:
                log_warning("Email recipient not configured")
                return False
            
            # Build email
            subject = f"[BugBountyAgent] {notification.title}"
            body = f"""
BugBountyAgent Notification
===========================

{notification.message}

Timestamp: {notification.timestamp}
Severity: {notification.severity}

--- Details ---
{json.dumps(notification.data, indent=2, default=str) if notification.data else 'None'}

---
This notification was sent automatically by BugBountyAgent.
"""
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = self.to_email
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.send_message(msg)
            
            log_info(f"Email notification sent to {self.to_email}")
            return True
            
        except Exception as e:
            log_error(f"Failed to send email notification: {e}")
            return False
    
    def _send_telegram(self, notification: Notification) -> bool:
        """Send notification via Telegram."""
        try:
            if not self.telegram_bot_token or not self.telegram_chat_id:
                log_warning("Telegram config incomplete")
                return False
            
            # Build message
            emoji_map = {
                'info': 'ℹ️',
                'warning': '⚠️',
                'error': '❌',
                'critical': '🔴',
                'success': '✅'
            }
            emoji = emoji_map.get(notification.severity, '📬')
            
            message = f"""
{emoji} *{notification.title}*
`{notification.message}`

📅 {notification.timestamp}
📊 Severity: {notification.severity.upper()}
"""
            
            if notification.data:
                # Format data for Telegram
                data_str = json.dumps(notification.data, indent=2, default=str)
                if len(data_str) > 500:
                    data_str = data_str[:500] + '...'
                message += f"\n📋 *Details:*\n```\n{data_str}\n```"
            
            # Send via Telegram API
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                log_info("Telegram notification sent")
                return True
            else:
                log_error(f"Telegram API error: {response.status_code}")
                return False
                
        except Exception as e:
            log_error(f"Failed to send Telegram notification: {e}")
            return False
    
    def _send_webhook(self, notification: Notification) -> bool:
        """Send notification via webhook."""
        try:
            if not self.webhook_url:
                log_warning("Webhook URL not configured")
                return False
            
            payload = {
                'title': notification.title,
                'message': notification.message,
                'severity': notification.severity,
                'timestamp': notification.timestamp,
                'data': notification.data
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.webhook_headers,
                timeout=10
            )
            
            if response.status_code in [200, 201, 202, 204]:
                log_info("Webhook notification sent")
                return True
            else:
                log_error(f"Webhook error: {response.status_code}")
                return False
                
        except Exception as e:
            log_error(f"Failed to send webhook notification: {e}")
            return False
    
    def _send_dashboard(self, notification: Notification) -> bool:
        """Send notification to dashboard via callback."""
        try:
            # This will be implemented with SocketIO
            # When dashboard is connected, emit events
            log_debug(f"Dashboard notification: {notification.title}")
            return True
        except Exception as e:
            log_error(f"Failed to send dashboard notification: {e}")
            return False
    
    # ============================================================
    # Configuration Methods
    # ============================================================
    
    def configure_email(self, smtp_server: str, smtp_port: int, 
                        from_email: str, to_email: str):
        """Configure email settings."""
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.from_email = from_email
        self.to_email = to_email
        self.email_enabled = True
        log_info("Email configured")
    
    def configure_telegram(self, bot_token: str, chat_id: str):
        """Configure Telegram settings."""
        self.telegram_bot_token = bot_token
        self.telegram_chat_id = chat_id
        self.telegram_enabled = True
        log_info("Telegram configured")
    
    def configure_webhook(self, url: str, headers: Dict[str, str] = None):
        """Configure webhook settings."""
        self.webhook_url = url
        self.webhook_headers = headers or {}
        self.webhook_enabled = True
        log_info("Webhook configured")
    
    def test_telegram(self) -> bool:
        """Test Telegram connection."""
        notification = Notification(
            type='info',
            title='🧪 Test Notification',
            message='This is a test notification from BugBountyAgent!',
            severity='info'
        )
        return self._send_telegram(notification)
    
    def test_email(self) -> bool:
        """Test email connection."""
        notification = Notification(
            type='info',
            title='🧪 Test Notification',
            message='This is a test email from BugBountyAgent!',
            severity='info'
        )
        return self._send_email(notification)