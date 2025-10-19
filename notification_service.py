"""
Notification Service

This service handles email notifications and in-app notifications
for tournament events and user interactions.
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from jinja2 import Template
from database import create_activity


class NotificationService:
    """Service for handling notifications and communications"""
    
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_email = os.getenv("FROM_EMAIL", "noreply@gamingnexus.com")
        self.from_name = os.getenv("FROM_NAME", "GamingNexus")
        
    def send_email(self, to_email: str, subject: str, html_content: str, text_content: str = None) -> bool:
        """
        Send email notification
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email content
            text_content: Plain text content (optional)
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            if not self.smtp_username or not self.smtp_password:
                print("SMTP credentials not configured, skipping email")
                return False
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = to_email
            
            # Add text content
            if text_content:
                text_part = MIMEText(text_content, 'plain')
                msg.attach(text_part)
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            print(f"✅ Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"❌ Error sending email to {to_email}: {e}")
            return False
    
    def create_in_app_notification(
        self, 
        user_id: str, 
        title: str, 
        message: str, 
        notification_type: str = "info",
        related_id: str = None,
        action_url: str = None
    ) -> bool:
        """
        Create in-app notification using activity system
        
        Args:
            user_id: Target user ID
            title: Notification title
            message: Notification message
            notification_type: Type of notification (info, success, warning, error)
            related_id: Related entity ID (tournament, payment, etc.)
            action_url: URL for notification action
            
        Returns:
            True if notification created successfully
        """
        try:
            activity_data = {
                "userId": user_id,
                "activityType": "notification",
                "title": title,
                "description": message,
                "metadata": {
                    "notificationType": notification_type,
                    "relatedId": related_id,
                    "actionUrl": action_url,
                    "isRead": False,
                    "priority": "normal"
                }
            }
            
            create_activity(activity_data)
            print(f"✅ In-app notification created for user {user_id}")
            return True
            
        except Exception as e:
            print(f"❌ Error creating in-app notification: {e}")
            return False
    

    
    def send_waitlist_promotion_notification(self, participant_email: str, promotion_data: Dict[str, Any]) -> bool:
        """Send notification when a team is promoted from waitlist"""
        try:
            subject = f"You're in! Promoted from waitlist for {promotion_data.get('tournamentName', 'Tournament')}"
            
            html_template = Template("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #28a745;">You're In! 🎉</h2>
                    
                    <p>Great news, {{ team_name }}!</p>
                    
                    <p>A spot has opened up in <strong>{{ tournament_name }}</strong> and you've been promoted from the waitlist!</p>
                    
                    <div style="background-color: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #28a745;">
                        <h3 style="margin-top: 0; color: #155724;">Tournament Details:</h3>
                        <ul style="list-style: none; padding: 0;">
                            <li><strong>Tournament:</strong> {{ tournament_name }}</li>
                            <li><strong>Game:</strong> {{ game }}</li>
                            <li><strong>Start Date:</strong> {{ start_date }}</li>
                            <li><strong>Entry Fee:</strong> ${{ entry_fee }}</li>
                        </ul>
                    </div>
                    
                    <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                        <h3 style="margin-top: 0; color: #856404;">⏰ Action Required</h3>
                        <p style="margin: 0;">You have <strong>{{ response_window }} hours</strong> to confirm your participation. If you don't respond within this time, your spot will be offered to the next team on the waitlist.</p>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{{ confirm_url }}" style="background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin-right: 10px;">
                            Confirm Participation
                        </a>
                        <a href="{{ decline_url }}" style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                            Decline
                        </a>
                    </div>
                    
                    <p>Don't miss this opportunity - confirm your spot now!</p>
                    
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    <p style="font-size: 12px; color: #666;">
                        This is an automated message from GamingNexus. Please do not reply to this email.
                    </p>
                </div>
            </body>
            </html>
            """)
            
            html_content = html_template.render(
                team_name=promotion_data.get('teamName', 'Team'),
                tournament_name=promotion_data.get('tournamentName', 'Tournament'),
                game=promotion_data.get('game', 'N/A'),
                start_date=promotion_data.get('startDate', 'N/A'),
                entry_fee=promotion_data.get('entryFee', 0),
                response_window=promotion_data.get('responseWindow', 24),
                confirm_url=f"https://gamingnexus.onrender.com/tournaments/{promotion_data.get('tournamentSlug', '')}/confirm-waitlist",
                decline_url=f"https://gamingnexus.onrender.com/tournaments/{promotion_data.get('tournamentSlug', '')}/decline-waitlist"
            )
            
            return self.send_email(participant_email, subject, html_content)
            
        except Exception as e:
            print(f"Error sending waitlist promotion notification: {e}")
            return False
    
    def send_tournament_reminder_notification(self, participant_email: str, reminder_data: Dict[str, Any]) -> bool:
        """Send tournament reminder notification"""
        try:
            subject = f"Reminder: {reminder_data.get('tournamentName', 'Tournament')} starts soon!"
            
            html_template = Template("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #ffc107;">Tournament Reminder ⏰</h2>
                    
                    <p>Hi {{ team_name }},</p>
                    
                    <p>This is a friendly reminder that <strong>{{ tournament_name }}</strong> starts in {{ time_until_start }}!</p>
                    
                    <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                        <h3 style="margin-top: 0; color: #856404;">Tournament Information:</h3>
                        <ul style="list-style: none; padding: 0;">
                            <li><strong>Start Time:</strong> {{ start_time }}</li>
                            <li><strong>Game:</strong> {{ game }}</li>
                            <li><strong>Format:</strong> {{ format }}</li>
                            <li><strong>Check-in:</strong> {{ checkin_time }}</li>
                        </ul>
                    </div>
                    
                    <div style="background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #1565c0;">Pre-Tournament Checklist:</h3>
                        <ul>
                            <li>✅ Ensure all team members are available</li>
                            <li>✅ Check your game client is updated</li>
                            <li>✅ Test your internet connection</li>
                            <li>✅ Join the tournament Discord/communication channel</li>
                            <li>✅ Review tournament rules</li>
                        </ul>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{{ tournament_url }}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                            View Tournament Details
                        </a>
                    </div>
                    
                    <p>Good luck in the tournament!</p>
                    
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    <p style="font-size: 12px; color: #666;">
                        This is an automated message from GamingNexus. Please do not reply to this email.
                    </p>
                </div>
            </body>
            </html>
            """)
            
            html_content = html_template.render(
                team_name=reminder_data.get('teamName', 'Team'),
                tournament_name=reminder_data.get('tournamentName', 'Tournament'),
                time_until_start=reminder_data.get('timeUntilStart', 'soon'),
                start_time=reminder_data.get('startTime', 'N/A'),
                game=reminder_data.get('game', 'N/A'),
                format=reminder_data.get('format', 'N/A'),
                checkin_time=reminder_data.get('checkinTime', '30 minutes before start'),
                tournament_url=f"https://gamingnexus.onrender.com/tournaments/{reminder_data.get('tournamentSlug', '')}"
            )
            
            return self.send_email(participant_email, subject, html_content)
            
        except Exception as e:
            print(f"Error sending tournament reminder: {e}")
            return False
    
    def send_bulk_notification(self, recipients: List[str], subject: str, html_content: str) -> Dict[str, Any]:
        """
        Send bulk notifications to multiple recipients
        
        Args:
            recipients: List of email addresses
            subject: Email subject
            html_content: HTML email content
            
        Returns:
            Dictionary with success/failure counts and details
        """
        results = {
            "total": len(recipients),
            "successful": 0,
            "failed": 0,
            "errors": []
        }
        
        for email in recipients:
            try:
                success = self.send_email(email, subject, html_content)
                if success:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
                    results["errors"].append(f"Failed to send to {email}")
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Error sending to {email}: {str(e)}")
        
        return results
    
    def schedule_reminder_notifications(self, tournament_id: str, tournament_data: Dict[str, Any]) -> bool:
        """
        Schedule reminder notifications for tournament events
        
        Args:
            tournament_id: Tournament ID
            tournament_data: Tournament information
            
        Returns:
            True if reminders scheduled successfully
        """
        try:
            # This would typically integrate with a task queue like Celery
            # For now, we'll just log the scheduling
            
            start_time = datetime.fromisoformat(tournament_data['tournamentStart'].replace('Z', '+00:00'))
            
            # Schedule reminders at different intervals
            reminder_intervals = [
                {"hours": 24, "message": "24 hours"},
                {"hours": 2, "message": "2 hours"},
                {"hours": 0.5, "message": "30 minutes"}
            ]
            
            for interval in reminder_intervals:
                reminder_time = start_time - timedelta(hours=interval["hours"])
                
                if reminder_time > datetime.utcnow():
                    print(f"📅 Scheduled reminder for {tournament_data['name']} at {reminder_time} ({interval['message']} before start)")
            
            return True
            
        except Exception as e:
            print(f"Error scheduling reminder notifications: {e}")
            return False


# Global notification service instance
notification_service = NotificationService()


def get_notification_service() -> NotificationService:
    """Get the global notification service instance"""
    return notification_service
  


