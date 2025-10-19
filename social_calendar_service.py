"""
Social Media and Calendar Integration Service

This service handles social media sharing, calendar integration, and promotional
material generation for tournaments.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode
import base64
import json

logger = logging.getLogger(__name__)


class SocialMediaService:
    """Service for social media integration and sharing"""
    
    def __init__(self):
        self.platform_configs = {
            'twitter': {
                'base_url': 'https://twitter.com/intent/tweet',
                'max_length': 280,
                'hashtags': ['gaming', 'tournament', 'esports']
            },
            'facebook': {
                'base_url': 'https://www.facebook.com/sharer/sharer.php',
                'max_length': 500
            },
            'linkedin': {
                'base_url': 'https://www.linkedin.com/sharing/share-offsite/',
                'max_length': 700
            },
            'reddit': {
                'base_url': 'https://www.reddit.com/submit',
                'max_length': 300
            },
            'discord': {
                'webhook_format': True,
                'max_length': 2000
            }
        }
    
    async def generate_social_share_content(self, tournament: Dict[str, Any], platform: str) -> Dict[str, Any]:
        """Generate platform-specific social media content"""
        try:
            config = self.platform_configs.get(platform)
            if not config:
                return {
                    "success": False,
                    "message": f"Unsupported platform: {platform}"
                }
            
            # Generate base content
            base_content = self._create_base_content(tournament)
            
            # Platform-specific formatting
            if platform == 'twitter':
                content = self._format_for_twitter(base_content, tournament)
            elif platform == 'facebook':
                content = self._format_for_facebook(base_content, tournament)
            elif platform == 'linkedin':
                content = self._format_for_linkedin(base_content, tournament)
            elif platform == 'reddit':
                content = self._format_for_reddit(base_content, tournament)
            elif platform == 'discord':
                content = self._format_for_discord(base_content, tournament)
            else:
                content = base_content
            
            return {
                "success": True,
                "data": content,
                "message": f"Content generated for {platform}"
            }
            
        except Exception as e:
            logger.error(f"Error generating social content for {platform}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to generate content for {platform}: {str(e)}"
            }
    
    def _create_base_content(self, tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Create base content structure"""
        # Format dates
        reg_start = datetime.fromisoformat(tournament['registrationStart']).strftime('%B %d, %Y')
        tournament_start = datetime.fromisoformat(tournament['tournamentStart']).strftime('%B %d, %Y')
        
        # Determine tournament type
        venue_type = tournament.get('venueType', 'online')
        location_text = ""
        if venue_type == 'physical' and tournament.get('venueDetails'):
            venue = tournament['venueDetails']
            location_text = f" at {venue['name']}, {venue['city']}"
        elif venue_type == 'hybrid':
            location_text = " (Hybrid: Online & Physical)"
        
        return {
            'title': tournament['title'],
            'game': tournament['game'],
            'description': tournament['description'][:200] + '...' if len(tournament['description']) > 200 else tournament['description'],
            'registration_start': reg_start,
            'tournament_start': tournament_start,
            'entry_fee': tournament['entryFee'],
            'prize_pool': tournament['prizePool'],
            'max_teams': tournament['maxTeams'],
            'organizer': tournament['organizerUsername'],
            'location_text': location_text,
            'venue_type': venue_type,
            'tournament_url': f"https://tournament-platform.com/tournaments/{tournament['slug']}"
        }
    
    def _format_for_twitter(self, content: Dict[str, Any], tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Format content for Twitter"""
        hashtags = ['#gaming', '#tournament', '#esports', f"#{content['game'].replace(' ', '')}"]
        
        tweet_text = f"🎮 {content['title']} Tournament!\n\n"
        tweet_text += f"🎯 Game: {content['game']}\n"
        tweet_text += f"💰 Prize Pool: ${content['prize_pool']}\n"
        tweet_text += f"👥 Max Teams: {content['max_teams']}\n"
        tweet_text += f"📅 Registration: {content['registration_start']}\n"
        tweet_text += f"🚀 Starts: {content['tournament_start']}{content['location_text']}\n\n"
        
        # Add hashtags if space allows
        hashtag_text = ' '.join(hashtags)
        if len(tweet_text + hashtag_text) <= 280:
            tweet_text += hashtag_text
        
        share_url = f"{self.platform_configs['twitter']['base_url']}?{urlencode({'text': tweet_text, 'url': content['tournament_url']})}"
        
        return {
            'platform': 'twitter',
            'text': tweet_text,
            'share_url': share_url,
            'hashtags': hashtags,
            'character_count': len(tweet_text)
        }
    
    def _format_for_facebook(self, content: Dict[str, Any], tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Format content for Facebook"""
        post_text = f"🎮 Join the {content['title']} Tournament!\n\n"
        post_text += f"We're excited to announce our upcoming {content['game']} tournament{content['location_text']}!\n\n"
        post_text += f"📋 Tournament Details:\n"
        post_text += f"• Game: {content['game']}\n"
        post_text += f"• Prize Pool: ${content['prize_pool']}\n"
        post_text += f"• Entry Fee: ${content['entry_fee']}\n"
        post_text += f"• Max Teams: {content['max_teams']}\n"
        post_text += f"• Registration Opens: {content['registration_start']}\n"
        post_text += f"• Tournament Date: {content['tournament_start']}\n"
        post_text += f"• Organized by: {content['organizer']}\n\n"
        post_text += f"Don't miss out on this exciting competition! Register now and show off your skills!\n\n"
        post_text += f"#Gaming #Tournament #Esports #{content['game'].replace(' ', '')}"
        
        share_url = f"{self.platform_configs['facebook']['base_url']}?{urlencode({'u': content['tournament_url']})}"
        
        return {
            'platform': 'facebook',
            'text': post_text,
            'share_url': share_url,
            'character_count': len(post_text)
        }
    
    def _format_for_linkedin(self, content: Dict[str, Any], tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Format content for LinkedIn"""
        post_text = f"🎮 Professional Gaming Tournament: {content['title']}\n\n"
        post_text += f"I'm excited to share details about our upcoming {content['game']} tournament, "
        post_text += f"showcasing competitive gaming talent{content['location_text']}.\n\n"
        post_text += f"Tournament Highlights:\n"
        post_text += f"• Competitive {content['game']} gameplay\n"
        post_text += f"• ${content['prize_pool']} prize pool\n"
        post_text += f"• Professional tournament format\n"
        post_text += f"• {content['max_teams']} team capacity\n"
        post_text += f"• Registration begins {content['registration_start']}\n"
        post_text += f"• Event date: {content['tournament_start']}\n\n"
        post_text += f"This tournament represents the growing esports industry and provides "
        post_text += f"opportunities for gamers to showcase their skills in a competitive environment.\n\n"
        post_text += f"Organized by: {content['organizer']}\n\n"
        post_text += f"#Esports #Gaming #Tournament #Competition #ProfessionalGaming"
        
        share_url = f"{self.platform_configs['linkedin']['base_url']}?{urlencode({'url': content['tournament_url']})}"
        
        return {
            'platform': 'linkedin',
            'text': post_text,
            'share_url': share_url,
            'character_count': len(post_text)
        }
    
    def _format_for_reddit(self, content: Dict[str, Any], tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Format content for Reddit"""
        title = f"[Tournament] {content['title']} - ${content['prize_pool']} Prize Pool!"
        
        post_text = f"Hey everyone! 👋\n\n"
        post_text += f"I'm organizing a {content['game']} tournament and wanted to share it with the community!\n\n"
        post_text += f"**Tournament Details:**\n"
        post_text += f"- **Game:** {content['game']}\n"
        post_text += f"- **Prize Pool:** ${content['prize_pool']}\n"
        post_text += f"- **Entry Fee:** ${content['entry_fee']}\n"
        post_text += f"- **Max Teams:** {content['max_teams']}\n"
        post_text += f"- **Registration:** {content['registration_start']}\n"
        post_text += f"- **Tournament Date:** {content['tournament_start']}\n"
        if content['location_text']:
            post_text += f"- **Location:** {content['location_text'].strip()}\n"
        post_text += f"\n**About:**\n{content['description']}\n\n"
        post_text += f"Looking forward to some great competition! Feel free to ask any questions.\n\n"
        post_text += f"Registration link in comments!"
        
        share_url = f"{self.platform_configs['reddit']['base_url']}?{urlencode({'title': title, 'text': post_text})}"
        
        return {
            'platform': 'reddit',
            'title': title,
            'text': post_text,
            'share_url': share_url,
            'character_count': len(post_text)
        }
    
    def _format_for_discord(self, content: Dict[str, Any], tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Format content for Discord"""
        embed_data = {
            "title": f"🎮 {content['title']} Tournament",
            "description": content['description'],
            "color": 0x00ff00,  # Green color
            "fields": [
                {"name": "🎯 Game", "value": content['game'], "inline": True},
                {"name": "💰 Prize Pool", "value": f"${content['prize_pool']}", "inline": True},
                {"name": "💳 Entry Fee", "value": f"${content['entry_fee']}", "inline": True},
                {"name": "👥 Max Teams", "value": str(content['max_teams']), "inline": True},
                {"name": "📅 Registration", "value": content['registration_start'], "inline": True},
                {"name": "🚀 Tournament Date", "value": content['tournament_start'], "inline": True},
                {"name": "👤 Organizer", "value": content['organizer'], "inline": True}
            ],
            "footer": {"text": "Click the link below to register!"},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if content['location_text']:
            embed_data['fields'].append({
                "name": "📍 Location", 
                "value": content['location_text'].strip(), 
                "inline": False
            })
        
        message_text = f"@everyone 🎮 **New Tournament Alert!** 🎮\n\n"
        message_text += f"**{content['title']}** is now open for registration!\n"
        message_text += f"Register here: {content['tournament_url']}\n\n"
        message_text += f"React with 🎮 if you're interested!"
        
        return {
            'platform': 'discord',
            'text': message_text,
            'embed': embed_data,
            'webhook_payload': {
                'content': message_text,
                'embeds': [embed_data]
            }
        }
    
    async def generate_shareable_link(self, tournament: Dict[str, Any], utm_source: str = None) -> Dict[str, Any]:
        """Generate a shareable tournament link with tracking parameters"""
        try:
            base_url = f"https://tournament-platform.com/tournaments/{tournament['slug']}"
            
            # Add UTM parameters for tracking
            utm_params = {
                'utm_campaign': 'tournament_sharing',
                'utm_medium': 'social',
                'utm_content': tournament['slug']
            }
            
            if utm_source:
                utm_params['utm_source'] = utm_source
            
            shareable_url = f"{base_url}?{urlencode(utm_params)}"
            
            # Generate short URL (mock implementation)
            short_url = f"https://trnmt.ly/{tournament['slug'][:8]}"
            
            return {
                "success": True,
                "data": {
                    "full_url": shareable_url,
                    "short_url": short_url,
                    "qr_code_url": f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={quote(shareable_url)}",
                    "utm_params": utm_params
                },
                "message": "Shareable link generated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error generating shareable link: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to generate shareable link: {str(e)}"
            }
    
    async def generate_promotional_materials(self, tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Generate promotional materials (images, banners, etc.)"""
        try:
            # Mock promotional material generation
            # In a real implementation, this would integrate with image generation APIs
            
            materials = {
                "social_media_images": {
                    "square": f"https://api.placeholder.com/600x600/007bff/ffffff?text={quote(tournament['title'])}",
                    "landscape": f"https://api.placeholder.com/1200x630/007bff/ffffff?text={quote(tournament['title'])}",
                    "story": f"https://api.placeholder.com/1080x1920/007bff/ffffff?text={quote(tournament['title'])}"
                },
                "banners": {
                    "web_banner": f"https://api.placeholder.com/728x90/007bff/ffffff?text={quote(tournament['title'])}",
                    "mobile_banner": f"https://api.placeholder.com/320x50/007bff/ffffff?text={quote(tournament['title'])}"
                },
                "flyers": {
                    "digital_flyer": f"https://api.placeholder.com/800x1200/007bff/ffffff?text={quote(tournament['title'])}",
                    "print_flyer": f"https://api.placeholder.com/2480x3508/007bff/ffffff?text={quote(tournament['title'])}"
                }
            }
            
            return {
                "success": True,
                "data": materials,
                "message": "Promotional materials generated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error generating promotional materials: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to generate promotional materials: {str(e)}"
            }


class CalendarIntegrationService:
    """Service for calendar integration and event management"""
    
    def __init__(self):
        self.calendar_providers = {
            'google': {
                'base_url': 'https://calendar.google.com/calendar/render',
                'format': 'google'
            },
            'outlook': {
                'base_url': 'https://outlook.live.com/calendar/0/deeplink/compose',
                'format': 'outlook'
            },
            'apple': {
                'format': 'ics'
            },
            'yahoo': {
                'base_url': 'https://calendar.yahoo.com/',
                'format': 'yahoo'
            }
        }
    
    async def generate_calendar_event(self, tournament: Dict[str, Any], provider: str = 'ics') -> Dict[str, Any]:
        """Generate calendar event for a tournament"""
        try:
            if provider not in self.calendar_providers and provider != 'ics':
                return {
                    "success": False,
                    "message": f"Unsupported calendar provider: {provider}"
                }
            
            # Parse tournament dates
            reg_start = datetime.fromisoformat(tournament['registrationStart'])
            reg_end = datetime.fromisoformat(tournament['registrationEnd'])
            tournament_start = datetime.fromisoformat(tournament['tournamentStart'])
            tournament_end = datetime.fromisoformat(tournament['tournamentEnd'])
            
            # Generate event data
            event_data = self._create_event_data(tournament, reg_start, reg_end, tournament_start, tournament_end)
            
            if provider == 'ics':
                calendar_content = self._generate_ics_content(event_data, tournament_start, tournament_end)
                return {
                    "success": True,
                    "data": {
                        "provider": "ics",
                        "content": calendar_content,
                        "filename": f"{tournament['slug']}_tournament.ics",
                        "mime_type": "text/calendar"
                    },
                    "message": "ICS calendar file generated successfully"
                }
            elif provider == 'google':
                google_url = self._generate_google_calendar_url(event_data, tournament_start, tournament_end)
                return {
                    "success": True,
                    "data": {
                        "provider": "google",
                        "calendar_url": google_url
                    },
                    "message": "Google Calendar URL generated successfully"
                }
            elif provider == 'outlook':
                outlook_url = self._generate_outlook_calendar_url(event_data, tournament_start, tournament_end)
                return {
                    "success": True,
                    "data": {
                        "provider": "outlook",
                        "calendar_url": outlook_url
                    },
                    "message": "Outlook Calendar URL generated successfully"
                }
            elif provider == 'yahoo':
                yahoo_url = self._generate_yahoo_calendar_url(event_data, tournament_start, tournament_end)
                return {
                    "success": True,
                    "data": {
                        "provider": "yahoo",
                        "calendar_url": yahoo_url
                    },
                    "message": "Yahoo Calendar URL generated successfully"
                }
            
        except Exception as e:
            logger.error(f"Error generating calendar event: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to generate calendar event: {str(e)}"
            }
    
    def _create_event_data(self, tournament: Dict[str, Any], reg_start, reg_end, tournament_start, tournament_end):
        """Create base event data structure"""
        # Determine location
        location = "Online Tournament"
        if tournament.get('venueType') == 'physical' and tournament.get('venueDetails'):
            venue = tournament['venueDetails']
            location = f"{venue['name']}, {venue['address']}, {venue['city']}, {venue['state']}"
        elif tournament.get('venueType') == 'hybrid':
            location = "Hybrid Tournament (Online & Physical)"
        
        # Create description
        description = f"{tournament['description']}\n\n"
        description += f"Tournament Details:\n"
        description += f"• Game: {tournament['game']}\n"
        description += f"• Prize Pool: ${tournament['prizePool']}\n"
        description += f"• Entry Fee: ${tournament['entryFee']}\n"
        description += f"• Max Teams: {tournament['maxTeams']}\n"
        description += f"• Organizer: {tournament['organizerUsername']}\n"
        description += f"• Registration: {reg_start.strftime('%B %d, %Y at %I:%M %p')} - {reg_end.strftime('%B %d, %Y at %I:%M %p')}\n\n"
        description += f"Register at: https://tournament-platform.com/tournaments/{tournament['slug']}"
        
        return {
            'title': f"{tournament['title']} - {tournament['game']} Tournament",
            'description': description,
            'location': location,
            'organizer': tournament['organizerUsername'],
            'url': f"https://tournament-platform.com/tournaments/{tournament['slug']}"
        }
    
    def _generate_ics_content(self, event_data, start_time, end_time):
        """Generate ICS calendar file content"""
        # Format dates for ICS (UTC format)
        start_utc = start_time.strftime('%Y%m%dT%H%M%SZ')
        end_utc = end_time.strftime('%Y%m%dT%H%M%SZ')
        created_utc = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        
        # Generate unique UID
        uid = f"tournament-{hash(event_data['title'])}-{start_utc}@tournament-platform.com"
        
        # Fix description formatting (extract backslash replacement outside f-string)
        description_formatted = event_data['description'].replace('\n', '\\n')
        
        ics_content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Tournament Platform//Tournament Calendar//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
BEGIN:VEVENT
UID:{uid}
DTSTART:{start_utc}
DTEND:{end_utc}
DTSTAMP:{created_utc}
CREATED:{created_utc}
SUMMARY:{event_data['title']}
DESCRIPTION:{description_formatted}
LOCATION:{event_data['location']}
ORGANIZER:CN={event_data['organizer']}
URL:{event_data['url']}
STATUS:CONFIRMED
TRANSP:OPAQUE
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Tournament starting in 1 hour
TRIGGER:-PT1H
END:VALARM
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Tournament starting in 24 hours
TRIGGER:-PT24H
END:VALARM
END:VEVENT
END:VCALENDAR"""
        
        return ics_content
    
    def _generate_google_calendar_url(self, event_data, start_time, end_time):
        """Generate Google Calendar URL"""
        # Format dates for Google Calendar
        start_formatted = start_time.strftime('%Y%m%dT%H%M%SZ')
        end_formatted = end_time.strftime('%Y%m%dT%H%M%SZ')
        
        params = {
            'action': 'TEMPLATE',
            'text': event_data['title'],
            'dates': f"{start_formatted}/{end_formatted}",
            'details': event_data['description'],
            'location': event_data['location'],
            'sprop': f"website:{event_data['url']}"
        }
        
        return f"{self.calendar_providers['google']['base_url']}?{urlencode(params)}"
    
    def _generate_outlook_calendar_url(self, event_data, start_time, end_time):
        """Generate Outlook Calendar URL"""
        # Format dates for Outlook
        start_formatted = start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_formatted = end_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        params = {
            'subject': event_data['title'],
            'startdt': start_formatted,
            'enddt': end_formatted,
            'body': event_data['description'],
            'location': event_data['location']
        }
        
        return f"{self.calendar_providers['outlook']['base_url']}?{urlencode(params)}"
    
    def _generate_yahoo_calendar_url(self, event_data, start_time, end_time):
        """Generate Yahoo Calendar URL"""
        # Calculate duration in minutes
        duration = int((end_time - start_time).total_seconds() / 60)
        
        params = {
            'v': '60',
            'title': event_data['title'],
            'st': start_time.strftime('%Y%m%dT%H%M%SZ'),
            'dur': f"{duration:04d}",
            'desc': event_data['description'],
            'in_loc': event_data['location']
        }
        
        return f"{self.calendar_providers['yahoo']['base_url']}?{urlencode(params)}"
    
    async def generate_reminder_schedule(self, tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Generate reminder schedule for tournament events"""
        try:
            reg_start = datetime.fromisoformat(tournament['registrationStart'])
            reg_end = datetime.fromisoformat(tournament['registrationEnd'])
            tournament_start = datetime.fromisoformat(tournament['tournamentStart'])
            
            reminders = []
            
            # Registration opening reminders
            reminders.append({
                'type': 'registration_opening',
                'title': 'Registration Opens Soon!',
                'message': f"Registration for {tournament['title']} opens in 24 hours!",
                'scheduled_time': (reg_start - timedelta(days=1)).isoformat(),
                'channels': ['email', 'push']
            })
            
            reminders.append({
                'type': 'registration_opening',
                'title': 'Registration is Now Open!',
                'message': f"Registration for {tournament['title']} is now open! Secure your spot now.",
                'scheduled_time': reg_start.isoformat(),
                'channels': ['email', 'push', 'social']
            })
            
            # Registration closing reminders
            reminders.append({
                'type': 'registration_closing',
                'title': 'Last Chance to Register!',
                'message': f"Registration for {tournament['title']} closes in 24 hours!",
                'scheduled_time': (reg_end - timedelta(days=1)).isoformat(),
                'channels': ['email', 'push']
            })
            
            reminders.append({
                'type': 'registration_closing',
                'title': 'Registration Closes Soon!',
                'message': f"Only 2 hours left to register for {tournament['title']}!",
                'scheduled_time': (reg_end - timedelta(hours=2)).isoformat(),
                'channels': ['email', 'push']
            })
            
            # Tournament starting reminders
            reminders.append({
                'type': 'tournament_starting',
                'title': 'Tournament Starts Tomorrow!',
                'message': f"{tournament['title']} starts tomorrow! Make sure you're ready.",
                'scheduled_time': (tournament_start - timedelta(days=1)).isoformat(),
                'channels': ['email', 'push']
            })
            
            reminders.append({
                'type': 'tournament_starting',
                'title': 'Tournament Starting Soon!',
                'message': f"{tournament['title']} starts in 1 hour! Get ready to compete!",
                'scheduled_time': (tournament_start - timedelta(hours=1)).isoformat(),
                'channels': ['email', 'push', 'sms']
            })
            
            return {
                "success": True,
                "data": {
                    "tournament_id": tournament.get('_id'),
                    "reminders": reminders,
                    "total_reminders": len(reminders)
                },
                "message": "Reminder schedule generated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error generating reminder schedule: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to generate reminder schedule: {str(e)}"
            }


# Service instances
def get_social_media_service():
    """Get social media service instance"""
    return SocialMediaService()

def get_calendar_integration_service():
    """Get calendar integration service instance"""
    return CalendarIntegrationService()