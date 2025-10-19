"""
Content Moderation Service

This service handles automated content filtering, manual review queues,
and moderation workflows for tournaments.
"""

import re
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModerationStatus(Enum):
    """Moderation status enumeration"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    FLAGGED = "flagged"
    UNDER_REVIEW = "under_review"


class ModerationAction(Enum):
    """Moderation action enumeration"""
    APPROVE = "approve"
    REJECT = "reject"
    FLAG = "flag"
    REQUEST_CHANGES = "request_changes"
    ESCALATE = "escalate"


class ContentType(Enum):
    """Content type enumeration"""
    TOURNAMENT_TITLE = "tournament_title"
    TOURNAMENT_DESCRIPTION = "tournament_description"
    ORGANIZER_MESSAGE = "organizer_message"
    TEAM_NAME = "team_name"
    PLAYER_NAME = "player_name"


@dataclass
class ModerationResult:
    """Result of content moderation check"""
    is_approved: bool
    confidence_score: float
    flagged_content: List[str]
    suggested_action: ModerationAction
    reason: str
    requires_manual_review: bool = False


@dataclass
class ModerationRule:
    """Content moderation rule"""
    rule_id: str
    name: str
    pattern: str
    content_types: List[ContentType]
    severity: str  # low, medium, high, critical
    action: ModerationAction
    is_active: bool = True


class ContentModerationService:
    """Service for automated content filtering and moderation"""
    
    def __init__(self):
        self.moderation_rules = self._load_moderation_rules()
        self.banned_words = self._load_banned_words()

        
    def _load_moderation_rules(self) -> List[ModerationRule]:
        """Load content moderation rules"""
        return [
            # Profanity and inappropriate content
            ModerationRule(
                rule_id="profanity_basic",
                name="Basic Profanity Filter",
                pattern=r'\b(fuck|shit|damn|hell|ass|bitch|bastard|crap)\b',
                content_types=[ContentType.TOURNAMENT_TITLE, ContentType.TOURNAMENT_DESCRIPTION],
                severity="medium",
                action=ModerationAction.FLAG
            ),
            ModerationRule(
                rule_id="profanity_severe",
                name="Severe Profanity Filter",
                pattern=r'\b(nigger|faggot|retard|cunt|whore|slut)\b',
                content_types=[ContentType.TOURNAMENT_TITLE, ContentType.TOURNAMENT_DESCRIPTION, ContentType.TEAM_NAME],
                severity="critical",
                action=ModerationAction.REJECT
            ),
            
            # Hate speech and discrimination
            ModerationRule(
                rule_id="hate_speech",
                name="Hate Speech Detection",
                pattern=r'\b(nazi|hitler|kill\s+(all|jews|blacks|muslims)|white\s+power|heil)\b',
                content_types=[ContentType.TOURNAMENT_TITLE, ContentType.TOURNAMENT_DESCRIPTION],
                severity="critical",
                action=ModerationAction.REJECT
            ),
            
            # Spam and promotional content
            ModerationRule(
                rule_id="spam_urls",
                name="Spam URL Detection",
                pattern=r'(https?://(?!(?:www\.)?(?:twitch\.tv|youtube\.com|discord\.gg))[^\s]+)',
                content_types=[ContentType.TOURNAMENT_DESCRIPTION],
                severity="medium",
                action=ModerationAction.FLAG
            ),
            ModerationRule(
                rule_id="excessive_caps",
                name="Excessive Capitalization",
                pattern=r'^[A-Z\s]{20,}$',
                content_types=[ContentType.TOURNAMENT_TITLE],
                severity="low",
                action=ModerationAction.FLAG
            ),
            
            # Scam and fraud detection
            ModerationRule(
                rule_id="money_scam",
                name="Money Scam Detection",
                pattern=r'\b(free\s+money|guaranteed\s+win|100%\s+win\s+rate|easy\s+cash|get\s+rich)\b',
                content_types=[ContentType.TOURNAMENT_DESCRIPTION],
                severity="high",
                action=ModerationAction.REJECT
            ),
            
            # Gaming-specific inappropriate content
            ModerationRule(
                rule_id="cheating_promotion",
                name="Cheating Promotion",
                pattern=r'\b(hack|cheat|aimbot|wallhack|esp|mod\s+menu|free\s+hacks)\b',
                content_types=[ContentType.TOURNAMENT_DESCRIPTION],
                severity="high",
                action=ModerationAction.REJECT
            ),
            
            # Personal information exposure
            ModerationRule(
                rule_id="personal_info",
                name="Personal Information Exposure",
                pattern=r'\b(\d{3}-\d{2}-\d{4}|\d{16}|\+\d{1,3}\s?\d{10})\b',
                content_types=[ContentType.TOURNAMENT_DESCRIPTION],
                severity="medium",
                action=ModerationAction.FLAG
            )
        ]
    
    def _load_banned_words(self) -> set:
        """Load banned words list"""
        return {
            # Basic profanity
            'fuck', 'shit', 'damn', 'hell', 'ass', 'bitch', 'bastard', 'crap',
            # Severe profanity
            'nigger', 'faggot', 'retard', 'cunt', 'whore', 'slut',
            # Hate speech
            'nazi', 'hitler', 'heil',
            # Gaming cheats
            'aimbot', 'wallhack', 'esp',
            # Scam terms
            'free money', 'guaranteed win', 'easy cash'
        }
    
    async def moderate_content(self, content: str, content_type: ContentType) -> ModerationResult:
        """
        Moderate content using automated rules and ML-based detection
        
        Args:
            content: Content to moderate
            content_type: Type of content being moderated
            
        Returns:
            ModerationResult with approval status and details
        """
        try:
            
            # Normalize content for analysis
            normalized_content = self._normalize_content(content)
            
            # Apply moderation rules
            rule_violations = []
            highest_severity = "low"
            suggested_action = ModerationAction.APPROVE
            
            for rule in self.moderation_rules:
                if not rule.is_active or content_type not in rule.content_types:
                    continue
                    
                if re.search(rule.pattern, normalized_content, re.IGNORECASE):
                    rule_violations.append({
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'action': rule.action
                    })
                    
                    # Update highest severity and suggested action
                    if self._get_severity_level(rule.severity) > self._get_severity_level(highest_severity):
                        highest_severity = rule.severity
                        suggested_action = rule.action
            
            # Calculate confidence score based on violations
            confidence_score = self._calculate_confidence_score(rule_violations, content)
            
            # Determine if manual review is required
            requires_manual_review = (
                highest_severity in ["high", "critical"] or
                len(rule_violations) >= 3 or
                confidence_score < 0.7
            )
            
            # Determine approval status
            is_approved = (
                len(rule_violations) == 0 or
                (highest_severity == "low" and not requires_manual_review)
            )
            
            # Generate reason
            if len(rule_violations) == 0:
                reason = "Content passed all moderation checks"
            else:
                violated_rules = [v['name'] for v in rule_violations]
                reason = f"Content flagged for: {', '.join(violated_rules)}"
            
            return ModerationResult(
                is_approved=is_approved,
                confidence_score=confidence_score,
                flagged_content=[v['name'] for v in rule_violations],
                suggested_action=suggested_action,
                reason=reason,
                requires_manual_review=requires_manual_review
            )
            
        except Exception as e:
            logger.error(f"Error in content moderation: {e}")
            # Fail safe - require manual review on error
            return ModerationResult(
                is_approved=False,
                confidence_score=0.0,
                flagged_content=["System Error"],
                suggested_action=ModerationAction.FLAG,
                reason=f"Moderation system error: {str(e)}",
                requires_manual_review=True
            )
    
    def _normalize_content(self, content: str) -> str:
        """Normalize content for consistent analysis"""
        # Convert to lowercase
        normalized = content.lower()
        
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        # Handle common character substitutions used to bypass filters
        substitutions = {
            '@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's',
            '$': 's', '7': 't', '4': 'a', '!': 'i'
        }
        
        for char, replacement in substitutions.items():
            normalized = normalized.replace(char, replacement)
        
        return normalized
    
    def _get_severity_level(self, severity: str) -> int:
        """Convert severity string to numeric level for comparison"""
        levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return levels.get(severity, 0)
    
    def _calculate_confidence_score(self, violations: List[Dict], content: str) -> float:
        """Calculate confidence score for moderation decision"""
        if not violations:
            return 0.95  # High confidence for clean content
        
        # Base score starts high and decreases with violations
        base_score = 0.9
        
        # Penalty for each violation based on severity
        severity_penalties = {"low": 0.1, "medium": 0.2, "high": 0.3, "critical": 0.5}
        
        total_penalty = 0
        for violation in violations:
            penalty = severity_penalties.get(violation['severity'], 0.1)
            total_penalty += penalty
        
        # Additional penalty for multiple violations
        if len(violations) > 1:
            total_penalty += 0.1 * (len(violations) - 1)
        
        # Content length factor (shorter content with violations is more suspicious)
        if len(content) < 50 and violations:
            total_penalty += 0.1
        
        confidence_score = max(0.0, base_score - total_penalty)
        return min(1.0, confidence_score)
    

    
    async def moderate_tournament_content(self, tournament_data: Dict[str, Any]) -> Dict[str, ModerationResult]:
        """
        Moderate all content in a tournament submission
        
        Args:
            tournament_data: Tournament data to moderate
            
        Returns:
            Dictionary of moderation results for each content field
        """
        results = {}
        
        # Moderate title
        if 'title' in tournament_data:
            results['title'] = await self.moderate_content(
                tournament_data['title'], 
                ContentType.TOURNAMENT_TITLE
            )
        
        # Moderate description
        if 'description' in tournament_data:
            results['description'] = await self.moderate_content(
                tournament_data['description'], 
                ContentType.TOURNAMENT_DESCRIPTION
            )
        
        return results
    
    def get_overall_moderation_status(self, moderation_results: Dict[str, ModerationResult]) -> Tuple[bool, str]:
        """
        Determine overall moderation status from individual field results
        
        Args:
            moderation_results: Dictionary of moderation results
            
        Returns:
            Tuple of (is_approved, reason)
        """
        if not moderation_results:
            return True, "No content to moderate"
        
        # Check if any field requires manual review
        requires_review = any(result.requires_manual_review for result in moderation_results.values())
        
        # Check if any field is rejected
        has_rejections = any(not result.is_approved and result.suggested_action == ModerationAction.REJECT 
                           for result in moderation_results.values())
        
        # Check if any field is flagged
        has_flags = any(not result.is_approved and result.suggested_action == ModerationAction.FLAG 
                       for result in moderation_results.values())
        
        if has_rejections:
            rejected_fields = [field for field, result in moderation_results.items() 
                             if not result.is_approved and result.suggested_action == ModerationAction.REJECT]
            return False, f"Content rejected in fields: {', '.join(rejected_fields)}"
        
        if requires_review or has_flags:
            flagged_fields = [field for field, result in moderation_results.items() 
                            if result.requires_manual_review or result.suggested_action == ModerationAction.FLAG]
            return False, f"Content requires manual review in fields: {', '.join(flagged_fields)}"
        
        return True, "All content approved"


class ModerationQueue:
    """Manages the manual review queue for flagged content"""
    
    def __init__(self):
        self.queue = []  # In production, this would be a database
        self.processing = {}  # Track items being processed
    
    async def add_to_queue(self, tournament_id: str, 
                          moderation_results: Dict[str, ModerationResult], 
                          priority: str = "normal") -> str:
        """
        Add tournament to manual review queue
        
        Args:
            tournament_id: ID of the tournament
            moderation_results: Results from automated moderation
            priority: Priority level (low, normal, high, urgent)
            
        Returns:
            Queue item ID
        """
        queue_item_id = f"queue_{int(datetime.utcnow().timestamp())}_{tournament_id}"
        
        queue_item = {
            'id': queue_item_id,
            'tournament_id': tournament_id,
            'moderation_results': moderation_results,
            'priority': priority,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'assigned_to': None,
            'reviewed_at': None,
            'reviewer_notes': None
        }
        
        # Insert based on priority
        priority_levels = {"urgent": 0, "high": 1, "normal": 2, "low": 3}
        priority_level = priority_levels.get(priority, 2)
        
        # Find insertion point based on priority
        insert_index = 0
        for i, item in enumerate(self.queue):
            item_priority = priority_levels.get(item['priority'], 2)
            if priority_level <= item_priority:
                insert_index = i
                break
            insert_index = i + 1
        
        self.queue.insert(insert_index, queue_item)
        
        logger.info(f"Added tournament {tournament_id} to moderation queue with priority {priority}")
        return queue_item_id
    
    async def get_next_item(self, reviewer_id: str) -> Optional[Dict[str, Any]]:
        """Get next item from queue for review"""
        for item in self.queue:
            if item['status'] == 'pending':
                item['status'] = 'in_review'
                item['assigned_to'] = reviewer_id
                self.processing[item['id']] = item
                return item
        
        return None
    
    async def complete_review(self, queue_item_id: str, reviewer_id: str, 
                            action: ModerationAction, notes: str = "") -> bool:
        """
        Complete manual review of queue item
        
        Args:
            queue_item_id: ID of the queue item
            reviewer_id: ID of the reviewer
            action: Moderation action taken
            notes: Reviewer notes
            
        Returns:
            Success status
        """
        # Find item in processing
        if queue_item_id not in self.processing:
            return False
        
        item = self.processing[queue_item_id]
        
        # Verify reviewer
        if item['assigned_to'] != reviewer_id:
            return False
        
        # Update item
        item['status'] = 'completed'
        item['action'] = action.value
        item['reviewer_notes'] = notes
        item['reviewed_at'] = datetime.utcnow().isoformat()
        
        # Remove from processing and queue
        del self.processing[queue_item_id]
        self.queue = [i for i in self.queue if i['id'] != queue_item_id]
        
        logger.info(f"Completed review for queue item {queue_item_id} with action {action.value}")
        return True
    
    async def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status"""
        return {
            'total_items': len(self.queue),
            'pending_items': len([i for i in self.queue if i['status'] == 'pending']),
            'in_review_items': len([i for i in self.queue if i['status'] == 'in_review']),
            'queue_items': self.queue[:10]  # Return first 10 items
        }


# Global service instances
content_moderation_service = ContentModerationService()
moderation_queue = ModerationQueue()


async def moderate_tournament_submission(tournament_data: Dict[str, Any]) -> Tuple[bool, str, Optional[str]]:
    """
    Moderate a tournament submission
    
    Args:
        tournament_data: Tournament data to moderate
        
    Returns:
        Tuple of (is_approved, reason, queue_item_id)
    """
    try:
        # Run automated moderation
        moderation_results = await content_moderation_service.moderate_tournament_content(
            tournament_data
        )
        
        # Get overall status
        is_approved, reason = content_moderation_service.get_overall_moderation_status(moderation_results)
        
        # If not approved, add to manual review queue
        queue_item_id = None
        if not is_approved:
            # Determine priority based on severity
            has_critical = any(
                result.suggested_action == ModerationAction.REJECT 
                for result in moderation_results.values()
            )
            priority = "high" if has_critical else "normal"
            
            queue_item_id = await moderation_queue.add_to_queue(
                tournament_data.get('id', 'unknown'),
                moderation_results,
                priority
            )
        
        return is_approved, reason, queue_item_id
        
    except Exception as e:
        logger.error(f"Error in tournament moderation: {e}")
        return False, f"Moderation system error: {str(e)}", None


def get_content_moderation_service() -> ContentModerationService:
    """Get the global content moderation service instance"""
    return content_moderation_service


def get_moderation_queue() -> ModerationQueue:
    """Get the global moderation queue instance"""
    return moderation_queue