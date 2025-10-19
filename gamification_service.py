"""
Gamification and Engagement Service

This service handles participant badges, achievement systems, loyalty
rewards, and tournament discovery recommendations.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from bson import ObjectId

logger = logging.getLogger(__name__)


class BadgeSystem:
    """Badge and achievement system for participants"""
    
    def __init__(self, db):
        self.db = db
        self.badges_collection = db.user_badges
        self.achievements_collection = db.user_achievements
        
        # Define badge types and requirements
        self.organizer_badges = {
            'first_tournament': {
                'name': 'Tournament Pioneer',
                'description': 'Organized your first tournament',
                'icon': 'fas fa-flag',
                'color': '#28a745',
                'requirement': 'tournaments_organized >= 1'
            },
            'veteran_organizer': {
                'name': 'Veteran Organizer',
                'description': 'Organized 10 tournaments',
                'icon': 'fas fa-medal',
                'color': '#ffc107',
                'requirement': 'tournaments_organized >= 10'
            },
            'tournament_master': {
                'name': 'Tournament Master',
                'description': 'Organized 50 tournaments',
                'icon': 'fas fa-crown',
                'color': '#dc3545',
                'requirement': 'tournaments_organized >= 50'
            },
            'crowd_pleaser': {
                'name': 'Crowd Pleaser',
                'description': 'Average rating above 4.5 stars',
                'icon': 'fas fa-star',
                'color': '#007bff',
                'requirement': 'average_rating >= 4.5 and total_ratings >= 10'
            },
            'big_league': {
                'name': 'Big League',
                'description': 'Organized tournament with 100+ participants',
                'icon': 'fas fa-users',
                'color': '#6f42c1',
                'requirement': 'max_participants >= 100'
            },
            'prize_master': {
                'name': 'Prize Master',
                'description': 'Total prize pools exceed $10,000',
                'icon': 'fas fa-trophy',
                'color': '#fd7e14',
                'requirement': 'total_prize_pool >= 10000'
            },
            'consistent_organizer': {
                'name': 'Consistent Organizer',
                'description': 'Organized tournaments for 6 consecutive months',
                'icon': 'fas fa-calendar-check',
                'color': '#20c997',
                'requirement': 'consecutive_months >= 6'
            },
            'community_builder': {
                'name': 'Community Builder',
                'description': 'Total participants across all tournaments exceed 1000',
                'icon': 'fas fa-handshake',
                'color': '#e83e8c',
                'requirement': 'total_participants >= 1000'
            }
        }
        
        self.participant_badges = {
            'first_tournament': {
                'name': 'Tournament Rookie',
                'description': 'Participated in your first tournament',
                'icon': 'fas fa-play',
                'color': '#28a745',
                'requirement': 'tournaments_participated >= 1'
            },
            'tournament_veteran': {
                'name': 'Tournament Veteran',
                'description': 'Participated in 25 tournaments',
                'icon': 'fas fa-shield-alt',
                'color': '#ffc107',
                'requirement': 'tournaments_participated >= 25'
            },
            'champion': {
                'name': 'Champion',
                'description': 'Won your first tournament',
                'icon': 'fas fa-trophy',
                'color': '#dc3545',
                'requirement': 'tournaments_won >= 1'
            },
            'serial_winner': {
                'name': 'Serial Winner',
                'description': 'Won 5 tournaments',
                'icon': 'fas fa-crown',
                'color': '#6f42c1',
                'requirement': 'tournaments_won >= 5'
            },
            'loyal_participant': {
                'name': 'Loyal Participant',
                'description': 'Participated in tournaments for 12 months',
                'icon': 'fas fa-heart',
                'color': '#e83e8c',
                'requirement': 'participation_months >= 12'
            },
            'early_bird': {
                'name': 'Early Bird',
                'description': 'Registered early for 10 tournaments',
                'icon': 'fas fa-clock',
                'color': '#17a2b8',
                'requirement': 'early_registrations >= 10'
            },
            'social_butterfly': {
                'name': 'Social Butterfly',
                'description': 'Shared 20 tournaments on social media',
                'icon': 'fas fa-share-alt',
                'color': '#fd7e14',
                'requirement': 'social_shares >= 20'
            }
        }
    
    async def check_and_award_badges(self, user_id: str, user_type: str = 'participant') -> Dict[str, Any]:
        """Check and award new badges to a user"""
        try:
            # Get user statistics
            user_stats = await self._get_user_statistics(user_id, user_type)
            
            # Get current badges
            current_badges = await self._get_user_badges(user_id)
            current_badge_ids = [badge['badge_id'] for badge in current_badges]
            
            # Check for new badges
            badge_definitions = self.organizer_badges if user_type == 'organizer' else self.participant_badges
            new_badges = []
            
            for badge_id, badge_info in badge_definitions.items():
                if badge_id not in current_badge_ids:
                    if self._check_badge_requirement(badge_info['requirement'], user_stats):
                        # Award new badge
                        badge_record = {
                            'userId': user_id,
                            'badgeId': badge_id,
                            'badgeName': badge_info['name'],
                            'badgeDescription': badge_info['description'],
                            'badgeIcon': badge_info['icon'],
                            'badgeColor': badge_info['color'],
                            'userType': user_type,
                            'awardedAt': datetime.utcnow().isoformat(),
                            'isNew': True
                        }
                        
                        self.badges_collection.insert_one(badge_record)
                        new_badges.append(badge_record)
                        
                        logger.info(f"Awarded badge '{badge_info['name']}' to user {user_id}")
            
            return {
                "success": True,
                "data": {
                    "new_badges": new_badges,
                    "total_badges": len(current_badges) + len(new_badges)
                },
                "message": f"Awarded {len(new_badges)} new badges"
            }
            
        except Exception as e:
            logger.error(f"Error checking badges for user {user_id}: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to check badges: {str(e)}"
            }
    
    async def _get_user_statistics(self, user_id: str, user_type: str) -> Dict[str, Any]:
        """Get user statistics for badge evaluation"""
        try:
            if user_type == 'organizer':
                # Get organizer statistics
                tournaments = list(self.db.user_tournaments.find({"organizerId": user_id}))
                reputation = self.db.organizer_reputation.find_one({"organizerId": user_id}) or {}
                
                stats = {
                    'tournaments_organized': len(tournaments),
                    'average_rating': reputation.get('averageRating', 0),
                    'total_ratings': reputation.get('totalRatings', 0),
                    'max_participants': max([t.get('maxTeams', 0) for t in tournaments] + [0]),
                    'total_prize_pool': sum([t.get('prizePool', 0) for t in tournaments]),
                    'total_participants': sum([len(t.get('participants', [])) for t in tournaments]),
                    'consecutive_months': self._calculate_consecutive_months(tournaments)
                }
            else:
                # Get participant statistics
                # This would typically come from a user_participation collection
                # For now, using mock data
                stats = {
                    'tournaments_participated': 0,
                    'tournaments_won': 0,
                    'participation_months': 0,
                    'early_registrations': 0,
                    'social_shares': 0
                }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting user statistics: {str(e)}")
            return {}
    
    def _calculate_consecutive_months(self, tournaments: List[Dict]) -> int:
        """Calculate consecutive months of tournament organization"""
        if not tournaments:
            return 0
        
        # Sort tournaments by creation date
        sorted_tournaments = sorted(tournaments, key=lambda x: x.get('createdAt', ''))
        
        # Group by month
        months = set()
        for tournament in sorted_tournaments:
            created_at = datetime.fromisoformat(tournament.get('createdAt', ''))
            month_key = f"{created_at.year}-{created_at.month:02d}"
            months.add(month_key)
        
        # Calculate consecutive months
        sorted_months = sorted(list(months))
        consecutive = 1
        max_consecutive = 1
        
        for i in range(1, len(sorted_months)):
            current = datetime.strptime(sorted_months[i], "%Y-%m")
            previous = datetime.strptime(sorted_months[i-1], "%Y-%m")
            
            # Check if months are consecutive
            if (current.year == previous.year and current.month == previous.month + 1) or \
               (current.year == previous.year + 1 and current.month == 1 and previous.month == 12):
                consecutive += 1
                max_consecutive = max(max_consecutive, consecutive)
            else:
                consecutive = 1
        
        return max_consecutive
    
    def _check_badge_requirement(self, requirement: str, stats: Dict[str, Any]) -> bool:
        """Check if badge requirement is met"""
        try:
            # Replace variable names with actual values
            for key, value in stats.items():
                requirement = requirement.replace(key, str(value))
            
            # Evaluate the requirement expression
            return eval(requirement)
        except Exception as e:
            logger.error(f"Error evaluating badge requirement '{requirement}': {str(e)}")
            return False
    
    async def _get_user_badges(self, user_id: str) -> List[Dict[str, Any]]:
        """Get current user badges"""
        try:
            badges = list(self.badges_collection.find({"userId": user_id}))
            return badges
        except Exception as e:
            logger.error(f"Error getting user badges: {str(e)}")
            return []
    
    async def get_user_badges(self, user_id: str) -> Dict[str, Any]:
        """Get all badges for a user"""
        try:
            badges = await self._get_user_badges(user_id)
            
            # Mark badges as viewed (remove isNew flag)
            self.badges_collection.update_many(
                {"userId": user_id, "isNew": True},
                {"$unset": {"isNew": ""}}
            )
            
            return {
                "success": True,
                "data": {
                    "badges": badges,
                    "total_badges": len(badges)
                },
                "message": "User badges retrieved successfully"
            }
            
        except Exception as e:
            logger.error(f"Error getting user badges: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to get user badges: {str(e)}"
            }


class LoyaltyRewardSystem:
    """Loyalty and engagement reward system"""
    
    def __init__(self, db):
        self.db = db
        self.loyalty_collection = db.user_loyalty
        self.rewards_collection = db.loyalty_rewards
        
        # Define reward tiers and benefits
        self.loyalty_tiers = {
            'bronze': {
                'name': 'Bronze Member',
                'points_required': 0,
                'benefits': ['Basic tournament access', 'Email notifications'],
                'color': '#cd7f32',
                'icon': 'fas fa-medal'
            },
            'silver': {
                'name': 'Silver Member',
                'points_required': 500,
                'benefits': ['Priority registration', '5% hosting fee discount', 'Early access to features'],
                'color': '#c0c0c0',
                'icon': 'fas fa-medal'
            },
            'gold': {
                'name': 'Gold Member',
                'points_required': 1500,
                'benefits': ['VIP support', '10% hosting fee discount', 'Custom tournament themes'],
                'color': '#ffd700',
                'icon': 'fas fa-crown'
            },
            'platinum': {
                'name': 'Platinum Member',
                'points_required': 3000,
                'benefits': ['Premium features', '15% hosting fee discount', 'Dedicated account manager'],
                'color': '#e5e4e2',
                'icon': 'fas fa-gem'
            },
            'diamond': {
                'name': 'Diamond Member',
                'points_required': 5000,
                'benefits': ['All premium features', '20% hosting fee discount', 'Beta access', 'Custom branding'],
                'color': '#b9f2ff',
                'icon': 'fas fa-diamond'
            }
        }
        
        # Point earning activities
        self.point_activities = {
            'tournament_participation': 50,
            'tournament_completion': 100,
            'tournament_win': 200,
            'tournament_organization': 300,
            'successful_tournament': 500,
            'high_rating_received': 150,
            'social_media_share': 25,
            'referral_signup': 250,
            'early_registration': 75,
            'feedback_submission': 50,
            'community_contribution': 100
        }
    
    async def award_loyalty_points(self, user_id: str, activity: str, multiplier: float = 1.0, metadata: Dict = None) -> Dict[str, Any]:
        """Award loyalty points for user activity"""
        try:
            if activity not in self.point_activities:
                return {
                    "success": False,
                    "message": f"Unknown activity: {activity}"
                }
            
            base_points = self.point_activities[activity]
            points_awarded = int(base_points * multiplier)
            
            # Get or create user loyalty record
            loyalty_record = self.loyalty_collection.find_one({"userId": user_id})
            if not loyalty_record:
                loyalty_record = {
                    "userId": user_id,
                    "totalPoints": 0,
                    "currentTier": "bronze",
                    "pointsHistory": [],
                    "createdAt": datetime.utcnow().isoformat(),
                    "updatedAt": datetime.utcnow().isoformat()
                }
            
            # Add points
            new_total = loyalty_record["totalPoints"] + points_awarded
            
            # Check for tier upgrade
            new_tier = self._calculate_tier(new_total)
            tier_upgraded = new_tier != loyalty_record["currentTier"]
            
            # Create point history entry
            history_entry = {
                "activity": activity,
                "pointsAwarded": points_awarded,
                "multiplier": multiplier,
                "metadata": metadata or {},
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Update loyalty record
            loyalty_record["totalPoints"] = new_total
            loyalty_record["currentTier"] = new_tier
            loyalty_record["pointsHistory"].append(history_entry)
            loyalty_record["updatedAt"] = datetime.utcnow().isoformat()
            
            # Save to database
            await self.loyalty_collection.replace_one(
                {"userId": user_id},
                loyalty_record,
                upsert=True
            )
            
            # Check and award badges if tier upgraded
            if tier_upgraded:
                await self._award_tier_badge(user_id, new_tier)
            
            logger.info(f"Awarded {points_awarded} points to user {user_id} for {activity}")
            
            return {
                "success": True,
                "data": {
                    "points_awarded": points_awarded,
                    "total_points": new_total,
                    "current_tier": new_tier,
                    "tier_upgraded": tier_upgraded,
                    "next_tier_points": self._get_next_tier_points(new_tier)
                },
                "message": f"Awarded {points_awarded} loyalty points"
            }
            
        except Exception as e:
            logger.error(f"Error awarding loyalty points: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to award loyalty points: {str(e)}"
            }
    
    def _calculate_tier(self, total_points: int) -> str:
        """Calculate loyalty tier based on total points"""
        for tier_id in reversed(list(self.loyalty_tiers.keys())):
            if total_points >= self.loyalty_tiers[tier_id]['points_required']:
                return tier_id
        return 'bronze'
    
    def _get_next_tier_points(self, current_tier: str) -> Optional[int]:
        """Get points required for next tier"""
        tier_keys = list(self.loyalty_tiers.keys())
        try:
            current_index = tier_keys.index(current_tier)
            if current_index < len(tier_keys) - 1:
                next_tier = tier_keys[current_index + 1]
                return self.loyalty_tiers[next_tier]['points_required']
        except ValueError:
            pass
        return None
    
    async def _award_tier_badge(self, user_id: str, tier: str):
        """Award badge for reaching new tier"""
        try:
            badge_record = {
                'userId': user_id,
                'badgeId': f'loyalty_{tier}',
                'badgeName': f'{self.loyalty_tiers[tier]["name"]} Achieved',
                'badgeDescription': f'Reached {self.loyalty_tiers[tier]["name"]} loyalty tier',
                'badgeIcon': self.loyalty_tiers[tier]['icon'],
                'badgeColor': self.loyalty_tiers[tier]['color'],
                'userType': 'loyalty',
                'awardedAt': datetime.utcnow().isoformat(),
                'isNew': True
            }
            
            self.db.user_badges.insert_one(badge_record)
            logger.info(f"Awarded {tier} tier badge to user {user_id}")
            
        except Exception as e:
            logger.error(f"Error awarding tier badge: {str(e)}")
    
    async def get_user_loyalty_status(self, user_id: str) -> Dict[str, Any]:
        """Get user's loyalty status and benefits"""
        try:
            loyalty_record = self.loyalty_collection.find_one({"userId": user_id})
            
            if not loyalty_record:
                # Create default record
                loyalty_record = {
                    "userId": user_id,
                    "totalPoints": 0,
                    "currentTier": "bronze",
                    "pointsHistory": [],
                    "createdAt": datetime.utcnow().isoformat(),
                    "updatedAt": datetime.utcnow().isoformat()
                }
                self.loyalty_collection.insert_one(loyalty_record)
            
            current_tier = loyalty_record["currentTier"]
            tier_info = self.loyalty_tiers[current_tier]
            next_tier_points = self._get_next_tier_points(current_tier)
            
            return {
                "success": True,
                "data": {
                    "total_points": loyalty_record["totalPoints"],
                    "current_tier": {
                        "id": current_tier,
                        "name": tier_info["name"],
                        "color": tier_info["color"],
                        "icon": tier_info["icon"],
                        "benefits": tier_info["benefits"]
                    },
                    "next_tier_points": next_tier_points,
                    "points_to_next_tier": next_tier_points - loyalty_record["totalPoints"] if next_tier_points else 0,
                    "recent_activities": loyalty_record["pointsHistory"][-10:],  # Last 10 activities
                    "all_tiers": self.loyalty_tiers
                },
                "message": "Loyalty status retrieved successfully"
            }
            
        except Exception as e:
            logger.error(f"Error getting loyalty status: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to get loyalty status: {str(e)}"
            }


class RecommendationEngine:
    """Tournament discovery recommendation system"""
    
    def __init__(self, db):
        self.db = db
        self.user_preferences_collection = db.user_preferences
        self.user_interactions_collection = db.user_interactions
    
    async def get_tournament_recommendations(self, user_id: str, limit: int = 10) -> Dict[str, Any]:
        """Get personalized tournament recommendations"""
        try:
            # Get user preferences and interaction history
            user_preferences = await self._get_user_preferences(user_id)
            interaction_history = await self._get_user_interactions(user_id)
            
            # Get all active tournaments
            active_tournaments = list(self.db.user_tournaments.find({
                "status": {"$in": ["active", "registration_open"]},
                "organizerId": {"$ne": user_id}  # Don't recommend user's own tournaments
            }))
            
            # Score tournaments based on user preferences
            scored_tournaments = []
            for tournament in active_tournaments:
                score = await self._calculate_tournament_score(tournament, user_preferences, interaction_history)
                scored_tournaments.append({
                    "tournament": tournament,
                    "score": score,
                    "reasons": self._get_recommendation_reasons(tournament, user_preferences, score)
                })
            
            # Sort by score and limit results
            scored_tournaments.sort(key=lambda x: x["score"], reverse=True)
            recommendations = scored_tournaments[:limit]
            
            return {
                "success": True,
                "data": {
                    "recommendations": recommendations,
                    "total_available": len(active_tournaments),
                    "user_preferences": user_preferences
                },
                "message": f"Generated {len(recommendations)} tournament recommendations"
            }
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to generate recommendations: {str(e)}"
            }
    
    async def _get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get user preferences for recommendations"""
        try:
            preferences = self.user_preferences_collection.find_one({"userId": user_id})
            
            if not preferences:
                # Create default preferences based on user activity
                preferences = await self._create_default_preferences(user_id)
            
            return preferences
            
        except Exception as e:
            logger.error(f"Error getting user preferences: {str(e)}")
            return {}
    
    async def _create_default_preferences(self, user_id: str) -> Dict[str, Any]:
        """Create default preferences based on user activity"""
        try:
            # Analyze user's tournament participation history
            # This would typically look at tournaments the user has joined
            # For now, creating basic default preferences
            
            default_preferences = {
                "userId": user_id,
                "preferredGames": [],
                "preferredFormats": [],
                "preferredEntryFeeRange": {"min": 0, "max": 100},
                "preferredPrizePools": {"min": 0, "max": 10000},
                "preferredTournamentSizes": {"min": 8, "max": 64},
                "preferredVenueTypes": ["online", "hybrid"],
                "preferredTimeSlots": [],
                "followedOrganizers": [],
                "interests": [],
                "createdAt": datetime.utcnow().isoformat(),
                "updatedAt": datetime.utcnow().isoformat()
            }
            
            self.user_preferences_collection.insert_one(default_preferences)
            return default_preferences
            
        except Exception as e:
            logger.error(f"Error creating default preferences: {str(e)}")
            return {}
    
    async def _get_user_interactions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get user interaction history"""
        try:
            interactions = list(self.user_interactions_collection.find(
                {"userId": user_id},
                sort=[("timestamp", -1)],
                limit=100
            ))
            return interactions
        except Exception as e:
            logger.error(f"Error getting user interactions: {str(e)}")
            return []
    
    async def _calculate_tournament_score(self, tournament: Dict, preferences: Dict, interactions: List[Dict]) -> float:
        """Calculate recommendation score for a tournament"""
        try:
            score = 0.0
            
            # Game preference scoring
            if tournament.get("game") in preferences.get("preferredGames", []):
                score += 30
            
            # Format preference scoring
            if tournament.get("format") in preferences.get("preferredFormats", []):
                score += 20
            
            # Entry fee preference scoring
            entry_fee = tournament.get("entryFee", 0)
            fee_range = preferences.get("preferredEntryFeeRange", {"min": 0, "max": 100})
            if fee_range["min"] <= entry_fee <= fee_range["max"]:
                score += 15
            
            # Prize pool preference scoring
            prize_pool = tournament.get("prizePool", 0)
            prize_range = preferences.get("preferredPrizePools", {"min": 0, "max": 10000})
            if prize_range["min"] <= prize_pool <= prize_range["max"]:
                score += 15
            
            # Tournament size preference scoring
            max_teams = tournament.get("maxTeams", 0)
            size_range = preferences.get("preferredTournamentSizes", {"min": 8, "max": 64})
            if size_range["min"] <= max_teams <= size_range["max"]:
                score += 10
            
            # Venue type preference scoring
            venue_type = tournament.get("venueType", "online")
            if venue_type in preferences.get("preferredVenueTypes", []):
                score += 10
            
            # Organizer reputation scoring
            organizer_rating = tournament.get("organizerRating", 0)
            score += organizer_rating * 5  # Up to 25 points for 5-star organizer
            
            # Followed organizer bonus
            if tournament.get("organizerId") in preferences.get("followedOrganizers", []):
                score += 25
            
            # Recent interaction bonus
            recent_games = [i.get("game") for i in interactions[-10:] if i.get("game")]
            if tournament.get("game") in recent_games:
                score += 10
            
            # Registration urgency scoring
            reg_end = datetime.fromisoformat(tournament.get("registrationEnd", ""))
            days_until_close = (reg_end - datetime.utcnow()).days
            if days_until_close <= 3:
                score += 15  # Bonus for tournaments closing soon
            
            # Popularity scoring (based on current participants)
            participants = len(tournament.get("participants", []))
            max_teams = tournament.get("maxTeams", 1)
            fill_rate = participants / max_teams if max_teams > 0 else 0
            if 0.3 <= fill_rate <= 0.8:  # Sweet spot - not too empty, not too full
                score += 10
            
            return max(0, score)  # Ensure non-negative score
            
        except Exception as e:
            logger.error(f"Error calculating tournament score: {str(e)}")
            return 0.0
    
    def _get_recommendation_reasons(self, tournament: Dict, preferences: Dict, score: float) -> List[str]:
        """Get reasons why this tournament was recommended"""
        reasons = []
        
        if tournament.get("game") in preferences.get("preferredGames", []):
            reasons.append(f"You enjoy {tournament.get('game')} tournaments")
        
        if tournament.get("format") in preferences.get("preferredFormats", []):
            reasons.append(f"Matches your preferred {tournament.get('format')} format")
        
        if tournament.get("organizerId") in preferences.get("followedOrganizers", []):
            reasons.append("Organized by someone you follow")
        
        organizer_rating = tournament.get("organizerRating", 0)
        if organizer_rating >= 4.5:
            reasons.append(f"Highly rated organizer ({organizer_rating:.1f}/5.0)")
        
        prize_pool = tournament.get("prizePool", 0)
        if prize_pool > 1000:
            reasons.append(f"Large prize pool (${prize_pool:,.2f})")
        
        # Registration urgency
        try:
            reg_end = datetime.fromisoformat(tournament.get("registrationEnd", ""))
            days_until_close = (reg_end - datetime.utcnow()).days
            if days_until_close <= 3:
                reasons.append("Registration closes soon")
        except:
            pass
        
        # Popularity
        participants = len(tournament.get("participants", []))
        max_teams = tournament.get("maxTeams", 1)
        fill_rate = participants / max_teams if max_teams > 0 else 0
        if fill_rate >= 0.5:
            reasons.append("Popular tournament - filling up fast")
        
        if not reasons:
            reasons.append("Recommended based on your activity")
        
        return reasons[:3]  # Limit to top 3 reasons
    
    async def record_user_interaction(self, user_id: str, interaction_type: str, tournament_id: str = None, metadata: Dict = None) -> Dict[str, Any]:
        """Record user interaction for improving recommendations"""
        try:
            interaction = {
                "userId": user_id,
                "interactionType": interaction_type,  # view, register, share, like, etc.
                "tournamentId": tournament_id,
                "metadata": metadata or {},
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.user_interactions_collection.insert_one(interaction)
            
            return {
                "success": True,
                "message": "Interaction recorded successfully"
            }
            
        except Exception as e:
            logger.error(f"Error recording user interaction: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to record interaction: {str(e)}"
            }
    
    async def update_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> Dict[str, Any]:
        """Update user preferences for recommendations"""
        try:
            preferences["userId"] = user_id
            preferences["updatedAt"] = datetime.utcnow().isoformat()
            
            await self.user_preferences_collection.replace_one(
                {"userId": user_id},
                preferences,
                upsert=True
            )
            
            return {
                "success": True,
                "data": preferences,
                "message": "User preferences updated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error updating user preferences: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to update preferences: {str(e)}"
            }


# Service instances
def get_badge_system(db):
    """Get badge system instance"""
    return BadgeSystem(db)

def get_loyalty_reward_system(db):
    """Get loyalty reward system instance"""
    return LoyaltyRewardSystem(db)

def get_recommendation_engine(db):
    """Get recommendation engine instance"""
    return RecommendationEngine(db)