"""
Tournament Analytics Service

This service provides comprehensive analytics and reporting for tournaments,
including performance metrics, user engagement, and business intelligence.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from database import get_database
from bson import ObjectId
import statistics


class TournamentAnalyticsService:
    """Service for tournament analytics and reporting"""
    
    def __init__(self):
        self.db = get_database()
        self.tournaments_collection = self.db.tournaments
        self.users_collection = self.db.users
        self.activities_collection = self.db.activities
        self.payments_collection = self.db.payments
    
    def get_tournament_analytics(self, tournament_id: str, organizer_id: str = None) -> Dict[str, Any]:
        """
        Get comprehensive analytics for a specific tournament (admin only)
        
        Args:
            tournament_id: Tournament ID
            organizer_id: Deprecated - no longer used
            
        Returns:
            Dictionary containing tournament analytics
        """
        try:
            # Get tournament data (admin tournaments only)
            tournament = self.tournaments_collection.find_one({
                "_id": ObjectId(tournament_id)
            })
            
            if not tournament:
                return {"error": "Tournament not found"}
            
            # Basic tournament metrics
            basic_metrics = self._get_basic_tournament_metrics(tournament)
            
            # Registration analytics
            registration_analytics = self._get_registration_analytics(tournament_id)
            
            # Engagement metrics
            engagement_metrics = self._get_engagement_metrics(tournament_id)
            
            # Revenue analytics (if applicable)
            revenue_analytics = self._get_tournament_revenue_analytics(tournament_id)
            
            # Performance metrics
            performance_metrics = self._get_tournament_performance_metrics(tournament)
            
            # Time-based analytics
            time_analytics = self._get_time_based_analytics(tournament_id)
            
            return {
                "success": True,
                "tournamentId": tournament_id,
                "tournamentTitle": tournament.get("title"),
                "generatedAt": datetime.utcnow().isoformat(),
                "basicMetrics": basic_metrics,
                "registrationAnalytics": registration_analytics,
                "engagementMetrics": engagement_metrics,
                "revenueAnalytics": revenue_analytics,
                "performanceMetrics": performance_metrics,
                "timeAnalytics": time_analytics
            }
            
        except Exception as e:
            print(f"Error generating tournament analytics: {e}")
            return {"error": "Failed to generate analytics"}
    
    def _get_basic_tournament_metrics(self, tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Get basic tournament metrics"""
        participants = tournament.get("participants", [])
        max_teams = tournament.get("maxTeams", 0)
        
        return {
            "totalParticipants": len(participants),
            "maxCapacity": max_teams,
            "capacityUtilization": (len(participants) / max_teams * 100) if max_teams > 0 else 0,
            "registrationStatus": tournament.get("status", "unknown"),
            "createdDate": tournament.get("createdAt"),
            "tournamentStart": tournament.get("tournamentStart"),
            "tournamentEnd": tournament.get("tournamentEnd"),
            "prizePool": tournament.get("prizePool", 0),
            "entryFee": tournament.get("entryFee", 0),
            "viewCount": tournament.get("viewCount", 0)
        }
    
    def _get_registration_analytics(self, tournament_id: str) -> Dict[str, Any]:
        """Get registration analytics"""
        try:
            # Get registration activities
            registration_activities = list(self.activities_collection.find({
                "tournamentId": tournament_id,
                "type": "team_registration"
            }).sort("timestamp", 1))
            
            if not registration_activities:
                return {
                    "totalRegistrations": 0,
                    "registrationTrend": [],
                    "peakRegistrationDay": None,
                    "averageRegistrationsPerDay": 0,
                    "registrationConversionRate": 0
                }
            
            # Calculate registration trend
            registration_trend = self._calculate_registration_trend(registration_activities)
            
            # Find peak registration day
            peak_day = self._find_peak_registration_day(registration_activities)
            
            # Calculate average registrations per day
            days_active = self._calculate_active_days(registration_activities)
            avg_per_day = len(registration_activities) / max(days_active, 1)
            
            return {
                "totalRegistrations": len(registration_activities),
                "registrationTrend": registration_trend,
                "peakRegistrationDay": peak_day,
                "averageRegistrationsPerDay": round(avg_per_day, 2),
                "registrationConversionRate": self._calculate_conversion_rate(tournament_id)
            }
            
        except Exception as e:
            print(f"Error calculating registration analytics: {e}")
            return {"error": "Failed to calculate registration analytics"}
    
    def _get_engagement_metrics(self, tournament_id: str) -> Dict[str, Any]:
        """Get engagement metrics"""
        try:
            # Get all activities for this tournament
            activities = list(self.activities_collection.find({
                "tournamentId": tournament_id
            }))
            
            # Count activities by type
            activity_counts = {}
            for activity in activities:
                activity_type = activity.get("type", "unknown")
                activity_counts[activity_type] = activity_counts.get(activity_type, 0) + 1
            
            # Calculate engagement score
            engagement_score = self._calculate_engagement_score(activities)
            
            # Get unique active users
            unique_users = set()
            for activity in activities:
                if activity.get("userId"):
                    unique_users.add(activity["userId"])
            
            return {
                "totalActivities": len(activities),
                "activityBreakdown": activity_counts,
                "uniqueActiveUsers": len(unique_users),
                "engagementScore": engagement_score,
                "averageActivitiesPerUser": len(activities) / max(len(unique_users), 1)
            }
            
        except Exception as e:
            print(f"Error calculating engagement metrics: {e}")
            return {"error": "Failed to calculate engagement metrics"}
    
    def _get_tournament_revenue_analytics(self, tournament_id: str) -> Dict[str, Any]:
        """Get revenue analytics for tournament"""
        try:
            # Get payment records for this tournament
            payments = list(self.payments_collection.find({
                "tournamentId": tournament_id,
                "status": "completed"
            }))
            
            total_revenue = sum(payment.get("amount", 0) for payment in payments)
            successful_payments = len(payments)
            
            # Get failed payments
            failed_payments = self.payments_collection.count_documents({
                "tournamentId": tournament_id,
                "status": "failed"
            })
            
            # Calculate payment success rate
            total_payment_attempts = successful_payments + failed_payments
            success_rate = (successful_payments / max(total_payment_attempts, 1)) * 100
            
            return {
                "totalRevenue": total_revenue,
                "successfulPayments": successful_payments,
                "failedPayments": failed_payments,
                "paymentSuccessRate": round(success_rate, 2),
                "averageRevenuePerParticipant": total_revenue / max(successful_payments, 1)
            }
            
        except Exception as e:
            print(f"Error calculating revenue analytics: {e}")
            return {"error": "Failed to calculate revenue analytics"}
    
    def _get_tournament_performance_metrics(self, tournament: Dict[str, Any]) -> Dict[str, Any]:
        """Get tournament performance metrics"""
        try:
            # Calculate performance score based on various factors
            participants = len(tournament.get("participants", []))
            max_teams = tournament.get("maxTeams", 1)
            view_count = tournament.get("viewCount", 0)
            
            # Capacity utilization score (0-40 points)
            capacity_score = min((participants / max_teams) * 40, 40)
            
            # Engagement score based on views (0-30 points)
            engagement_score = min((view_count / max(participants, 1)) * 10, 30)
            
            # Time management score (0-30 points)
            time_score = self._calculate_time_management_score(tournament)
            
            total_score = capacity_score + engagement_score + time_score
            
            return {
                "overallPerformanceScore": round(total_score, 2),
                "capacityUtilizationScore": round(capacity_score, 2),
                "engagementScore": round(engagement_score, 2),
                "timeManagementScore": round(time_score, 2),
                "performanceGrade": self._get_performance_grade(total_score)
            }
            
        except Exception as e:
            print(f"Error calculating performance metrics: {e}")
            return {"error": "Failed to calculate performance metrics"}
    
    def _get_time_based_analytics(self, tournament_id: str) -> Dict[str, Any]:
        """Get time-based analytics"""
        try:
            # Get activities grouped by time periods
            activities = list(self.activities_collection.find({
                "tournamentId": tournament_id
            }).sort("timestamp", 1))
            
            if not activities:
                return {"hourlyDistribution": {}, "dailyDistribution": {}, "weeklyTrend": []}
            
            # Hourly distribution
            hourly_dist = {}
            daily_dist = {}
            
            for activity in activities:
                timestamp = activity.get("timestamp")
                if timestamp:
                    if isinstance(timestamp, str):
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    else:
                        dt = timestamp
                    
                    hour = dt.hour
                    day = dt.strftime('%A')
                    
                    hourly_dist[hour] = hourly_dist.get(hour, 0) + 1
                    daily_dist[day] = daily_dist.get(day, 0) + 1
            
            # Weekly trend (last 4 weeks)
            weekly_trend = self._calculate_weekly_trend(activities)
            
            return {
                "hourlyDistribution": hourly_dist,
                "dailyDistribution": daily_dist,
                "weeklyTrend": weekly_trend,
                "peakActivityHour": max(hourly_dist.items(), key=lambda x: x[1])[0] if hourly_dist else None,
                "peakActivityDay": max(daily_dist.items(), key=lambda x: x[1])[0] if daily_dist else None
            }
            
        except Exception as e:
            print(f"Error calculating time-based analytics: {e}")
            return {"error": "Failed to calculate time-based analytics"}
    
    def get_organizer_analytics(self, organizer_id: str) -> Dict[str, Any]:
        """Get analytics for organizer (disabled - user hosting removed)"""
        return {
            "success": True,
            "totalTournaments": 0,
            "organizerScore": 0,
            "message": "User hosting functionality has been removed"
        }
    
    def get_platform_analytics(self) -> Dict[str, Any]:
        """Get platform-wide analytics"""
        try:
            # Total tournaments (admin only)
            total_admin_tournaments = self.tournaments_collection.count_documents({})
            
            # Active tournaments (admin only)
            active_tournaments = self.tournaments_collection.count_documents({
                "status": {"$in": ["active", "registration_open", "ongoing"]}
            })
            
            # Total users
            total_users = self.users_collection.count_documents({})
            
            # Total revenue (tournament entry fees only)
            total_tournament_revenue = self._calculate_total_tournament_revenue()
            
            # Growth metrics
            growth_metrics = self._calculate_growth_metrics()
            
            # User engagement metrics
            engagement_metrics = self._calculate_platform_engagement_metrics()
            
            # Performance metrics
            performance_metrics = self._calculate_platform_performance_metrics()
            
            return {
                "success": True,
                "totalTournaments": total_admin_tournaments,
                "adminTournaments": total_admin_tournaments,
                "activeTournaments": active_tournaments,
                "totalUsers": total_users,
                "totalTournamentRevenue": total_tournament_revenue,
                "growthMetrics": growth_metrics,
                "engagementMetrics": engagement_metrics,
                "performanceMetrics": performance_metrics,
                "generatedAt": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            print(f"Error generating platform analytics: {e}")
            return {"error": "Failed to generate platform analytics"}
    
    # Helper methods
    
    def _calculate_registration_trend(self, activities: List[Dict]) -> List[Dict]:
        """Calculate registration trend over time"""
        if not activities:
            return []
        
        # Group by date
        daily_counts = {}
        for activity in activities:
            timestamp = activity.get("timestamp")
            if timestamp:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp
                date_key = dt.strftime('%Y-%m-%d')
                daily_counts[date_key] = daily_counts.get(date_key, 0) + 1
        
        # Convert to trend data
        trend_data = []
        for date, count in sorted(daily_counts.items()):
            trend_data.append({"date": date, "registrations": count})
        
        return trend_data
    
    def _find_peak_registration_day(self, activities: List[Dict]) -> Optional[str]:
        """Find the day with most registrations"""
        daily_counts = {}
        for activity in activities:
            timestamp = activity.get("timestamp")
            if timestamp:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp
                date_key = dt.strftime('%Y-%m-%d')
                daily_counts[date_key] = daily_counts.get(date_key, 0) + 1
        
        if not daily_counts:
            return None
        
        return max(daily_counts.items(), key=lambda x: x[1])[0]
    
    def _calculate_active_days(self, activities: List[Dict]) -> int:
        """Calculate number of active days"""
        dates = set()
        for activity in activities:
            timestamp = activity.get("timestamp")
            if timestamp:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp
                dates.add(dt.strftime('%Y-%m-%d'))
        return len(dates)
    
    def _calculate_conversion_rate(self, tournament_id: str) -> float:
        """Calculate registration conversion rate"""
        # This would require view tracking vs registrations
        # For now, return a placeholder
        return 0.0
    
    def _calculate_engagement_score(self, activities: List[Dict]) -> float:
        """Calculate engagement score based on activities"""
        if not activities:
            return 0.0
        
        # Weight different activity types
        weights = {
            "tournament_view": 1,
            "team_registration": 5,
            "payment_completed": 3,
            "tournament_shared": 2,
            "message_sent": 2
        }
        
        total_score = 0
        for activity in activities:
            activity_type = activity.get("type", "unknown")
            total_score += weights.get(activity_type, 1)
        
        return total_score / len(activities)
    
    def _calculate_time_management_score(self, tournament: Dict[str, Any]) -> float:
        """Calculate time management score"""
        # This is a simplified scoring system
        # In reality, you'd track actual tournament execution vs planned schedule
        return 25.0  # Placeholder score
    
    def _get_performance_grade(self, score: float) -> str:
        """Get performance grade based on score"""
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 60:
            return "C"
        else:
            return "D"
    
    def _calculate_weekly_trend(self, activities: List[Dict]) -> List[Dict]:
        """Calculate weekly activity trend"""
        # Group activities by week
        weekly_counts = {}
        for activity in activities:
            timestamp = activity.get("timestamp")
            if timestamp:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp
                
                # Get week start (Monday)
                week_start = dt - timedelta(days=dt.weekday())
                week_key = week_start.strftime('%Y-%m-%d')
                weekly_counts[week_key] = weekly_counts.get(week_key, 0) + 1
        
        # Convert to trend data
        trend_data = []
        for week, count in sorted(weekly_counts.items()):
            trend_data.append({"week": week, "activities": count})
        
        return trend_data[-4:]  # Last 4 weeks
    

    
    def _calculate_total_tournament_revenue(self) -> float:
        """Calculate total tournament entry fee revenue"""
        try:
            payments = list(self.payments_collection.find({
                "status": "completed"
            }))
            return sum(payment.get("amount", 0) for payment in payments)
        except Exception as e:
            print(f"Error calculating tournament revenue: {e}")
            return 0.0
    
    def _calculate_growth_metrics(self) -> Dict[str, Any]:
        """Calculate platform growth metrics"""
        try:
            # Calculate monthly growth for the last 6 months
            now = datetime.utcnow()
            six_months_ago = now - timedelta(days=180)
            
            # Tournament growth
            monthly_tournaments = {}
            tournaments = list(self.user_tournaments_collection.find({
                "createdAt": {"$gte": six_months_ago.isoformat()}
            }))
            
            for tournament in tournaments:
                created_at = tournament.get("createdAt")
                if created_at:
                    if isinstance(created_at, str):
                        dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    else:
                        dt = created_at
                    month_key = dt.strftime('%Y-%m')
                    monthly_tournaments[month_key] = monthly_tournaments.get(month_key, 0) + 1
            
            # User growth
            monthly_users = {}
            users = list(self.users_collection.find({
                "createdAt": {"$gte": six_months_ago.isoformat()}
            }))
            
            for user in users:
                created_at = user.get("createdAt")
                if created_at:
                    if isinstance(created_at, str):
                        dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    else:
                        dt = created_at
                    month_key = dt.strftime('%Y-%m')
                    monthly_users[month_key] = monthly_users.get(month_key, 0) + 1
            
            return {
                "monthlyTournamentGrowth": monthly_tournaments,
                "monthlyUserGrowth": monthly_users
            }
            
        except Exception as e:
            print(f"Error calculating growth metrics: {e}")
            return {}
    
    def _calculate_platform_engagement_metrics(self) -> Dict[str, Any]:
        """Calculate platform-wide engagement metrics"""
        try:
            # Get all activities from the last 30 days
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            
            activities = list(self.activities_collection.find({
                "timestamp": {"$gte": thirty_days_ago.isoformat()}
            }))
            
            # Calculate engagement metrics
            total_activities = len(activities)
            unique_users = set()
            activity_types = {}
            
            for activity in activities:
                if activity.get("userId"):
                    unique_users.add(activity["userId"])
                
                activity_type = activity.get("type", "unknown")
                activity_types[activity_type] = activity_types.get(activity_type, 0) + 1
            
            # Calculate daily active users (last 7 days)
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            daily_active_users = set()
            
            recent_activities = list(self.activities_collection.find({
                "timestamp": {"$gte": seven_days_ago.isoformat()}
            }))
            
            for activity in recent_activities:
                if activity.get("userId"):
                    daily_active_users.add(activity["userId"])
            
            # Calculate retention metrics
            retention_metrics = self._calculate_user_retention()
            
            # Calculate session metrics
            session_metrics = self._calculate_session_metrics()
            
            return {
                "totalActivities": total_activities,
                "uniqueActiveUsers": len(unique_users),
                "dailyActiveUsers": len(daily_active_users),
                "activityBreakdown": activity_types,
                "averageActivitiesPerUser": total_activities / max(len(unique_users), 1),
                "retentionMetrics": retention_metrics,
                "sessionMetrics": session_metrics
            }
            
        except Exception as e:
            print(f"Error calculating platform engagement metrics: {e}")
            return {}
    
    def _calculate_platform_performance_metrics(self) -> Dict[str, Any]:
        """Calculate platform-wide performance metrics"""
        try:
            # Tournament success metrics
            total_tournaments = self.user_tournaments_collection.count_documents({})
            completed_tournaments = self.user_tournaments_collection.count_documents({
                "status": "completed"
            })
            
            # Calculate average fill rate
            tournaments = list(self.user_tournaments_collection.find({}, {
                "participants": 1,
                "maxTeams": 1
            }))
            
            fill_rates = []
            for tournament in tournaments:
                participants = len(tournament.get("participants", []))
                max_teams = tournament.get("maxTeams", 1)
                if max_teams > 0:
                    fill_rates.append((participants / max_teams) * 100)
            
            average_fill_rate = sum(fill_rates) / len(fill_rates) if fill_rates else 0
            
            # Calculate organizer performance
            organizer_performance = self._calculate_organizer_performance_metrics()
            
            # Calculate platform health score
            platform_health = self._calculate_platform_health_score()
            
            return {
                "tournamentCompletionRate": (completed_tournaments / max(total_tournaments, 1)) * 100,
                "averageFillRate": round(average_fill_rate, 2),
                "totalTournaments": total_tournaments,
                "completedTournaments": completed_tournaments,
                "organizerPerformance": organizer_performance,
                "platformHealthScore": platform_health
            }
            
        except Exception as e:
            print(f"Error calculating platform performance metrics: {e}")
            return {}
    
    def _calculate_user_retention(self) -> Dict[str, Any]:
        """Calculate user retention metrics"""
        try:
            # Get users created in the last 30 days
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            
            new_users = list(self.users_collection.find({
                "createdAt": {"$gte": thirty_days_ago.isoformat()}
            }, {"_id": 1, "createdAt": 1}))
            
            # Check how many returned within 7 days
            retained_users = 0
            for user in new_users:
                user_id = str(user["_id"])
                created_at = user.get("createdAt")
                
                if created_at:
                    if isinstance(created_at, str):
                        created_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    else:
                        created_date = created_at
                    
                    # Check if user had activity within 7 days of registration
                    seven_days_after = created_date + timedelta(days=7)
                    
                    activity_count = self.activities_collection.count_documents({
                        "userId": user_id,
                        "timestamp": {
                            "$gte": created_date.isoformat(),
                            "$lte": seven_days_after.isoformat()
                        }
                    })
                    
                    if activity_count > 1:  # More than just registration
                        retained_users += 1
            
            retention_rate = (retained_users / max(len(new_users), 1)) * 100
            
            return {
                "newUsers": len(new_users),
                "retainedUsers": retained_users,
                "retentionRate": round(retention_rate, 2)
            }
            
        except Exception as e:
            print(f"Error calculating user retention: {e}")
            return {"retentionRate": 0}
    
    def _calculate_session_metrics(self) -> Dict[str, Any]:
        """Calculate session-based metrics"""
        try:
            # This is a simplified version - in a real implementation,
            # you'd track actual user sessions
            
            # Get activities from last 7 days
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            activities = list(self.activities_collection.find({
                "timestamp": {"$gte": seven_days_ago.isoformat()}
            }))
            
            # Group activities by user and day to estimate sessions
            user_daily_activities = {}
            for activity in activities:
                user_id = activity.get("userId")
                timestamp = activity.get("timestamp")
                
                if user_id and timestamp:
                    if isinstance(timestamp, str):
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    else:
                        dt = timestamp
                    
                    day_key = f"{user_id}_{dt.strftime('%Y-%m-%d')}"
                    user_daily_activities[day_key] = user_daily_activities.get(day_key, 0) + 1
            
            # Calculate average session length (activities per session)
            session_lengths = list(user_daily_activities.values())
            avg_session_length = sum(session_lengths) / len(session_lengths) if session_lengths else 0
            
            return {
                "totalSessions": len(session_lengths),
                "averageSessionLength": round(avg_session_length, 2),
                "averageSessionsPerUser": len(session_lengths) / max(len(set(k.split('_')[0] for k in user_daily_activities.keys())), 1)
            }
            
        except Exception as e:
            print(f"Error calculating session metrics: {e}")
            return {}
    
    def _calculate_organizer_performance_metrics(self) -> Dict[str, Any]:
        """Calculate organizer performance metrics"""
        try:
            # Get all organizers
            organizers = list(self.user_tournaments_collection.aggregate([
                {"$group": {"_id": "$organizerId", "tournamentCount": {"$sum": 1}}}
            ]))
            
            # Calculate performance scores for each organizer
            performance_scores = []
            for organizer in organizers:
                organizer_id = organizer["_id"]
                tournament_count = organizer["tournamentCount"]
                
                # Get organizer's tournaments
                tournaments = list(self.user_tournaments_collection.find({
                    "organizerId": organizer_id
                }))
                
                # Calculate average performance
                total_score = 0
                for tournament in tournaments:
                    participants = len(tournament.get("participants", []))
                    max_teams = tournament.get("maxTeams", 1)
                    
                    # Simple performance calculation
                    fill_rate = (participants / max_teams) * 100 if max_teams > 0 else 0
                    completion_bonus = 20 if tournament.get("status") == "completed" else 0
                    
                    total_score += fill_rate + completion_bonus
                
                avg_score = total_score / len(tournaments) if tournaments else 0
                performance_scores.append(avg_score)
            
            return {
                "totalOrganizers": len(organizers),
                "averageOrganizerScore": sum(performance_scores) / len(performance_scores) if performance_scores else 0,
                "topPerformers": len([s for s in performance_scores if s >= 80]),
                "activeOrganizers": len([o for o in organizers if o["tournamentCount"] >= 1])
            }
            
        except Exception as e:
            print(f"Error calculating organizer performance: {e}")
            return {}
    
    def _calculate_platform_health_score(self) -> float:
        """Calculate overall platform health score"""
        try:
            # Factors that contribute to platform health
            
            # 1. Tournament completion rate (0-25 points)
            total_tournaments = self.user_tournaments_collection.count_documents({})
            completed_tournaments = self.user_tournaments_collection.count_documents({
                "status": "completed"
            })
            completion_rate = (completed_tournaments / max(total_tournaments, 1)) * 100
            completion_score = min(completion_rate * 0.25, 25)
            
            # 2. User engagement (0-25 points)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            active_users = self.activities_collection.distinct("userId", {
                "timestamp": {"$gte": thirty_days_ago.isoformat()}
            })
            total_users = self.users_collection.count_documents({})
            engagement_rate = (len(active_users) / max(total_users, 1)) * 100
            engagement_score = min(engagement_rate * 0.5, 25)
            
            # 3. Revenue growth (0-25 points)
            # Simplified - in real implementation, calculate actual growth
            revenue_score = 20  # Placeholder
            
            # 4. Platform stability (0-25 points)
            # Based on error rates, uptime, etc.
            stability_score = 22  # Placeholder
            
            total_score = completion_score + engagement_score + revenue_score + stability_score
            
            return round(total_score, 2)
            
        except Exception as e:
            print(f"Error calculating platform health score: {e}")
            return 0.0


# Singleton instance
_analytics_service = None

def get_analytics_service() -> TournamentAnalyticsService:
    """Get analytics service instance"""
    global _analytics_service
    if _analytics_service is None:
        _analytics_service = TournamentAnalyticsService()
    return _analytics_service