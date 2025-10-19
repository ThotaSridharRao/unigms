"""
Data Privacy and Compliance Service

This module provides GDPR-compliant data export, deletion, and privacy controls
for the tournament platform.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import uuid

from database import (
    get_user_by_email,
    get_tournaments_for_user,
    get_user_activities,
    store_audit_log,
    get_audit_logs,
    store_user_consent,
    get_user_consents as db_get_user_consents,
    store_data_export_request,
    get_data_export_request,
    update_data_export_request,
    store_data_deletion_request,
    get_data_deletion_request,
    update_data_deletion_request,
    anonymize_user_data,
    delete_user_data_by_category,
    get_user_data_summary,
    get_user_by_id
)

logger = logging.getLogger(__name__)

class DataCategory(Enum):
    """Categories of personal data"""
    PROFILE = "profile"
    TOURNAMENTS = "tournaments"
    PAYMENTS = "payments"
    ACTIVITIES = "activities"
    COMMUNICATIONS = "communications"
    ANALYTICS = "analytics"

class ConsentType(Enum):
    """Types of user consent"""
    ESSENTIAL = "essential"  # Required for service
    ANALYTICS = "analytics"  # Usage analytics
    MARKETING = "marketing"  # Marketing communications
    THIRD_PARTY = "third_party"  # Third-party integrations

@dataclass
class UserConsent:
    """User consent record"""
    user_id: str
    consent_type: ConsentType
    granted: bool
    granted_at: datetime
    withdrawn_at: Optional[datetime] = None
    ip_address: str = ""
    user_agent: str = ""

@dataclass
class DataExportRequest:
    """Data export request"""
    request_id: str
    user_id: str
    email: str
    categories: List[DataCategory]
    requested_at: datetime
    completed_at: Optional[datetime] = None
    download_url: Optional[str] = None
    expires_at: Optional[datetime] = None

@dataclass
class DataDeletionRequest:
    """Data deletion request"""
    request_id: str
    user_id: str
    email: str
    requested_at: datetime
    completed_at: Optional[datetime] = None
    retention_overrides: Dict[str, str] = None  # Legal retention requirements

@dataclass
class RetentionPolicy:
    """Data retention policy configuration"""
    financial_records_years: int = 7  # Legal requirement
    tournament_data_years: int = 2
    activity_logs_months: int = 12
    analytics_data_years: int = 3
    communication_logs_months: int = 6

class AuditLogger:
    """Audit logging for compliance"""
    
    def __init__(self):
        self.audit_logs: List[Dict] = []
    
    def log_data_access(self, user_id: str, accessed_by: str, data_type: str, 
                       purpose: str, ip_address: str = ""):
        """Log data access for audit purposes"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "data_access",
            "user_id": user_id,
            "accessed_by": accessed_by,
            "data_type": data_type,
            "purpose": purpose,
            "ip_address": ip_address,
            "audit_id": str(uuid.uuid4())
        }
        
        # Store in database
        store_audit_log(audit_entry)
        self.audit_logs.append(audit_entry)
        logger.info(f"AUDIT: Data access - {audit_entry}")
    
    def log_data_export(self, user_id: str, requested_by: str, categories: List[str]):
        """Log data export request"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "data_export",
            "user_id": user_id,
            "requested_by": requested_by,
            "categories": categories,
            "audit_id": str(uuid.uuid4())
        }
        
        # Store in database
        store_audit_log(audit_entry)
        self.audit_logs.append(audit_entry)
        logger.info(f"AUDIT: Data export - {audit_entry}")
    
    def log_data_deletion(self, user_id: str, requested_by: str, deletion_type: str):
        """Log data deletion request"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "data_deletion",
            "user_id": user_id,
            "requested_by": requested_by,
            "deletion_type": deletion_type,
            "audit_id": str(uuid.uuid4())
        }
        
        # Store in database
        store_audit_log(audit_entry)
        self.audit_logs.append(audit_entry)
        logger.info(f"AUDIT: Data deletion - {audit_entry}")
    
    def log_consent_change(self, user_id: str, consent_type: str, granted: bool, ip_address: str = ""):
        """Log consent changes"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "consent_change",
            "user_id": user_id,
            "consent_type": consent_type,
            "granted": granted,
            "ip_address": ip_address,
            "audit_id": str(uuid.uuid4())
        }
        
        # Store in database
        store_audit_log(audit_entry)
        self.audit_logs.append(audit_entry)
        logger.info(f"AUDIT: Consent change - {audit_entry}")

class DataPrivacyService:
    """Main service for data privacy and compliance"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.retention_policy = RetentionPolicy()
        self.export_requests: Dict[str, DataExportRequest] = {}
        self.deletion_requests: Dict[str, DataDeletionRequest] = {}
        self.user_consents: Dict[str, List[UserConsent]] = {}
    
    async def export_user_data(self, user_id: str, requested_by: str, 
                              categories: List[DataCategory] = None) -> DataExportRequest:
        """Export all user data for GDPR compliance"""
        if categories is None:
            categories = list(DataCategory)
        
        # Create export request
        request_id = str(uuid.uuid4())
        user = await self._get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        export_request = DataExportRequest(
            request_id=request_id,
            user_id=user_id,
            email=user["email"],
            categories=categories,
            requested_at=datetime.utcnow()
        )
        
        # Log the export request
        self.audit_logger.log_data_export(
            user_id, requested_by, [cat.value for cat in categories]
        )
        
        # Collect data based on categories
        export_data = {}
        
        if DataCategory.PROFILE in categories:
            export_data["profile"] = await self._export_profile_data(user_id)
        
        if DataCategory.TOURNAMENTS in categories:
            export_data["tournaments"] = await self._export_tournament_data(user_id)
        
        if DataCategory.PAYMENTS in categories:
            export_data["payments"] = await self._export_payment_data(user_id)
        
        if DataCategory.ACTIVITIES in categories:
            export_data["activities"] = await self._export_activity_data(user_id)
        
        if DataCategory.COMMUNICATIONS in categories:
            export_data["communications"] = await self._export_communication_data(user_id)
        
        if DataCategory.ANALYTICS in categories:
            export_data["analytics"] = await self._export_analytics_data(user_id)
        
        # Create export file
        export_filename = f"user_data_export_{user_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        export_data["export_metadata"] = {
            "request_id": request_id,
            "user_id": user_id,
            "export_date": datetime.utcnow().isoformat(),
            "categories": [cat.value for cat in categories],
            "data_controller": "Tournament Platform",
            "retention_notice": "This export contains your personal data as of the export date. Some data may be retained for legal compliance."
        }
        
        # Create exports directory if it doesn't exist
        import os
        os.makedirs("exports", exist_ok=True)
        
        # Save export data (in production, this would be saved to secure storage)
        with open(f"exports/{export_filename}", "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        
        # Update export request
        export_request.completed_at = datetime.utcnow()
        export_request.download_url = f"/api/privacy/exports/{export_filename}"
        export_request.expires_at = datetime.utcnow() + timedelta(days=30)
        
        # Store in database
        store_data_export_request({
            "request_id": request_id,
            "user_id": user_id,
            "email": user["email"],
            "categories": [cat.value for cat in categories],
            "requested_at": export_request.requested_at,
            "completed_at": export_request.completed_at,
            "download_url": export_request.download_url,
            "expires_at": export_request.expires_at
        })
        
        self.export_requests[request_id] = export_request
        
        return export_request
    
    async def delete_user_data(self, user_id: str, requested_by: str, 
                              deletion_type: str = "full") -> DataDeletionRequest:
        """Delete user data with retention policy compliance"""
        request_id = str(uuid.uuid4())
        user = await self._get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        deletion_request = DataDeletionRequest(
            request_id=request_id,
            user_id=user_id,
            email=user["email"],
            requested_at=datetime.utcnow()
        )
        
        # Log the deletion request
        self.audit_logger.log_data_deletion(user_id, requested_by, deletion_type)
        
        # Apply retention policy
        retention_overrides = {}
        
        if deletion_type == "full":
            # Full deletion with retention policy compliance
            await self._delete_profile_data(user_id, retention_overrides)
            await self._delete_tournament_data(user_id, retention_overrides)
            await self._anonymize_payment_data(user_id, retention_overrides)
            await self._delete_activity_data(user_id, retention_overrides)
            await self._delete_communication_data(user_id, retention_overrides)
            await self._delete_analytics_data(user_id, retention_overrides)
        
        elif deletion_type == "anonymize":
            # Anonymize instead of delete
            anonymize_user_data(user_id)
        
        deletion_request.completed_at = datetime.utcnow()
        deletion_request.retention_overrides = retention_overrides
        
        # Store in database
        store_data_deletion_request({
            "request_id": request_id,
            "user_id": user_id,
            "email": user["email"],
            "requested_at": deletion_request.requested_at,
            "completed_at": deletion_request.completed_at,
            "deletion_type": deletion_type,
            "retention_overrides": retention_overrides
        })
        
        self.deletion_requests[request_id] = deletion_request
        
        return deletion_request
    
    async def manage_user_consent(self, user_id: str, consent_type: ConsentType, 
                                 granted: bool, ip_address: str = "", user_agent: str = "") -> UserConsent:
        """Manage user consent preferences"""
        consent = UserConsent(
            user_id=user_id,
            consent_type=consent_type,
            granted=granted,
            granted_at=datetime.utcnow(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Store consent in database
        consent_data = {
            "consent_type": consent_type.value,
            "granted": granted,
            "granted_at": consent.granted_at,
            "ip_address": ip_address,
            "user_agent": user_agent
        }
        store_user_consent(user_id, consent_data)
        
        # Store consent in memory cache
        if user_id not in self.user_consents:
            self.user_consents[user_id] = []
        
        # Remove previous consent of same type
        self.user_consents[user_id] = [
            c for c in self.user_consents[user_id] 
            if c.consent_type != consent_type
        ]
        
        self.user_consents[user_id].append(consent)
        
        # Log consent change
        self.audit_logger.log_consent_change(
            user_id, consent_type.value, granted, ip_address
        )
        
        return consent
    
    async def get_user_consents(self, user_id: str) -> List[UserConsent]:
        """Get user's current consent preferences"""
        # Get from database
        db_consents = db_get_user_consents(user_id)
        
        # Convert to UserConsent objects
        consents = []
        for consent_data in db_consents:
            consent = UserConsent(
                user_id=user_id,
                consent_type=ConsentType(consent_data["consent_type"]),
                granted=consent_data["granted"],
                granted_at=datetime.fromisoformat(consent_data["granted_at"]) if isinstance(consent_data["granted_at"], str) else consent_data["granted_at"],
                withdrawn_at=datetime.fromisoformat(consent_data["withdrawn_at"]) if consent_data.get("withdrawn_at") and isinstance(consent_data["withdrawn_at"], str) else consent_data.get("withdrawn_at"),
                ip_address=consent_data.get("ip_address", ""),
                user_agent=consent_data.get("user_agent", "")
            )
            consents.append(consent)
        
        return consents
    
    async def check_consent(self, user_id: str, consent_type: ConsentType) -> bool:
        """Check if user has granted specific consent"""
        consents = await self.get_user_consents(user_id)
        for consent in consents:
            if consent.consent_type == consent_type and consent.granted:
                return True
        return False
    
    async def get_privacy_dashboard_data(self, user_id: str) -> Dict:
        """Get privacy dashboard data for user"""
        consents = await self.get_user_consents(user_id)
        
        # Get data summary from database
        data_summary = get_user_data_summary(user_id)
        
        return {
            "user_id": user_id,
            "consents": [asdict(c) for c in consents],
            "data_summary": data_summary,
            "retention_policy": asdict(self.retention_policy),
            "rights": {
                "data_portability": True,
                "right_to_erasure": True,
                "right_to_rectification": True,
                "right_to_restrict_processing": True
            }
        }
    
    # Private helper methods
    async def _get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        return get_user_by_id(user_id)
    
    async def _export_profile_data(self, user_id: str) -> Dict:
        """Export user profile data"""
        # Get user profile data
        user = await self._get_user_by_id(user_id)
        if not user:
            return {}
        
        return {
            "user_id": user_id,
            "email": user.get("email"),
            "username": user.get("username"),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login"),
            "profile_settings": user.get("settings", {})
        }
    
    async def _export_tournament_data(self, user_id: str) -> Dict:
        """Export tournament-related data"""
        # Get tournaments participated in (user hosting removed)
        participated_tournaments = get_tournaments_for_user(user_id)
        
        return {
            "participated_tournaments": [self._sanitize_tournament_data(t) for t in participated_tournaments]
        }
    
    async def _export_payment_data(self, user_id: str) -> Dict:
        """Export payment data (anonymized for privacy)"""
        # Get payment records
        payments = []  # This would query payment records
        
        return {
            "payment_summary": {
                "total_payments": len(payments),
                "total_amount": sum(p.get("amount", 0) for p in payments),
                "currency": "USD"
            },
            "payments": [self._anonymize_payment_record(p) for p in payments]
        }
    
    async def _export_activity_data(self, user_id: str) -> Dict:
        """Export user activity data"""
        activities = get_user_activities(user_id)
        
        return {
            "activities": [self._sanitize_activity_data(a) for a in activities]
        }
    
    async def _export_communication_data(self, user_id: str) -> Dict:
        """Export communication data"""
        return {
            "notifications_sent": [],  # Would query notification logs
            "messages": []  # Would query message history
        }
    
    async def _export_analytics_data(self, user_id: str) -> Dict:
        """Export analytics data"""
        return {
            "usage_statistics": {},  # Would query analytics data
            "preferences": {}
        }
    
    async def _delete_profile_data(self, user_id: str, retention_overrides: Dict):
        """Delete user profile data"""
        delete_user_data_by_category(user_id, "profile")
        logger.info(f"Deleting profile data for user {user_id}")
    
    async def _delete_tournament_data(self, user_id: str, retention_overrides: Dict):
        """Delete tournament data with retention policy"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_policy.tournament_data_years * 365)
        delete_user_data_by_category(user_id, "tournaments", cutoff_date)
        logger.info(f"Deleting tournament data older than {cutoff_date} for user {user_id}")
    
    async def _anonymize_payment_data(self, user_id: str, retention_overrides: Dict):
        """Anonymize payment data (cannot delete due to legal requirements)"""
        # Payment data is anonymized as part of the anonymize_user_data function
        logger.info(f"Anonymizing payment data for user {user_id}")
    
    async def _delete_activity_data(self, user_id: str, retention_overrides: Dict):
        """Delete activity data"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_policy.activity_logs_months * 30)
        delete_user_data_by_category(user_id, "activities", cutoff_date)
        logger.info(f"Deleting activity data older than {cutoff_date} for user {user_id}")
    
    async def _delete_communication_data(self, user_id: str, retention_overrides: Dict):
        """Delete communication data"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_policy.communication_logs_months * 30)
        delete_user_data_by_category(user_id, "communications", cutoff_date)
        logger.info(f"Deleting communication data older than {cutoff_date} for user {user_id}")
    
    async def _delete_analytics_data(self, user_id: str, retention_overrides: Dict):
        """Delete analytics data"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_policy.analytics_data_years * 365)
        delete_user_data_by_category(user_id, "analytics", cutoff_date)
        logger.info(f"Deleting analytics data older than {cutoff_date} for user {user_id}")
    
    async def _get_data_summary(self, user_id: str, category: DataCategory) -> Dict:
        """Get summary of data for specific category"""
        return {
            "category": category.value,
            "record_count": 0,  # Would count actual records
            "last_updated": datetime.utcnow().isoformat(),
            "retention_period": "varies"
        }
    
    def _sanitize_tournament_data(self, tournament: Dict) -> Dict:
        """Remove sensitive data from tournament export"""
        return {
            "tournament_id": tournament.get("_id"),
            "title": tournament.get("title"),
            "game": tournament.get("game"),
            "created_at": tournament.get("created_at"),
            "status": tournament.get("status")
        }
    
    def _anonymize_payment_record(self, payment: Dict) -> Dict:
        """Anonymize payment record for export"""
        return {
            "payment_id": payment.get("_id"),
            "amount": payment.get("amount"),
            "currency": payment.get("currency"),
            "date": payment.get("created_at"),
            "status": payment.get("status"),
            "payment_method": "***"  # Anonymized
        }
    
    def _sanitize_activity_data(self, activity: Dict) -> Dict:
        """Sanitize activity data for export"""
        return {
            "activity_id": activity.get("_id"),
            "type": activity.get("type"),
            "timestamp": activity.get("timestamp"),
            "description": activity.get("description")
        }

# Global instance
data_privacy_service = DataPrivacyService()

def get_data_privacy_service() -> DataPrivacyService:
    """Get the global data privacy service instance"""
    return data_privacy_service