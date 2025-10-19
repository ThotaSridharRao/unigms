"""
Privacy and Compliance API Endpoints

This module provides API endpoints for GDPR compliance, data export,
deletion, and consent management.
"""

from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime
import os

from auth import verify_jwt_token
from data_privacy_service import (
    get_data_privacy_service,
    DataCategory,
    ConsentType,
    DataExportRequest,
    DataDeletionRequest
)
from database import (
    get_data_export_request,
    get_data_deletion_request,
    get_audit_logs
)

# Pydantic models for API requests/responses
class ConsentRequest(BaseModel):
    consent_type: str
    granted: bool

class DataExportRequestModel(BaseModel):
    categories: Optional[List[str]] = None
    email_notification: bool = True

class DataDeletionRequestModel(BaseModel):
    deletion_type: str = "full"  # "full" or "anonymize"
    confirmation_email: EmailStr
    reason: Optional[str] = None

class PrivacyDashboardResponse(BaseModel):
    user_id: str
    consents: List[dict]
    data_summary: dict
    retention_policy: dict
    rights: dict

class ConsentResponse(BaseModel):
    consent_type: str
    granted: bool
    granted_at: str

class ExportStatusResponse(BaseModel):
    request_id: str
    status: str
    requested_at: str
    completed_at: Optional[str] = None
    download_url: Optional[str] = None
    expires_at: Optional[str] = None

class DeletionStatusResponse(BaseModel):
    request_id: str
    status: str
    requested_at: str
    completed_at: Optional[str] = None

# Create router
privacy_router = APIRouter(prefix="/api/privacy", tags=["Privacy & Compliance"])
security = HTTPBearer()

def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    try:
        token = auth.credentials
        payload = verify_jwt_token(token)
        return payload
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

@privacy_router.get("/dashboard", response_model=PrivacyDashboardResponse)
async def get_privacy_dashboard(user: dict = Depends(get_current_user)):
    """Get user's privacy dashboard with consent status and data summary"""
    try:
        privacy_service = get_data_privacy_service()
        user_id = user.get("user_id")
        
        dashboard_data = await privacy_service.get_privacy_dashboard_data(user_id)
        
        return PrivacyDashboardResponse(**dashboard_data)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve privacy dashboard: {str(e)}"
        )

@privacy_router.post("/consent", response_model=ConsentResponse)
async def update_consent(
    consent_request: ConsentRequest,
    request: Request,
    user: dict = Depends(get_current_user)
):
    """Update user consent preferences"""
    try:
        privacy_service = get_data_privacy_service()
        user_id = user.get("user_id")
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Validate consent type
        try:
            consent_type = ConsentType(consent_request.consent_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid consent type: {consent_request.consent_type}"
            )
        
        # Essential consent cannot be withdrawn
        if consent_type == ConsentType.ESSENTIAL and not consent_request.granted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Essential consent cannot be withdrawn"
            )
        
        consent = await privacy_service.manage_user_consent(
            user_id=user_id,
            consent_type=consent_type,
            granted=consent_request.granted,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return ConsentResponse(
            consent_type=consent.consent_type.value,
            granted=consent.granted,
            granted_at=consent.granted_at.isoformat()
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update consent: {str(e)}"
        )

@privacy_router.get("/consent")
async def get_user_consents(user: dict = Depends(get_current_user)):
    """Get user's current consent preferences"""
    try:
        privacy_service = get_data_privacy_service()
        user_id = user.get("user_id")
        
        consents = await privacy_service.get_user_consents(user_id)
        
        return {
            "consents": [
                {
                    "consent_type": c.consent_type.value,
                    "granted": c.granted,
                    "granted_at": c.granted_at.isoformat(),
                    "withdrawn_at": c.withdrawn_at.isoformat() if c.withdrawn_at else None
                }
                for c in consents
            ]
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve consents: {str(e)}"
        )

@privacy_router.post("/export", response_model=ExportStatusResponse)
async def request_data_export(
    export_request: DataExportRequestModel,
    user: dict = Depends(get_current_user)
):
    """Request export of user's personal data"""
    try:
        privacy_service = get_data_privacy_service()
        user_id = user.get("user_id")
        user_email = user.get("email")
        
        # Validate categories
        categories = []
        if export_request.categories:
            for cat_str in export_request.categories:
                try:
                    categories.append(DataCategory(cat_str))
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid data category: {cat_str}"
                    )
        
        # Create export request
        export_result = await privacy_service.export_user_data(
            user_id=user_id,
            requested_by=user_email,
            categories=categories or None
        )
        
        return ExportStatusResponse(
            request_id=export_result.request_id,
            status="completed" if export_result.completed_at else "processing",
            requested_at=export_result.requested_at.isoformat(),
            completed_at=export_result.completed_at.isoformat() if export_result.completed_at else None,
            download_url=export_result.download_url,
            expires_at=export_result.expires_at.isoformat() if export_result.expires_at else None
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create export request: {str(e)}"
        )

@privacy_router.get("/export/{request_id}")
async def get_export_status(
    request_id: str,
    user: dict = Depends(get_current_user)
):
    """Get status of data export request"""
    try:
        privacy_service = get_data_privacy_service()
        
        # Get from database
        export_request_data = get_data_export_request(request_id)
        
        if not export_request_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Export request not found"
            )
        
        # Verify user owns this request
        if export_request_data["user_id"] != user.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        return ExportStatusResponse(
            request_id=export_request_data["request_id"],
            status="completed" if export_request_data.get("completed_at") else "processing",
            requested_at=export_request_data["requested_at"],
            completed_at=export_request_data.get("completed_at"),
            download_url=export_request_data.get("download_url"),
            expires_at=export_request_data.get("expires_at")
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve export status: {str(e)}"
        )

@privacy_router.get("/exports/{filename}")
async def download_export(
    filename: str,
    user: dict = Depends(get_current_user)
):
    """Download exported data file"""
    try:
        # Validate filename and user access
        if not filename.startswith(f"user_data_export_{user.get('user_id')}_"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        file_path = f"exports/{filename}"
        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Export file not found or expired"
            )
        
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type="application/json"
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download export: {str(e)}"
        )

@privacy_router.post("/delete", response_model=DeletionStatusResponse)
async def request_data_deletion(
    deletion_request: DataDeletionRequestModel,
    user: dict = Depends(get_current_user)
):
    """Request deletion of user's personal data"""
    try:
        privacy_service = get_data_privacy_service()
        user_id = user.get("user_id")
        user_email = user.get("email")
        
        # Verify email confirmation
        if deletion_request.confirmation_email != user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Confirmation email does not match user email"
            )
        
        # Validate deletion type
        if deletion_request.deletion_type not in ["full", "anonymize"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid deletion type. Must be 'full' or 'anonymize'"
            )
        
        # Create deletion request
        deletion_result = await privacy_service.delete_user_data(
            user_id=user_id,
            requested_by=user_email,
            deletion_type=deletion_request.deletion_type
        )
        
        return DeletionStatusResponse(
            request_id=deletion_result.request_id,
            status="completed" if deletion_result.completed_at else "processing",
            requested_at=deletion_result.requested_at.isoformat(),
            completed_at=deletion_result.completed_at.isoformat() if deletion_result.completed_at else None
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create deletion request: {str(e)}"
        )

@privacy_router.get("/delete/{request_id}")
async def get_deletion_status(
    request_id: str,
    user: dict = Depends(get_current_user)
):
    """Get status of data deletion request"""
    try:
        privacy_service = get_data_privacy_service()
        
        # Get from database
        deletion_request_data = get_data_deletion_request(request_id)
        
        if not deletion_request_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Deletion request not found"
            )
        
        # Verify user owns this request
        if deletion_request_data["user_id"] != user.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        return DeletionStatusResponse(
            request_id=deletion_request_data["request_id"],
            status="completed" if deletion_request_data.get("completed_at") else "processing",
            requested_at=deletion_request_data["requested_at"],
            completed_at=deletion_request_data.get("completed_at")
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve deletion status: {str(e)}"
        )

@privacy_router.get("/audit-log")
async def get_audit_log(
    user: dict = Depends(get_current_user),
    limit: int = 50
):
    """Get user's privacy-related audit log"""
    try:
        privacy_service = get_data_privacy_service()
        user_id = user.get("user_id")
        
        # Get audit logs from database
        user_audit_logs = get_audit_logs(user_id=user_id, limit=limit)
        
        return {
            "audit_logs": user_audit_logs,
            "total_count": len(user_audit_logs)
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve audit log: {str(e)}"
        )

# Admin endpoints for compliance management
@privacy_router.get("/admin/compliance-report")
async def get_compliance_report(user: dict = Depends(get_current_user)):
    """Get compliance report (admin only)"""
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    try:
        privacy_service = get_data_privacy_service()
        
        return {
            "export_requests": len(privacy_service.export_requests),
            "deletion_requests": len(privacy_service.deletion_requests),
            "total_audit_logs": len(privacy_service.audit_logger.audit_logs),
            "consent_statistics": {
                "total_users_with_consents": len(privacy_service.user_consents)
            }
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate compliance report: {str(e)}"
        )