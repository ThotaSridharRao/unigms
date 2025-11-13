import re
from datetime import datetime
from typing import Optional, List, Dict, Any  # Add Dict, Any if not already imported
from pydantic import BaseModel, EmailStr, constr, Field, field_validator


class UserRegistration(BaseModel):
    """Model for user registration request"""
    username: str
    email: str
    password: str
    role: Optional[str] = "user"
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    contact_phone: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username requirements"""
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if len(v) > 20:
            raise ValueError("Username must be less than 20 characters")
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Validate email format"""
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, v):
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password requirements"""
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        """Validate user role"""
        allowed_roles = ["user", "host", "admin"]
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of: {', '.join(allowed_roles)}")
        return v


class UserLogin(BaseModel):
    """Model for user login request"""
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Validate email format"""
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, v):
            raise ValueError("Invalid email format")
        return v.lower()


class UserResponse(BaseModel):
    """Model for user response data"""
    user_id: str
    email: str
    message: str


class LoginResponse(BaseModel):
    """Model for login response"""
    token: str
    user_id: str
    email: str
    message: str
    redirect_path: str


class ErrorResponse(BaseModel):
    """Model for error responses"""
    error: str


class TournamentStatusUpdate(BaseModel):
    """Model for updating tournament status"""
    # Fix: Use 'str' as the type hint and apply the constraint via Field(...)
    status: str = Field(
        ..., # Indicates the field is required
        pattern=r"^(upcoming|registration_open|registration_closed|ongoing|ended)$",
        description="Tournament status must be one of the predefined values."
    )


class Tournament(BaseModel):
    """Model for tournament data"""
    name: str
    game: str
    description: str
    max_participants: int
    entry_fee: float
    prize_pool: float
    start_date: str
    end_date: str
    status: str = "registration"
    format: str = "single_elimination"


class TournamentResponse(BaseModel):
    """Model for tournament response"""
    tournament_id: str
    name: str
    game: str
    description: str
    max_participants: int
    entry_fee: float
    prize_pool: float
    start_date: str
    end_date: str
    status: str
    format: str
    slug: str
    participants_count: int = 0


class Activity(BaseModel):
    """Model for activity data"""
    type: str
    description: str
    user_id: Optional[str] = None
    tournament_id: Optional[str] = None
    timestamp: Optional[str] = None


def validate_email_format(email: str) -> bool:
    """Helper function to validate email format"""
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, email))


def validate_password_strength(password: str) -> bool:
    """Helper function to validate password strength"""
    return len(password) >= 8


class FinalistTeam(BaseModel):
    """Model for a finalist team"""
    position: int = Field(..., ge=1, le=16, description="Position (1-16)")
    teamName: str = Field(..., min_length=1, max_length=50, description="Team name")
    totalPoints: int = Field(default=0, ge=0, description="Total points scored")


class FinalistsUpdate(BaseModel):
    """Model for updating tournament finalists"""
    finalists: List[FinalistTeam] = Field(..., max_items=16, description="List of finalist teams")

    @field_validator("finalists")
    @classmethod
    def validate_unique_positions(cls, v: List[FinalistTeam]) -> List[FinalistTeam]:
        positions = [finalist.position for finalist in v]
        if len(positions) != len(set(positions)):
            raise ValueError("Duplicate positions not allowed")
        return v

    @field_validator("finalists")
    @classmethod
    def validate_unique_team_names(cls, v: List[FinalistTeam]) -> List[FinalistTeam]:
        team_names = [finalist.teamName.lower() for finalist in v]
        if len(team_names) != len(set(team_names)):
            raise ValueError("Duplicate team names not allowed")
        return v

# Payment-related models
class PlayerData(BaseModel):
    """Model for player data in team registration"""
    name: str = Field(..., min_length=2, max_length=50, description="Player name")
    email: str = Field(..., description="Player email")
    inGameId: str = Field(..., min_length=3, max_length=30, description="In-game ID")
    role: Optional[str] = Field(default="Player", description="Player role in team")
    userId: Optional[str] = Field(default=None, description="User account ID if linked")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Player name cannot be empty")
        return v.strip()

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, v):
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("inGameId")
    @classmethod
    def validate_in_game_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("In-game ID cannot be empty")
        return v.strip()

    @field_validator("userId")
    @classmethod
    def validate_user_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            return None  # Convert empty strings to None
        return v


class TeamRegistrationData(BaseModel):
    """Model for team registration data"""
    teamName: str = Field(..., min_length=3, max_length=50, description="Team name")
    players: List[PlayerData] = Field(..., min_items=1, max_items=4, description="Team players")
    phone: Optional[str] = Field(default=None, description="Captain's phone number")
    captainUserId: Optional[str] = Field(default=None, description="Captain's user account ID")
    registeredBy: Optional[str] = Field(default=None, description="User ID who registered this team")

    @field_validator("teamName")
    @classmethod
    def validate_team_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Team name cannot be empty")
        return v.strip()

    @field_validator("players")
    @classmethod
    def validate_unique_emails(cls, v: List[PlayerData]) -> List[PlayerData]:
        emails = [player.email.lower() for player in v]
        if len(emails) != len(set(emails)):
            raise ValueError("Duplicate email addresses not allowed in team")
        return v

    @field_validator("players")
    @classmethod
    def validate_unique_game_ids(cls, v: List[PlayerData]) -> List[PlayerData]:
        game_ids = [player.inGameId.lower() for player in v]
        if len(game_ids) != len(set(game_ids)):
            raise ValueError("Duplicate in-game IDs not allowed in team")
        return v

    @field_validator("captainUserId")
    @classmethod
    def validate_captain_user_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            return None  # Convert empty strings to None
        return v

    @field_validator("registeredBy")
    @classmethod
    def validate_registered_by(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            return None  # Convert empty strings to None
        return v


class PaymentInitiationRequest(BaseModel):
    """Model for payment initiation request"""
    tournamentSlug: str = Field(..., description="Tournament slug")
    teamData: TeamRegistrationData = Field(..., description="Team registration data")
    amount: float = Field(..., gt=0, description="Payment amount")

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("Amount must be greater than 0")
        if v > 100000:  # Max amount limit
            raise ValueError("Amount exceeds maximum limit")
        return round(v, 2)


class PaymentResponse(BaseModel):
    """Model for payment response"""
    success: bool
    transactionId: Optional[str] = None
    paymentId: Optional[str] = None
    payuData: Optional[Dict[str, Any]] = None
    payuUrl: Optional[str] = None
    message: str
    requiresPayment: Optional[bool] = None
    entryFee: Optional[float] = None


class PaymentStatusResponse(BaseModel):
    """Model for payment status response"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None


class PaymentCallbackData(BaseModel):
    """Model for PayU callback data validation"""
    txnid: str
    status: str
    hash: str
    amount: Optional[str] = None
    email: Optional[str] = None
    firstname: Optional[str] = None
    productinfo: Optional[str] = None
    udf1: Optional[str] = None  # Tournament slug
    udf2: Optional[str] = None  # User ID
    udf3: Optional[str] = None
    udf4: Optional[str] = None
    udf5: Optional[str] = None
    error_Message: Optional[str] = None


class PaymentRecord(BaseModel):
    """Model for payment record in database"""
    transactionId: str
    userId: str
    userEmail: str
    tournamentSlug: str
    teamData: TeamRegistrationData
    amount: float
    status: str  # initiated, success, failed
    payuData: Dict[str, Any]
    payuResponse: Optional[Dict[str, Any]] = None
    createdAt: str
    updatedAt: str


class PaymentStatistics(BaseModel):
    """Model for payment statistics"""
    total_payments: int = 0
    successful_payments: int = 0
    failed_payments: int = 0
    pending_payments: int = 0
    total_revenue: float = 0.0


# Team registration response models
class TeamRegistrationResponse(BaseModel):
    """Model for team registration response"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: str
    requiresPayment: Optional[bool] = None
    entryFee: Optional[float] = None
    paymentData: Optional[Dict[str, Any]] = None


class RegistrationStatusResponse(BaseModel):
    """Model for registration status check response"""
    success: bool
    data: Dict[str, Any]


# Bracket-related models
class BracketTeam(BaseModel):
    """Model for a team in tournament brackets"""
    teamId: str
    teamName: str
    status: str = "registered"  # registered, qualified, eliminated
    paymentStatus: str = "pending"  # pending, paid
    score: int = 0
    position: Optional[int] = None
    previousRoundScore: Optional[int] = None
    previousRoundPosition: Optional[int] = None


class BracketGroup(BaseModel):
    """Model for a group in tournament brackets"""
    groupId: int
    teams: List[BracketTeam]
    status: str = "pending"  # pending, active, completed


class BracketRound(BaseModel):
    """Model for a round in tournament brackets"""
    status: str = "pending"  # pending, active, completed
    teams: List[BracketTeam] = []
    groups: List[BracketGroup] = []


class TournamentBrackets(BaseModel):
    """Model for tournament brackets"""
    tournamentId: str
    totalTeams: int
    currentRound: int = 1
    rounds: Dict[str, BracketRound]
    payments: Dict[str, Dict[str, Any]] = {}
    results: Dict[str, Any] = {}


class RoundStartRequest(BaseModel):
    """Model for starting a round"""
    roundKey: str


class RoundCompleteRequest(BaseModel):
    """Model for completing a round"""
    roundKey: str
    qualifyingTeams: Optional[List[Dict[str, Any]]] = None


class BracketPaymentRequest(BaseModel):
    """Model for bracket payment update"""
    teamId: str
    roundKey: str
    amount: float
    status: str = "paid"
    paymentMethod: Optional[str] = "manual"
    transactionId: Optional[str] = None


class TeamDetailsResponse(BaseModel):
    """Model for team details response"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None



# Activity System Models
class ActivityType:
    """Activity type constants"""
    USER_JOINED = "user_joined"
    USER_REGISTERED_TOURNAMENT = "user_registered_tournament"
    TOURNAMENT_ANNOUNCED = "tournament_announced"
    TOURNAMENT_REGISTRATION_OPENING = "tournament_registration_opening"
    TOURNAMENT_REGISTRATION_CLOSING = "tournament_registration_closing"
    TOURNAMENT_STARTED = "tournament_started"
    TOURNAMENT_ENDED = "tournament_ended"
    LEADERBOARD_UPDATED = "leaderboard_updated"
    PAYMENT_COMPLETED = "payment_completed"
    ROUND_STARTED = "round_started"
    ROUND_COMPLETED = "round_completed"
    TEAM_ADVANCED = "team_advanced"
    TOURNAMENT_STATUS_CHANGED = "tournament_status_changed"


class ActivityCreate(BaseModel):
    """Model for creating an activity"""
    type: str
    title: str
    description: str
    userId: Optional[str] = None
    username: Optional[str] = None
    tournamentId: Optional[str] = None
    tournamentTitle: Optional[str] = None
    tournamentSlug: Optional[str] = None
    teamId: Optional[str] = None
    teamName: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}
    priority: str = "normal"  # low, normal, high, urgent


class ActivityResponse(BaseModel):
    """Model for activity response"""
    id: str
    type: str
    title: str
    description: str
    userId: Optional[str] = None
    username: Optional[str] = None
    tournamentId: Optional[str] = None
    tournamentTitle: Optional[str] = None
    tournamentSlug: Optional[str] = None
    teamId: Optional[str] = None
    teamName: Optional[str] = None
    metadata: Dict[str, Any] = {}
    priority: str = "normal"
    timestamp: str
    timeAgo: Optional[str] = None


class ActivityListResponse(BaseModel):
    """Model for activity list response"""
    success: bool
    data: List[ActivityResponse]
    total: int
    page: int
    limit: int

# Content Moderation Models
class ModerationReview(BaseModel):
    """Model for manual moderation review"""
    reviewId: str
    tournamentId: str
    organizerId: str
    reviewerId: str
    action: str  # approve, reject, flag, request_changes
    notes: str
    flaggedContent: List[str] = []
    reviewedAt: str
    priority: str = "normal"  # low, normal, high, urgent


class ModerationQueueItem(BaseModel):
    """Model for moderation queue items"""
    queueId: str
    tournamentId: str
    organizerId: str
    organizerEmail: str
    tournamentTitle: str
    flaggedFields: List[str]
    priority: str = "normal"
    status: str = "pending"  # pending, in_review, completed
    assignedTo: Optional[str] = None
    createdAt: str
    reviewedAt: Optional[str] = None


class ModerationAction(BaseModel):
    """Model for moderation actions"""
    action: str = Field(..., pattern=r"^(approve|reject|flag|request_changes|escalate)$")
    notes: str = Field(..., min_length=10, max_length=1000)
    notifyOrganizer: bool = True


class ModerationStats(BaseModel):
    """Model for moderation statistics"""
    totalReviews: int = 0
    pendingReviews: int = 0
    approvedToday: int = 0
    rejectedToday: int = 0
    averageReviewTime: float = 0.0  # in minutes
    topReviewers: List[Dict[str, Any]] = []


class ContentModerationResult(BaseModel):
    """Model for content moderation results"""
    isApproved: bool
    confidenceScore: float
    flaggedContent: List[str] = []
    suggestedAction: str
    reason: str
    requiresManualReview: bool = False


class DisputeTicket(BaseModel):
    """Model for dispute resolution tickets"""
    ticketId: str
    tournamentId: str
    organizerId: str
    reporterId: str
    reporterEmail: str
    
    # Dispute details
    disputeType: str  # refund_request, organizer_misconduct, tournament_cancellation, technical_issue
    priority: str = "normal"  # low, normal, high, urgent
    status: str = "open"  # open, in_progress, resolved, closed
    
    # Content
    title: str = Field(..., min_length=5, max_length=100)
    description: str = Field(..., min_length=20, max_length=2000)
    evidence: List[str] = []  # URLs to evidence files/screenshots
    
    # Resolution
    assignedTo: Optional[str] = None
    resolution: Optional[str] = None
    resolutionNotes: Optional[str] = None
    refundAmount: Optional[float] = None
    
    # Timestamps
    createdAt: str
    updatedAt: str
    resolvedAt: Optional[str] = None
    
    # Communication
    messages: List[Dict[str, Any]] = []


class SupportTicket(BaseModel):
    """Model for general support tickets"""
    ticketId: str
    userId: str
    userEmail: str
    
    # Ticket details
    category: str  # technical, payment, tournament, account, other
    priority: str = "normal"
    status: str = "open"
    
    # Content
    subject: str = Field(..., min_length=5, max_length=100)
    description: str = Field(..., min_length=10, max_length=2000)
    attachments: List[str] = []
    
    # Assignment and resolution
    assignedTo: Optional[str] = None
    tags: List[str] = []
    resolution: Optional[str] = None
    satisfactionRating: Optional[int] = Field(None, ge=1, le=5)
    
    # Timestamps
    createdAt: str
    updatedAt: str
    resolvedAt: Optional[str] = None
    
    # Communication thread
    messages: List[Dict[str, Any]] = []


# Enhanced Ticket Models for API Integration
class TicketCreateRequest(BaseModel):
    """Model for creating new tickets from frontend"""
    issueType: str = Field(..., pattern=r"^(tournament|payment|technical|account|other)$", description="Type of issue")
    priority: str = Field(..., pattern=r"^(low|medium|high|critical)$", description="Priority level")
    subject: str = Field(..., min_length=5, max_length=100, description="Brief description of the issue")
    description: str = Field(..., min_length=10, max_length=2000, description="Detailed description of the issue")
    tournamentId: Optional[str] = Field(None, description="Tournament ID if issue is tournament-related")
    attachments: List[str] = Field(default=[], max_items=5, description="List of attachment file paths")

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, v: str) -> str:
        """Validate and sanitize subject"""
        if not v.strip():
            raise ValueError("Subject cannot be empty")
        # Remove any HTML tags and excessive whitespace
        import re
        cleaned = re.sub(r'<[^>]+>', '', v.strip())
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Validate and sanitize description"""
        if not v.strip():
            raise ValueError("Description cannot be empty")
        # Remove any HTML tags and excessive whitespace
        import re
        cleaned = re.sub(r'<[^>]+>', '', v.strip())
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned

    @field_validator("attachments")
    @classmethod
    def validate_attachments(cls, v: List[str]) -> List[str]:
        """Validate attachment file paths"""
        if not v:
            return []
        
        # Validate each attachment path
        valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt']
        validated_attachments = []
        
        for attachment in v:
            if not attachment.strip():
                continue
            
            # Check file extension
            import os
            _, ext = os.path.splitext(attachment.lower())
            if ext not in valid_extensions:
                raise ValueError(f"Invalid file type: {ext}. Allowed types: {', '.join(valid_extensions)}")
            
            validated_attachments.append(attachment.strip())
        
        return validated_attachments


class TicketResponse(BaseModel):
    """Model for ticket operation responses"""
    success: bool
    ticketId: Optional[str] = None
    message: str
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None


class TicketListRequest(BaseModel):
    """Model for ticket list requests with filtering and pagination"""
    page: int = Field(1, ge=1, description="Page number")
    limit: int = Field(10, ge=1, le=100, description="Items per page")
    status: Optional[str] = Field(None, pattern=r"^(open|in_progress|resolved|closed)$", description="Filter by status")
    category: Optional[str] = Field(None, pattern=r"^(tournament|payment|technical|account|other)$", description="Filter by category")
    priority: Optional[str] = Field(None, pattern=r"^(low|medium|high|critical)$", description="Filter by priority")
    search: Optional[str] = Field(None, min_length=1, max_length=100, description="Search in subject and description")

    @field_validator("search")
    @classmethod
    def validate_search(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize search query"""
        if not v:
            return None
        
        # Remove any HTML tags and excessive whitespace
        import re
        cleaned = re.sub(r'<[^>]+>', '', v.strip())
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned if cleaned else None


class TicketListResponse(BaseModel):
    """Model for ticket list responses"""
    success: bool
    data: Dict[str, Any]
    message: Optional[str] = None


class AdminTicketUpdate(BaseModel):
    """Model for admin ticket updates"""
    status: Optional[str] = Field(None, pattern=r"^(open|in_progress|resolved|closed)$")
    assignedTo: Optional[str] = None
    tags: Optional[List[str]] = Field(None, max_items=10)
    priority: Optional[str] = Field(None, pattern=r"^(low|medium|high|critical)$")
    resolution: Optional[str] = Field(None, max_length=1000)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate and sanitize tags"""
        if not v:
            return None
        
        validated_tags = []
        for tag in v:
            if not tag.strip():
                continue
            
            # Remove any HTML tags and limit length
            import re
            cleaned = re.sub(r'<[^>]+>', '', tag.strip())
            cleaned = re.sub(r'\s+', ' ', cleaned)
            
            if len(cleaned) > 50:
                cleaned = cleaned[:50]
            
            if cleaned:
                validated_tags.append(cleaned)
        
        return validated_tags if validated_tags else None

    @field_validator("resolution")
    @classmethod
    def validate_resolution(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize resolution text"""
        if not v:
            return None
        
        # Remove any HTML tags and excessive whitespace
        import re
        cleaned = re.sub(r'<[^>]+>', '', v.strip())
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned if cleaned else None


class TicketMessage(BaseModel):
    """Model for ticket messages"""
    messageId: str
    senderId: str
    senderRole: str = Field(..., pattern=r"^(user|admin)$")
    content: str = Field(..., min_length=1, max_length=2000)
    attachments: List[str] = Field(default=[])
    timestamp: str
    isInternal: bool = Field(default=False, description="Internal admin notes not visible to users")

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        """Validate and sanitize message content"""
        if not v.strip():
            raise ValueError("Message content cannot be empty")
        
        # Remove any HTML tags and excessive whitespace
        import re
        cleaned = re.sub(r'<[^>]+>', '', v.strip())
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned


class TicketStats(BaseModel):
    """Model for ticket statistics"""
    totalTickets: int = 0
    openTickets: int = 0
    inProgressTickets: int = 0
    resolvedTickets: int = 0
    closedTickets: int = 0
    highPriorityTickets: int = 0
    criticalPriorityTickets: int = 0
    averageResolutionTime: float = 0.0  # in hours
    ticketsByCategory: Dict[str, int] = {}
    ticketsByPriority: Dict[str, int] = {}


# User Tournament Hosting Models (Host-specific tournaments)
class VenueZone(BaseModel):
    """Model for venue zone details"""
    zoneId: str
    zoneName: str
    capacity: int
    pricePerSlot: float
    amenities: List[str] = []


class VenueDetails(BaseModel):
    """Model for venue details"""
    venueId: str
    venueName: str
    address: str
    city: str
    state: str
    country: str
    zones: List[VenueZone] = []
    totalCapacity: int
    contactInfo: Dict[str, str] = {}







# Response Models for Content Moderation
class ModerationResponse(BaseModel):
    """Response model for moderation operations"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: str
    queueItemId: Optional[str] = None


class DisputeResponse(BaseModel):
    """Response model for dispute operations"""
    success: bool
    data: Optional[DisputeTicket] = None
    message: str
    ticketId: Optional[str] = None


class SupportResponse(BaseModel):
    """Response model for support operations"""
    success: bool
    data: Optional[SupportTicket] = None
    message: str
    ticketId: Optional[str] = None

# In models.py, add the following model:

class AdminWithdrawalAction(BaseModel):
    """Model for admin action on a withdrawal request"""
    action: str = Field(..., pattern=r"^(complete|fail)$", description="Action to take: 'complete' or 'fail'")
    notes: Optional[str] = Field(None, max_length=500, description="Admin notes regarding the decision")


class RoomDetails(BaseModel):
    """Model for room details"""
    round: str = Field(..., min_length=1, max_length=100, description="Round or match name")
    matchTime: str = Field(..., description="Match start time in ISO format")
    roomId: str = Field(..., min_length=1, max_length=50, description="Room/Lobby ID")
    password: str = Field(..., min_length=1, max_length=50, description="Room/Match password")

    @field_validator("round")
    @classmethod
    def validate_round(cls, v: str) -> str:
        """Validate round name"""
        v = v.strip()
        if len(v) < 1:
            raise ValueError("Round name cannot be empty")
        return v

    @field_validator("roomId")
    @classmethod
    def validate_room_id(cls, v: str) -> str:
        """Validate room ID"""
        v = v.strip()
        if len(v) < 1:
            raise ValueError("Room ID cannot be empty")
        return v

    @field_validator("password")
    @classmethod
    def validate_password_field(cls, v: str) -> str:
        """Validate password"""
        v = v.strip()
        if len(v) < 1:
            raise ValueError("Password cannot be empty")
        return v


class RoomDetailsResponse(BaseModel):
    """Model for room details response"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None