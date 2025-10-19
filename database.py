import os
from datetime import datetime, timedelta
from pymongo import MongoClient
from dotenv import load_dotenv
from bson import ObjectId
import re

# Load environment variables
load_dotenv()

# MongoDB connection
client = None
database = None

def get_database():
    """Get MongoDB database instance"""
    global client, database
    
    if database is None:
        try:
            mongodb_url = os.getenv("MONGODB_URL")
            if not mongodb_url:
                raise ValueError("MONGODB_URL environment variable is not set")
            
            print(f"Connecting to MongoDB with URL: {mongodb_url[:50]}...")
            client = MongoClient(mongodb_url)
            
            # Test the connection
            client.admin.command('ping')
            print("✅ MongoDB connection test successful")
            
            # Extract database name from URL or use default
            database_name = None
            if '/' in mongodb_url:
                # Extract database name from URL (after the last /)
                url_parts = mongodb_url.split('/')
                if len(url_parts) > 3:
                    # Remove query parameters if present
                    db_part = url_parts[-1].split('?')[0]
                    if db_part:
                        database_name = db_part
            
            # Use extracted name or default
            if database_name:
                database = client[database_name]
                print(f"✅ Using database: {database_name}")
            else:
                # Use a default database name
                database = client["tournament_platform"]
                print("✅ Using default database: tournament_platform")
            
            print("✅ Connected to MongoDB Atlas successfully")
            
        except Exception as e:
            print(f"❌ Failed to connect to MongoDB: {e}")
            print(f"MongoDB URL format: {mongodb_url[:20]}...")
            raise e
    
    return database

def create_user(username: str, email: str, password_hash: str, role: str = "user", contact_phone: str = None, firstName: str = None, lastName: str = None):
    """Create a new user in the database"""
    try:
        db = get_database()
        users_collection = db.users
        
        # Check if user already exists (email or username)
        existing_user = users_collection.find_one({
            "$or": [
                {"email": email},
                {"username": username}
            ]
        })
        if existing_user:
            if existing_user.get("email") == email:
                raise ValueError("Email already exists")
            else:
                raise ValueError("Username already exists")
        
        # Create user document
        user_doc = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "role": role,
            "created_at": datetime.utcnow()
        }
        
        # Add optional fields if provided
        if contact_phone:
            user_doc["contact_phone"] = contact_phone
        if firstName:
            user_doc["firstName"] = firstName
        if lastName:
            user_doc["lastName"] = lastName
        
        result = users_collection.insert_one(user_doc)
        return str(result.inserted_id)
        
    except ValueError as e:
        # Re-raise validation errors
        raise e
    except Exception as e:
        print(f"Error creating user: {e}")
        raise e

def get_user_by_email(email: str):
    """Find user by email address"""
    try:
        db = get_database()
        users_collection = db.users
        
        user = users_collection.find_one({"email": email})
        return user
        
    except Exception as e:
        print(f"Error finding user: {e}")
        raise e

def find_user_id_by_email(email: str) -> str:
    """Find user ID by email address"""
    try:
        db = get_database()
        users_collection = db.users
        
        user = users_collection.find_one({"email": email.lower()}, {"_id": 1})
        if user:
            return str(user["_id"])
        return None
        
    except Exception as e:
        print(f"Error finding user ID by email {email}: {e}")
        return None

def get_user_by_id(user_id: str):
    """Find user by user ID"""
    try:
        db = get_database()
        users_collection = db.users
        
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        return user
        
    except Exception as e:
        print(f"Error finding user by ID {user_id}: {e}")
        return None

def enhance_registration_with_user_ids(registration_data: dict, logged_in_user_id: str, logged_in_user_email: str) -> dict:
    """Add user ID information to registration data"""
    try:
        enhanced_data = registration_data.copy()
        
        # Add the user who registered this team
        enhanced_data["registeredBy"] = logged_in_user_id
        
        # Check if the captain email matches the logged-in user
        captain_email = enhanced_data.get("captainEmail", "").lower()
        if captain_email == logged_in_user_email.lower():
            enhanced_data["captainUserId"] = logged_in_user_id
            print(f"✅ Captain user ID linked: {logged_in_user_id}")
        else:
            # Try to find captain user ID by email
            captain_user_id = find_user_id_by_email(captain_email)
            if captain_user_id:
                enhanced_data["captainUserId"] = captain_user_id
                print(f"✅ Captain user ID found by email: {captain_user_id}")
        
        # Enhance player data with user IDs
        if "players" in enhanced_data:
            enhanced_players = []
            for player in enhanced_data["players"]:
                enhanced_player = player.copy()
                player_email = player.get("email", "").lower()
                
                # Try to find user ID for this player
                player_user_id = find_user_id_by_email(player_email)
                if player_user_id:
                    enhanced_player["userId"] = player_user_id
                    print(f"✅ Player user ID found: {player_user_id} for {player_email}")
                else:
                    print(f"ℹ️ No user account found for player email: {player_email}")
                
                enhanced_players.append(enhanced_player)
            
            enhanced_data["players"] = enhanced_players
        
        return enhanced_data
        
    except Exception as e:
        print(f"Error enhancing registration with user IDs: {e}")
        # Return original data if enhancement fails
        return registration_data

def batch_enhance_historical_registrations(limit: int = 100) -> dict:
    """Enhance historical tournament registrations with user IDs"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        stats = {
            "processed": 0,
            "enhanced": 0,
            "errors": 0,
            "details": []
        }
        
        # Find tournaments that don't have user ID enhancements yet
        tournaments = tournaments_collection.find({
            "participants": {"$exists": True, "$ne": []}
        }).limit(limit)
        
        for tournament in tournaments:
            try:
                tournament_updated = False
                enhanced_participants = []
                
                for participant in tournament.get("participants", []):
                    enhanced_participant = participant.copy()
                    participant_updated = False
                    
                    # Enhance captain user ID if missing
                    if "captainUserId" not in participant and "captainEmail" in participant:
                        captain_user_id = find_user_id_by_email(participant["captainEmail"])
                        if captain_user_id:
                            enhanced_participant["captainUserId"] = captain_user_id
                            participant_updated = True
                    
                    # Enhance player user IDs if missing
                    if "players" in participant:
                        enhanced_players = []
                        for player in participant["players"]:
                            enhanced_player = player.copy()
                            if "userId" not in player and "email" in player:
                                player_user_id = find_user_id_by_email(player["email"])
                                if player_user_id:
                                    enhanced_player["userId"] = player_user_id
                                    participant_updated = True
                            enhanced_players.append(enhanced_player)
                        enhanced_participant["players"] = enhanced_players
                    
                    enhanced_participants.append(enhanced_participant)
                    if participant_updated:
                        tournament_updated = True
                
                # Update tournament if any participants were enhanced
                if tournament_updated:
                    result = tournaments_collection.update_one(
                        {"_id": tournament["_id"]},
                        {"$set": {"participants": enhanced_participants}}
                    )
                    if result.modified_count > 0:
                        stats["enhanced"] += 1
                        stats["details"].append(f"Enhanced tournament: {tournament.get('title', 'Unknown')}")
                
                stats["processed"] += 1
                
            except Exception as e:
                stats["errors"] += 1
                stats["details"].append(f"Error processing tournament {tournament.get('_id')}: {str(e)}")
                print(f"Error processing tournament {tournament.get('_id')}: {e}")
        
        return stats
        
    except Exception as e:
        print(f"Error in batch enhancement: {e}")
        return {"processed": 0, "enhanced": 0, "errors": 1, "details": [str(e)]}

def validate_registration_data_consistency() -> dict:
    """Validate registration data consistency and report issues"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        validation_stats = {
            "total_tournaments": 0,
            "total_participants": 0,
            "issues_found": 0,
            "issues": []
        }
        
        tournaments = tournaments_collection.find({"participants": {"$exists": True, "$ne": []}})
        
        for tournament in tournaments:
            validation_stats["total_tournaments"] += 1
            tournament_title = tournament.get("title", "Unknown")
            
            for participant in tournament.get("participants", []):
                validation_stats["total_participants"] += 1
                participant_issues = []
                
                # Check for missing required fields
                if not participant.get("teamName"):
                    participant_issues.append("Missing team name")
                
                if not participant.get("captainEmail"):
                    participant_issues.append("Missing captain email")
                
                # Check for inconsistent user ID assignments
                captain_email = participant.get("captainEmail")
                captain_user_id = participant.get("captainUserId")
                
                if captain_email and captain_user_id:
                    # Verify that the user ID matches the email
                    actual_user_id = find_user_id_by_email(captain_email)
                    if actual_user_id and actual_user_id != captain_user_id:
                        participant_issues.append(f"Captain user ID mismatch: stored={captain_user_id}, actual={actual_user_id}")
                
                # Check player data consistency
                for i, player in enumerate(participant.get("players", [])):
                    if not player.get("email"):
                        participant_issues.append(f"Player {i+1} missing email")
                    
                    if not player.get("name"):
                        participant_issues.append(f"Player {i+1} missing name")
                    
                    # Check player user ID consistency
                    player_email = player.get("email")
                    player_user_id = player.get("userId")
                    
                    if player_email and player_user_id:
                        actual_user_id = find_user_id_by_email(player_email)
                        if actual_user_id and actual_user_id != player_user_id:
                            participant_issues.append(f"Player {i+1} user ID mismatch: stored={player_user_id}, actual={actual_user_id}")
                
                # Report issues for this participant
                if participant_issues:
                    validation_stats["issues_found"] += len(participant_issues)
                    validation_stats["issues"].append({
                        "tournament": tournament_title,
                        "tournament_id": str(tournament["_id"]),
                        "team_name": participant.get("teamName", "Unknown"),
                        "issues": participant_issues
                    })
        
        return validation_stats
        
    except Exception as e:
        print(f"Error in data validation: {e}")
        return {"total_tournaments": 0, "total_participants": 0, "issues_found": 0, "issues": [], "error": str(e)}

def cleanup_duplicate_user_ids() -> dict:
    """Clean up duplicate or inconsistent user ID assignments"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        cleanup_stats = {
            "tournaments_processed": 0,
            "participants_fixed": 0,
            "players_fixed": 0,
            "errors": 0,
            "details": []
        }
        
        tournaments = tournaments_collection.find({"participants": {"$exists": True, "$ne": []}})
        
        for tournament in tournaments:
            cleanup_stats["tournaments_processed"] += 1
            tournament_updated = False
            updated_participants = []
            
            for participant in tournament.get("participants", []):
                updated_participant = participant.copy()
                participant_updated = False
                
                # Fix captain user ID if inconsistent
                captain_email = participant.get("captainEmail")
                if captain_email:
                    correct_user_id = find_user_id_by_email(captain_email)
                    current_user_id = participant.get("captainUserId")
                    
                    if correct_user_id and correct_user_id != current_user_id:
                        updated_participant["captainUserId"] = correct_user_id
                        participant_updated = True
                        cleanup_stats["participants_fixed"] += 1
                        cleanup_stats["details"].append(
                            f"Fixed captain user ID for {participant.get('teamName', 'Unknown')} in {tournament.get('title', 'Unknown')}"
                        )
                    elif not correct_user_id and current_user_id:
                        # Remove invalid user ID
                        updated_participant.pop("captainUserId", None)
                        participant_updated = True
                
                # Fix player user IDs if inconsistent
                if "players" in participant:
                    updated_players = []
                    for player in participant["players"]:
                        updated_player = player.copy()
                        player_email = player.get("email")
                        
                        if player_email:
                            correct_user_id = find_user_id_by_email(player_email)
                            current_user_id = player.get("userId")
                            
                            if correct_user_id and correct_user_id != current_user_id:
                                updated_player["userId"] = correct_user_id
                                participant_updated = True
                                cleanup_stats["players_fixed"] += 1
                            elif not correct_user_id and current_user_id:
                                # Remove invalid user ID
                                updated_player.pop("userId", None)
                                participant_updated = True
                        
                        updated_players.append(updated_player)
                    
                    updated_participant["players"] = updated_players
                
                updated_participants.append(updated_participant)
                if participant_updated:
                    tournament_updated = True
            
            # Update tournament if any participants were fixed
            if tournament_updated:
                try:
                    result = tournaments_collection.update_one(
                        {"_id": tournament["_id"]},
                        {"$set": {"participants": updated_participants}}
                    )
                    if result.modified_count == 0:
                        cleanup_stats["errors"] += 1
                        cleanup_stats["details"].append(f"Failed to update tournament: {tournament.get('title', 'Unknown')}")
                except Exception as e:
                    cleanup_stats["errors"] += 1
                    cleanup_stats["details"].append(f"Error updating tournament {tournament.get('title', 'Unknown')}: {str(e)}")
        
        return cleanup_stats
        
    except Exception as e:
        print(f"Error in cleanup: {e}")
        return {"tournaments_processed": 0, "participants_fixed": 0, "players_fixed": 0, "errors": 1, "details": [str(e)]}

def get_migration_status_report() -> dict:
    """Generate a comprehensive migration status report"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        report = {
            "total_tournaments": 0,
            "tournaments_with_participants": 0,
            "total_participants": 0,
            "participants_with_user_ids": 0,
            "players_with_user_ids": 0,
            "total_players": 0,
            "enhancement_coverage": {
                "captain_user_ids": 0,
                "registered_by_fields": 0,
                "player_user_ids": 0
            },
            "migration_progress": 0.0,
            "recommendations": []
        }
        
        tournaments = tournaments_collection.find({})
        
        for tournament in tournaments:
            report["total_tournaments"] += 1
            
            participants = tournament.get("participants", [])
            if participants:
                report["tournaments_with_participants"] += 1
                
                for participant in participants:
                    report["total_participants"] += 1
                    
                    # Check captain enhancements
                    if participant.get("captainUserId"):
                        report["enhancement_coverage"]["captain_user_ids"] += 1
                    
                    if participant.get("registeredBy"):
                        report["enhancement_coverage"]["registered_by_fields"] += 1
                    
                    # Check player enhancements
                    for player in participant.get("players", []):
                        report["total_players"] += 1
                        if player.get("userId"):
                            report["enhancement_coverage"]["player_user_ids"] += 1
        
        # Calculate migration progress
        total_entities = report["total_participants"] + report["total_players"]
        enhanced_entities = (
            report["enhancement_coverage"]["captain_user_ids"] + 
            report["enhancement_coverage"]["player_user_ids"]
        )
        
        if total_entities > 0:
            report["migration_progress"] = (enhanced_entities / total_entities) * 100
        
        # Generate recommendations
        if report["migration_progress"] < 50:
            report["recommendations"].append("Run historical data enhancement to improve user ID coverage")
        
        if report["enhancement_coverage"]["registered_by_fields"] < report["total_participants"] * 0.8:
            report["recommendations"].append("Many participants missing 'registeredBy' field - consider data cleanup")
        
        if report["total_tournaments"] > 0 and report["tournaments_with_participants"] == 0:
            report["recommendations"].append("No tournaments have participants - system may be new or data migration needed")
        
        return report
        
    except Exception as e:
        print(f"Error generating migration report: {e}")
        return {"error": str(e)}

def setup_database():
    """Set up database indexes and initial configuration"""
    try:
        print("Setting up database...")
        db = get_database()
        
        if db is None:
            raise ValueError("Failed to get database instance")
        
        print(f"Database instance type: {type(db)}")
        print(f"Database name: {db.name}")
        
        users_collection = db.users
        payments_collection = db.payments  # ADDED: Payment collection
        brackets_collection = db.brackets  # ADDED: Brackets collection
        activities_collection = db.activities  # ADDED: Activities collection
        
        # Create unique index on email
        print("Creating users collection indexes...")
        try:
            users_collection.create_index("email", unique=True)
            print("✅ Users email index created")
        except Exception as e:
            print(f"❌ Error creating users email index: {e}")
            raise e
        
        # ADDED: Create indexes for payments collection
        print("Creating payments collection indexes...")
        try:
            payments_collection.create_index("transactionId", unique=True)
            payments_collection.create_index("userEmail")
            payments_collection.create_index("tournamentSlug")
            payments_collection.create_index("status")
            payments_collection.create_index("createdAt")
            print("✅ Payments indexes created")
        except Exception as e:
            print(f"❌ Error creating payments indexes: {e}")
            raise e
        
        # ADDED: Create indexes for brackets collection
        print("Creating brackets collection indexes...")
        try:
            brackets_collection.create_index("tournamentId", unique=True)
            brackets_collection.create_index("createdAt")
            brackets_collection.create_index("updatedAt")
            print("✅ Brackets indexes created")
        except Exception as e:
            print(f"❌ Error creating brackets indexes: {e}")
            raise e
        
        # ADDED: Create indexes for activities collection
        print("Creating activities collection indexes...")
        try:
            print("Creating timestamp index...")
            activities_collection.create_index([("timestamp", -1)])  # For sorting by time
            print("Creating type index...")
            activities_collection.create_index("type")
            print("Creating userId index...")
            activities_collection.create_index("userId")
            print("Creating tournamentId index...")
            activities_collection.create_index("tournamentId")
            print("Creating priority index...")
            activities_collection.create_index("priority")
            print("Creating createdAt index...")
            activities_collection.create_index("createdAt")
            print("✅ Activities indexes created")
        except Exception as e:
            print(f"❌ Error creating activities indexes: {e}")
            print(f"Error type: {type(e)}")
            print(f"Error details: {str(e)}")
            raise e

    # ADD THIS BLOCK TO FIX THE ERROR
    except Exception as e:
        print(f"❌ An error occurred during database setup: {e}")
        raise e
        
        
def create_admin_user(username: str, email: str, password_hash: str):
    """Create an admin user in the database"""
    try:
        db = get_database()
        users_collection = db.users
        
        # Check if user already exists (email or username)
        existing_user = users_collection.find_one({
            "$or": [
                {"email": email},
                {"username": username}
            ]
        })
        if existing_user:
            if existing_user.get("email") == email:
                raise ValueError("Email already exists")
            else:
                raise ValueError("Username already exists")
        
        # Create admin user document
        user_doc = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "role": "admin",  # Admin role
            "created_at": datetime.utcnow()
        }
        
        result = users_collection.insert_one(user_doc)
        return str(result.inserted_id)
        
    except ValueError as e:
        # Re-raise validation errors
        raise e
    except Exception as e:
        print(f"Error creating admin user: {e}")
        raise e

# ADDED: Payment-related database functions
def create_payment_record(payment_data: dict) -> str:
    """Create payment record in database"""
    try:
        db = get_database()
        payments_collection = db.payments
        result = payments_collection.insert_one(payment_data)
        print(f"✅ Payment record created: {payment_data['transactionId']}")
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error creating payment record: {e}")
        raise e

def update_payment_status(transaction_id: str, status: str, payu_response: dict = None):
    """Update payment status in database (PRODUCTION VERSION)"""
    try:
        db = get_database()
        payments_collection = db.payments
        
        # Search directly by the provided ID (no TEST_ prefix handling)
        search_id = transaction_id
        
        update_data = {
            "status": status,
            "updatedAt": datetime.utcnow().isoformat()
        }
        
        if payu_response:
            update_data["payuResponse"] = payu_response
        
        result = payments_collection.update_one(
            {"transactionId": search_id},
            {"$set": update_data}
        )
        print(f"✅ Payment status updated: {transaction_id} -> {status} (Target ID: {search_id})")
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating payment status: {e}")
        raise e

def get_payment_by_transaction_id(transaction_id: str):
    """Get payment record by transaction ID (PRODUCTION VERSION)"""
    try:
        db = get_database()
        payments_collection = db.payments
        
        # Only search for the ID provided (no TEST_ prefix handling)
        payment = payments_collection.find_one({"transactionId": transaction_id})

        return payment
        
    except Exception as e:
        print(f"Error fetching payment by transaction ID: {e}")
        raise e

def get_user_payments(user_email: str, limit: int = 50):
    """Get all payments for a specific user"""
    try:
        db = get_database()
        payments_collection = db.payments
        
        payments = list(payments_collection.find(
            {"userEmail": user_email},
            {"payuData": 0}  # Exclude sensitive PayU data
        ).sort("createdAt", -1).limit(limit))
        
        # Convert ObjectId to string
        for payment in payments:
            payment["_id"] = str(payment["_id"])
        
        return payments
    except Exception as e:
        print(f"Error fetching user payments: {e}")
        raise e

def get_tournament_payments(tournament_slug: str):
    """Get all payments for a specific tournament (admin function)"""
    try:
        db = get_database()
        payments_collection = db.payments
        
        payments = list(payments_collection.find(
            {"tournamentSlug": tournament_slug},
            {"payuData.hash": 0}  # Exclude sensitive hash data
        ).sort("createdAt", -1))
        
        # Convert ObjectId to string
        for payment in payments:
            payment["_id"] = str(payment["_id"])
        
        return payments
    except Exception as e:
        print(f"Error fetching tournament payments: {e}")
        raise e

def get_payment_statistics():
    """Get payment statistics for admin dashboard"""
    try:
        db = get_database()
        payments_collection = db.payments
        
        # Aggregate statistics
        stats = {
            "total_payments": payments_collection.count_documents({}),
            "successful_payments": payments_collection.count_documents({"status": "success"}),
            "failed_payments": payments_collection.count_documents({"status": "failed"}),
            "pending_payments": payments_collection.count_documents({"status": "initiated"}),
            "total_revenue": 0
        }
        
        # Calculate total revenue from successful payments
        revenue_pipeline = [
            {"$match": {"status": "success"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]
        
        revenue_result = list(payments_collection.aggregate(revenue_pipeline))
        if revenue_result:
            stats["total_revenue"] = revenue_result[0]["total"]
        
        return stats
    except Exception as e:
        print(f"Error fetching payment statistics: {e}")
        raise e

# END OF ADDED PAYMENT FUNCTIONS

def create_tournament_in_db(tournament_data: dict):
    """Create a new tournament in the database"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        # Generate a URL-friendly slug from the title
        slug = re.sub(r'[^\w]+', '-', tournament_data['title'].lower())
        tournament_data['slug'] = slug
        
        result = tournaments_collection.insert_one(tournament_data)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error creating tournament: {e}")
        raise e

def get_all_tournaments_from_db():
    """Get all tournaments from the database with participant counts and dynamic status"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        tournaments = list(tournaments_collection.find({}))

        # Add participant count and dynamic status to each tournament
        for tournament in tournaments:
            # Convert ObjectId to string for JSON serialization
            if '_id' in tournament:
                tournament['_id'] = str(tournament['_id'])
            
            participants = tournament.get("participants", [])
            # Convert participant ObjectIds to strings
            for participant in participants:
                if '_id' in participant:
                    participant['_id'] = str(participant['_id'])
            
            tournament["participant_count"] = len(participants)

            # If format is 'kp', ensure maxTeams is set correctly to 100
            if tournament.get("format") == "kp" and "kpSettings" in tournament:
                kp_settings = tournament["kpSettings"]
                # Calculate total teams: 4 groups * 25 teams/group = 100
                tournament["maxTeams"] = kp_settings.get("groupSize", 25) * kp_settings.get("numberOfGroups", 4)

        return tournaments
    except Exception as e:
        print(f"Error fetching tournaments: {e}")
        raise e
    
# In database.py, replace the entire function

def get_tournaments_by_host_id(host_id: str, status: str = None, search: str = None, sort_by: str = 'createdAt', sort_order: str = 'desc'):
    """Get all tournaments for a specific host with filtering and sorting."""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        query = {"hostId": host_id}
        
        if status and status != 'all':
            query["status"] = status
        
        if search:
            query["$or"] = [
                {"title": {"$regex": search, "$options": "i"}},
                {"game": {"$regex": search, "$options": "i"}},
            ]
            
        sort_direction = -1 if sort_order == 'desc' else 1
        
        tournaments = list(tournaments_collection.find(query).sort(sort_by, sort_direction))

        # Add participant count and convert all ObjectIds to strings
        for tournament in tournaments:
            tournament['_id'] = str(tournament['_id'])
            participants = tournament.get("participants", [])
            
            # --- THIS IS THE FIX ---
            # Loop through participants and convert their _id as well
            for participant in participants:
                if '_id' in participant:
                    participant['_id'] = str(participant['_id'])
            # ---------------------
            
            tournament["participant_count"] = len(participants)

        return tournaments
    except Exception as e:
        print(f"Error fetching tournaments for host {host_id}: {e}")
        raise e

def get_tournament_by_slug_from_db(slug: str):
    """Get a single tournament by its slug with participant count and dynamic status"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        tournament = tournaments_collection.find_one({"slug": slug})
        
        if tournament:
            # Convert ObjectId to string for JSON serialization
            if '_id' in tournament:
                tournament['_id'] = str(tournament['_id'])
            
            # Add participant count and dynamic status
            participants = tournament.get("participants", [])
            # Convert participant ObjectIds to strings
            for participant in participants:
                if '_id' in participant:
                    participant['_id'] = str(participant['_id'])
            
            tournament["participant_count"] = len(participants)

            # Calculate prize distribution if format is 'kp' and prizePool is available
            if tournament.get("format") == "kp" and tournament.get("prizePool"):
                prize_pool = tournament["prizePool"]
                distribution = tournament.get("kpSettings", {}).get("prizeDistribution", {})
                
                # Default distribution if not specified
                first_dist = distribution.get("first", 0.5)
                second_dist = distribution.get("second", 0.3)
                third_dist = distribution.get("third", 0.2)

                tournament["prizeDistribution"] = {
                    "first": round(prize_pool * first_dist),
                    "second": round(prize_pool * second_dist),
                    "third": round(prize_pool * third_dist)
                }
        
        return tournament
    except Exception as e:
        print(f"Error fetching tournament by slug: {e}")
        raise e

def update_tournament_in_db(slug: str, update_data: dict):
    """Update a tournament in the database by its slug"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        # Ensure the slug is not changed by the update data
        if 'slug' in update_data:
            del update_data['slug']
        
        # Remove _id if present to prevent update conflicts
        if '_id' in update_data:
            del update_data['_id']
        
        result = tournaments_collection.update_one(
            {"slug": slug},
            {"$set": update_data}
        )
        
        print(f"✅ Tournament updated: {slug}, modified_count: {result.modified_count}")
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating tournament: {e}")
        raise e

def delete_tournament_from_db(slug: str):
    """Delete a tournament from the database by its slug"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        result = tournaments_collection.delete_one({"slug": slug})
        
        print(f"✅ Tournament deletion attempted: {slug}, deleted_count: {result.deleted_count}")
        return result.deleted_count > 0
        
    except Exception as e:
        print(f"Error deleting tournament: {e}")
        raise e

def check_tournament_has_participants(slug: str):
    """Check if a tournament has registered participants"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        tournament = tournaments_collection.find_one({"slug": slug})
        if not tournament:
            return False
        
        participants = tournament.get("participants", [])
        has_participants = len(participants) > 0
        
        print(f"✅ Tournament {slug} participant check: {len(participants)} participants")
        return has_participants
        
    except Exception as e:
        print(f"Error checking tournament participants: {e}")
        raise e

def distribute_kp_teams(participants, num_groups=4):
    """Distribute teams into groups for KP format tournaments"""
    import random
    
    # Shuffle teams for fair distribution
    teams = list(participants)
    random.shuffle(teams)
    
    # Calculate teams per group
    total_teams = len(teams)
    base_teams_per_group = total_teams // num_groups
    extra_teams = total_teams % num_groups
    
    groups = []
    start_idx = 0
    
    for i in range(num_groups):
        # Add extra team to first few groups if needed
        group_size = base_teams_per_group + (1 if i < extra_teams else 0)
        end_idx = start_idx + group_size
        
        group_teams = teams[start_idx:end_idx]
        groups.append({
            "groupNumber": i + 1,
            "groupName": f"Qualifier {i + 1}",
            "teams": group_teams,
            "teamCount": len(group_teams)
        })
        
        start_idx = end_idx
    
    return groups

# Add this new function to the end of database.py

def get_tournaments_for_user(user_email: str, user_id: str = None):
    """
    Find all tournaments a user has joined by checking if their primary email 
    is used to participate in any tournament event.
    """
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        user_email_lower = user_email.lower()
        
        # Simple email-based query to find tournaments where user participated
        email_query = {
            "participants": {
                "$elemMatch": {
                    "$or": [
                        {"captainEmail": user_email_lower},
                        {"players.email": user_email_lower}
                    ]
                }
            }
        }
        
        tournaments = list(tournaments_collection.find(email_query))
        
        # Convert ObjectId to string and add basic participation info
        result_tournaments = []
        for tournament in tournaments:
            tournament['_id'] = str(tournament['_id'])
            
            # Find user's participation details
            participation_info = find_user_participation_in_tournament(
                tournament, user_email, user_id
            )
            
            if participation_info:
                tournament.update(participation_info)
                result_tournaments.append(tournament)
        
        return result_tournaments
        
    except Exception as e:
        print(f"Error fetching tournaments for user {user_email}: {e}")
        raise e

def find_user_participation_in_tournament(tournament: dict, user_email: str, user_id: str = None) -> dict:
    """Find how a user participates in a specific tournament"""
    try:
        participation_info = {
            "user_team_name": None,
            "user_role": None,
            "participation_type": None,
            "registration_email": None,
            "team_id": None
        }
        
        participants = tournament.get("participants", [])
        user_email_lower = user_email.lower()
        
        for participant in participants:
            participant_id = str(participant.get("_id", ""))
            
            # Check if user registered this team
            if user_id and participant.get("registeredBy") == user_id:
                participation_info.update({
                    "user_team_name": participant.get("teamName"),
                    "user_role": "registered_by",
                    "participation_type": "user_id",
                    "registration_email": participant.get("captainEmail", ""),
                    "team_id": participant_id
                })
                return participation_info
            
            # Check if user is the captain (by user ID)
            if user_id and participant.get("captainUserId") == user_id:
                participation_info.update({
                    "user_team_name": participant.get("teamName"),
                    "user_role": "captain",
                    "participation_type": "user_id",
                    "registration_email": participant.get("captainEmail", ""),
                    "team_id": participant_id
                })
                return participation_info
            
            # Check if user is the captain (by email)
            if participant.get("captainEmail", "").lower() == user_email_lower:
                participation_info.update({
                    "user_team_name": participant.get("teamName"),
                    "user_role": "captain",
                    "participation_type": "email_match",
                    "registration_email": participant.get("captainEmail", ""),
                    "team_id": participant_id
                })
                return participation_info
            
            # Check if user is in players list (by user ID)
            if user_id:
                for player in participant.get("players", []):
                    if player.get("userId") == user_id:
                        participation_info.update({
                            "user_team_name": participant.get("teamName"),
                            "user_role": "player",
                            "participation_type": "user_id",
                            "registration_email": player.get("email", ""),
                            "team_id": participant_id
                        })
                        return participation_info
            
            # Check if user is in players list (by email)
            for player in participant.get("players", []):
                if player.get("email", "").lower() == user_email_lower:
                    participation_info.update({
                        "user_team_name": participant.get("teamName"),
                        "user_role": "player",
                        "participation_type": "email_match",
                        "registration_email": player.get("email", ""),
                        "team_id": participant_id
                    })
                    return participation_info
        
        return None
        
    except Exception as e:
        print(f"Error finding user participation: {e}")
        return None

# Bracket Management Functions
def create_tournament_brackets(tournament_id: str, brackets_data: dict):
    """Create tournament brackets in the database"""
    try:
        db = get_database()
        brackets_collection = db.brackets
        
        # Add metadata
        brackets_data["tournamentId"] = tournament_id
        brackets_data["createdAt"] = datetime.utcnow().isoformat()
        brackets_data["updatedAt"] = datetime.utcnow().isoformat()
        
        result = brackets_collection.insert_one(brackets_data)
        print(f"✅ Brackets created for tournament: {tournament_id}")
        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error creating tournament brackets: {e}")
        raise e

def get_tournament_brackets(tournament_id: str):
    """Get tournament brackets by tournament ID"""
    try:
        db = get_database()
        brackets_collection = db.brackets
        
        brackets = brackets_collection.find_one({"tournamentId": tournament_id})
        if brackets:
            brackets['_id'] = str(brackets['_id'])
        
        return brackets
        
    except Exception as e:
        print(f"Error fetching tournament brackets: {e}")
        raise e

def update_tournament_brackets(tournament_id: str, update_data: dict):
    """Update tournament brackets"""
    try:
        db = get_database()
        brackets_collection = db.brackets
        
        update_data["updatedAt"] = datetime.utcnow().isoformat()
        
        result = brackets_collection.update_one(
            {"tournamentId": tournament_id},
            {"$set": update_data}
        )
        
        print(f"✅ Brackets updated for tournament: {tournament_id}")
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating tournament brackets: {e}")
        raise e

def update_round_status(tournament_id: str, round_key: str, status: str):
    """Update the status of a specific round"""
    try:
        db = get_database()
        brackets_collection = db.brackets
        
        update_data = {
            f"rounds.{round_key}.status": status,
            "updatedAt": datetime.utcnow().isoformat()
        }
        
        result = brackets_collection.update_one(
            {"tournamentId": tournament_id},
            {"$set": update_data}
        )
        
        print(f"✅ Round {round_key} status updated to {status} for tournament: {tournament_id}")
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating round status: {e}")
        raise e

def update_team_payment_status(tournament_id: str, team_id: str, round_key: str, payment_data: dict):
    """Update team payment status for a specific round"""
    try:
        db = get_database()
        brackets_collection = db.brackets
        
        # Find the team in the specific round and update payment status
        brackets = get_tournament_brackets(tournament_id)
        if not brackets:
            raise ValueError("Brackets not found")
        
        # Update the team's payment status in the round
        for team in brackets["rounds"][round_key]["teams"]:
            if team["teamId"] == team_id:
                team["paymentStatus"] = payment_data.get("status", "paid")
                break
        
        # Update the brackets
        result = brackets_collection.update_one(
            {"tournamentId": tournament_id},
            {"$set": {
                f"rounds.{round_key}.teams": brackets["rounds"][round_key]["teams"],
                f"payments.{team_id}.{round_key}": payment_data,
                "updatedAt": datetime.utcnow().isoformat()
            }}
        )
        
        print(f"✅ Payment status updated for team {team_id} in round {round_key}")
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating team payment status: {e}")
        raise e

def advance_teams_to_next_round(tournament_id: str, current_round: str, qualifying_teams: list):
    """Advance qualifying teams to the next round"""
    try:
        db = get_database()
        brackets_collection = db.brackets
        
        # Define round progression
        round_progression = {
            "1": "2",
            "2": "3", 
            "3": "4",
            "4": "final"
        }
        
        next_round = round_progression.get(current_round)
        if not next_round:
            raise ValueError("Invalid round progression")
        
        # Get current brackets
        brackets = get_tournament_brackets(tournament_id)
        if not brackets:
            raise ValueError("Brackets not found")
        
        # Initialize next round if it doesn't exist
        if next_round not in brackets["rounds"]:
            brackets["rounds"][next_round] = {
                "status": "pending",
                "teams": [],
                "groups": []
            }
        
        # Add qualifying teams to next round
        for team_data in qualifying_teams:
            brackets["rounds"][next_round]["teams"].append({
                "teamId": team_data["teamId"],
                "teamName": team_data["teamName"],
                "status": "qualified",
                "paymentStatus": "pending",
                "score": 0,
                "position": None,
                "previousRoundScore": team_data.get("score", 0),
                "previousRoundPosition": team_data.get("position")
            })
        
        # Update current round status and brackets
        brackets["rounds"][current_round]["status"] = "completed"
        brackets["currentRound"] = int(next_round) if next_round.isdigit() else next_round
        
        result = brackets_collection.update_one(
            {"tournamentId": tournament_id},
            {"$set": brackets}
        )
        
        print(f"✅ Teams advanced from round {current_round} to {next_round}")
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error advancing teams to next round: {e}")
        raise e

def get_team_by_id(team_id: str):
    """Get team details by team ID from tournaments participants"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        # Find tournament containing this team
        tournament = tournaments_collection.find_one({
            "participants._id": ObjectId(team_id)
        })
        
        if tournament:
            # Find the specific team in participants
            for participant in tournament.get("participants", []):
                if str(participant.get("_id")) == team_id:
                    participant["_id"] = str(participant["_id"])
                    participant["tournamentId"] = str(tournament["_id"])
                    participant["tournamentTitle"] = tournament.get("title")
                    return participant
        
        return None
        
    except Exception as e:
        print(f"Error fetching team by ID: {e}")
        raise e

def get_user_team_in_tournament(tournament_id: str, user_email: str, user_id: str = None):
    """Get user's team in a specific tournament using enhanced lookup"""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        tournament = tournaments_collection.find_one({"_id": ObjectId(tournament_id)})
        if not tournament:
            return None
        
        user_email_lower = user_email.lower()
        
        # Find user's team in participants using multiple strategies
        for participant in tournament.get("participants", []):
            participant_found = False
            user_role = None
            
            # Strategy 1: Check by user ID (primary)
            if user_id:
                # Check if user registered this team
                if participant.get("registeredBy") == user_id:
                    participant_found = True
                    user_role = "registered_by"
                # Check if user is captain by user ID
                elif participant.get("captainUserId") == user_id:
                    participant_found = True
                    user_role = "captain"
                # Check if user is in players list by user ID
                else:
                    for player in participant.get("players", []):
                        if player.get("userId") == user_id:
                            participant_found = True
                            user_role = "player"
                            break
            
            # Strategy 2: Check by email (fallback)
            if not participant_found:
                # Check if user is captain by email
                if participant.get("captainEmail", "").lower() == user_email_lower:
                    participant_found = True
                    user_role = "captain"
                # Check if user is in players list by email
                else:
                    for player in participant.get("players", []):
                        if player.get("email", "").lower() == user_email_lower:
                            participant_found = True
                            user_role = "player"
                            break
            
            if participant_found:
                # Enhance participant data with user role information
                enhanced_participant = participant.copy()
                enhanced_participant["_id"] = str(participant.get("_id", ""))
                enhanced_participant["user_role"] = user_role
                enhanced_participant["participation_type"] = "user_id" if user_id and (
                    participant.get("registeredBy") == user_id or 
                    participant.get("captainUserId") == user_id or
                    any(p.get("userId") == user_id for p in participant.get("players", []))
                ) else "email_match"
                
                return enhanced_participant
        
        return None
        
    except Exception as e:
        print(f"Error fetching user team in tournament: {e}")
        raise e


# Activity System Functions
def create_activity(activity_data: dict):
    """Create a new activity record"""
    try:
        db = get_database()
        activities_collection = db.activities
        
        # Add timestamp and metadata
        activity_data["timestamp"] = datetime.utcnow().isoformat()
        activity_data["createdAt"] = datetime.utcnow()
        
        result = activities_collection.insert_one(activity_data)
        print(f"✅ Activity created: {activity_data['type']} - {activity_data['title']}")
        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error creating activity: {e}")
        raise e


def get_recent_activities(limit: int = 20, skip: int = 0, activity_type: str = None, user_id: str = None):
    """Get recent activities with optional filtering"""
    try:
        db = get_database()
        activities_collection = db.activities
        
        # Build query filter
        query = {}
        if activity_type:
            query["type"] = activity_type
        if user_id:
            query["userId"] = user_id
        
        # Get activities with pagination
        activities = list(activities_collection.find(query)
                         .sort("timestamp", -1)
                         .skip(skip)
                         .limit(limit))
        
        # Convert ObjectId to string and add time ago
        for activity in activities:
            activity["_id"] = str(activity["_id"])
            activity["id"] = activity["_id"]
            
            # Calculate time ago
            if "timestamp" in activity:
                activity_time = datetime.fromisoformat(activity["timestamp"].replace('Z', ''))
                time_diff = datetime.utcnow() - activity_time
                activity["timeAgo"] = format_time_ago(time_diff)
        
        # Get total count for pagination
        total_count = activities_collection.count_documents(query)
        
        return activities, total_count
        
    except Exception as e:
        print(f"Error fetching recent activities: {e}")
        raise e


def get_user_activities(user_id: str, limit: int = 20, skip: int = 0):
    """Get activities for a specific user"""
    try:
        db = get_database()
        activities_collection = db.activities
        
        # Get user-specific activities
        activities = list(activities_collection.find({"userId": user_id})
                         .sort("timestamp", -1)
                         .skip(skip)
                         .limit(limit))
        
        # Convert ObjectId to string and add time ago
        for activity in activities:
            activity["_id"] = str(activity["_id"])
            activity["id"] = activity["_id"]
            
            # Calculate time ago
            if "timestamp" in activity:
                activity_time = datetime.fromisoformat(activity["timestamp"].replace('Z', ''))
                time_diff = datetime.utcnow() - activity_time
                activity["timeAgo"] = format_time_ago(time_diff)
        
        total_count = activities_collection.count_documents({"userId": user_id})
        
        return activities, total_count
        
    except Exception as e:
        print(f"Error fetching user activities: {e}")
        raise e


def get_tournament_activities(tournament_id: str, limit: int = 20):
    """Get activities for a specific tournament"""
    try:
        db = get_database()
        activities_collection = db.activities
        
        activities = list(activities_collection.find({"tournamentId": tournament_id})
                         .sort("timestamp", -1)
                         .limit(limit))
        
        # Convert ObjectId to string and add time ago
        for activity in activities:
            activity["_id"] = str(activity["_id"])
            activity["id"] = activity["_id"]
            
            # Calculate time ago
            if "timestamp" in activity:
                activity_time = datetime.fromisoformat(activity["timestamp"].replace('Z', ''))
                time_diff = datetime.utcnow() - activity_time
                activity["timeAgo"] = format_time_ago(time_diff)
        
        return activities
        
    except Exception as e:
        print(f"Error fetching tournament activities: {e}")
        raise e


def format_time_ago(time_diff):
    """Format time difference into human readable string"""
    seconds = int(time_diff.total_seconds())
    
    if seconds < 60:
        return "Just now"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m ago"
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{hours}h ago"
    elif seconds < 2592000:  # 30 days
        days = seconds // 86400
        return f"{days}d ago"
    else:
        months = seconds // 2592000
        return f"{months}mo ago"


def cleanup_old_activities(days_to_keep: int = 90):
    """Clean up activities older than specified days"""
    try:
        db = get_database()
        activities_collection = db.activities
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        result = activities_collection.delete_many({
            "createdAt": {"$lt": cutoff_date}
        })
        
        print(f"✅ Cleaned up {result.deleted_count} old activities")
        return result.deleted_count
        
    except Exception as e:
        print(f"Error cleaning up old activities: {e}")
        raise e


# Activity Helper Functions
def log_user_joined_activity(user_id: str, username: str, email: str):
    """Log when a user joins the platform"""
    activity_data = {
        "type": "user_joined",
        "title": f"Welcome {username}!",
        "description": f"{username} joined GamingNexus",
        "userId": user_id,
        "username": username,
        "priority": "normal",
        "metadata": {
            "email": email,
            "action": "registration"
        }
    }
    return create_activity(activity_data)


def log_tournament_registration_activity(user_id: str, username: str, tournament_id: str, 
                                       tournament_title: str, tournament_slug: str, team_name: str):
    """Log when a user registers for a tournament"""
    activity_data = {
        "type": "user_registered_tournament",
        "title": f"{username} registered for {tournament_title}",
        "description": f"Team '{team_name}' registered for {tournament_title}",
        "userId": user_id,
        "username": username,
        "tournamentId": tournament_id,
        "tournamentTitle": tournament_title,
        "tournamentSlug": tournament_slug,
        "teamName": team_name,
        "priority": "normal",
        "metadata": {
            "action": "tournament_registration",
            "teamName": team_name
        }
    }
    return create_activity(activity_data)


def log_tournament_announced_activity(tournament_id: str, tournament_title: str, 
                                    tournament_slug: str, admin_email: str, prize_pool: int = None):
    """Log when a new tournament is announced"""
    description = f"New tournament '{tournament_title}' has been announced"
    if prize_pool:
        description += f" with ₹{prize_pool:,} prize pool"
    
    activity_data = {
        "type": "tournament_announced",
        "title": f"🏆 New Tournament: {tournament_title}",
        "description": description,
        "tournamentId": tournament_id,
        "tournamentTitle": tournament_title,
        "tournamentSlug": tournament_slug,
        "priority": "high",
        "metadata": {
            "action": "tournament_creation",
            "createdBy": admin_email,
            "prizePool": prize_pool
        }
    }
    return create_activity(activity_data)


def log_tournament_status_activity(tournament_id: str, tournament_title: str, 
                                 tournament_slug: str, old_status: str, new_status: str):
    """Log when tournament status changes"""
    status_messages = {
        "registration_open": "Registration is now open",
        "registration_closed": "Registration has closed",
        "ongoing": "Tournament has started",
        "ended": "Tournament has ended"
    }
    
    message = status_messages.get(new_status, f"Status changed to {new_status}")
    
    activity_data = {
        "type": "tournament_status_changed",
        "title": f"{tournament_title}: {message}",
        "description": f"{tournament_title} status changed from {old_status} to {new_status}",
        "tournamentId": tournament_id,
        "tournamentTitle": tournament_title,
        "tournamentSlug": tournament_slug,
        "priority": "high" if new_status in ["registration_open", "ongoing"] else "normal",
        "metadata": {
            "action": "status_change",
            "oldStatus": old_status,
            "newStatus": new_status
        }
    }
    return create_activity(activity_data)


def log_round_activity(tournament_id: str, tournament_title: str, tournament_slug: str, 
                      round_key: str, action: str, admin_email: str):
    """Log round start/complete activities"""
    round_names = {
        "1": "Round 1",
        "2": "Round 2", 
        "3": "Round 3",
        "4": "Round 4",
        "final": "Finals"
    }
    
    round_name = round_names.get(round_key, f"Round {round_key}")
    
    if action == "started":
        title = f"🚀 {round_name} Started"
        description = f"{round_name} of {tournament_title} has begun"
        activity_type = "round_started"
    else:
        title = f"✅ {round_name} Completed"
        description = f"{round_name} of {tournament_title} has been completed"
        activity_type = "round_completed"
    
    activity_data = {
        "type": activity_type,
        "title": title,
        "description": description,
        "tournamentId": tournament_id,
        "tournamentTitle": tournament_title,
        "tournamentSlug": tournament_slug,
        "priority": "high",
        "metadata": {
            "action": action,
            "round": round_key,
            "roundName": round_name,
            "adminEmail": admin_email
        }
    }
    return create_activity(activity_data)


def log_payment_activity(user_id: str, username: str, tournament_id: str, 
                        tournament_title: str, amount: float, status: str):
    """Log payment completion activities"""
    if status == "success":
        title = f"💰 Payment Successful"
        description = f"{username} completed payment of ₹{amount:,.0f} for {tournament_title}"
        priority = "normal"
    else:
        title = f"❌ Payment Failed"
        description = f"Payment of ₹{amount:,.0f} failed for {username} in {tournament_title}"
        priority = "low"
    
    activity_data = {
        "type": "payment_completed",
        "title": title,
        "description": description,
        "userId": user_id,
        "username": username,
        "tournamentId": tournament_id,
        "tournamentTitle": tournament_title,
        "priority": priority,
        "metadata": {
            "action": "payment",
            "amount": amount,
            "status": status
        }
    }
    return create_activity(activity_data)


# Dispute Resolution Database Functions

def create_dispute_ticket(dispute_data: dict) -> str:
    """Create a new dispute ticket"""
    try:
        db = get_database()
        dispute_tickets = db.dispute_tickets
        
        # Generate human-readable ticket ID if not provided
        if "ticket_id" not in dispute_data:
            user_id = dispute_data.get("user_id") or dispute_data.get("reporter_id") or "unknown"
            dispute_data["ticket_id"] = f"dispute_{int(datetime.utcnow().timestamp())}_{user_id}"
        
        ticket_doc = {
            **dispute_data,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "messages": []
        }
        
        result = dispute_tickets.insert_one(ticket_doc)
        
        # Return the human-readable ticket ID instead of ObjectId
        return ticket_doc.get("ticket_id", str(result.inserted_id))
        
    except Exception as e:
        print(f"Error creating dispute ticket: {e}")
        raise e


def get_dispute_ticket(ticket_id: str) -> dict:
    """Get dispute ticket by ID"""
    try:
        db = get_database()
        dispute_tickets = db.dispute_tickets
        
        ticket = dispute_tickets.find_one({"_id": ObjectId(ticket_id)})
        
        if ticket:
            ticket['_id'] = str(ticket['_id'])
            
        return ticket
        
    except Exception as e:
        print(f"Error getting dispute ticket: {e}")
        raise e


def get_dispute_ticket_by_ticket_id(ticket_id: str) -> dict:
    """Get dispute ticket by human-readable ticket ID"""
    try:
        db = get_database()
        dispute_tickets = db.dispute_tickets
        
        ticket = dispute_tickets.find_one({"ticketId": ticket_id})
        
        if ticket:
            ticket['_id'] = str(ticket['_id'])
            
        return ticket
        
    except Exception as e:
        print(f"Error getting dispute ticket by ticket ID: {e}")
        raise e


def update_dispute_ticket(ticket_id: str, update_data: dict) -> bool:
    """Update dispute ticket"""
    try:
        db = get_database()
        dispute_tickets = db.dispute_tickets
        
        update_data["updated_at"] = datetime.utcnow()
        
        result = dispute_tickets.update_one(
            {"_id": ObjectId(ticket_id)},
            {"$set": update_data}
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating dispute ticket: {e}")
        raise e


def update_dispute_ticket_by_ticket_id(ticket_id: str, update_data: dict) -> bool:
    """Update dispute ticket by human-readable ticket ID"""
    try:
        db = get_database()
        dispute_tickets = db.dispute_tickets
        
        update_data["updated_at"] = datetime.utcnow()
        
        # Try to update by ticketId first
        result = dispute_tickets.update_one(
            {"ticketId": ticket_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            # Try by MongoDB _id as fallback
            try:
                result = dispute_tickets.update_one(
                    {"_id": ObjectId(ticket_id)},
                    {"$set": update_data}
                )
            except:
                pass
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating dispute ticket by ticket ID: {e}")
        raise e


def add_dispute_message(ticket_id: str, message_data: dict) -> bool:
    """Add a message to dispute ticket"""
    try:
        db = get_database()
        dispute_tickets = db.dispute_tickets
        
        message = {
            **message_data,
            "timestamp": datetime.utcnow()
        }
        
        result = dispute_tickets.update_one(
            {"_id": ObjectId(ticket_id)},
            {
                "$push": {"messages": message},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error adding dispute message: {e}")
        raise e


def get_dispute_tickets(status: str = None, limit: int = 50, skip: int = 0) -> list:
    """Get dispute tickets with optional status filter"""
    try:
        db = get_database()
        dispute_tickets = db.dispute_tickets
        
        query = {}
        if status:
            query["status"] = status
        
        tickets = list(dispute_tickets.find(query)
                      .sort("created_at", -1)
                      .skip(skip)
                      .limit(limit))
        
        # Convert ObjectId to string
        for ticket in tickets:
            ticket['_id'] = str(ticket['_id'])
            
        return tickets
        
    except Exception as e:
        print(f"Error getting dispute tickets: {e}")
        raise e


def create_support_ticket(support_data: dict) -> str:
    """Create a new support ticket with enhanced validation and indexing"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        # Ensure proper timestamp fields
        current_time = datetime.utcnow()
        ticket_doc = {
            **support_data,
            "created_at": current_time,
            "updated_at": current_time,
            "messages": []
        }
        
        # Ensure required fields have defaults
        if "status" not in ticket_doc:
            ticket_doc["status"] = "open"
        if "priority" not in ticket_doc:
            ticket_doc["priority"] = "medium"
        if "tags" not in ticket_doc:
            ticket_doc["tags"] = []
        if "attachments" not in ticket_doc:
            ticket_doc["attachments"] = []
        
        # Insert the ticket
        result = support_tickets.insert_one(ticket_doc)
        
        # Ensure indexes exist for efficient querying (use ticket_id to match data structure)
        try:
            support_tickets.create_index([("ticket_id", 1)], unique=True, background=True)
            support_tickets.create_index([("user_id", 1)], background=True)
            support_tickets.create_index([("status", 1)], background=True)
            support_tickets.create_index([("category", 1)], background=True)
            support_tickets.create_index([("priority", 1)], background=True)
            support_tickets.create_index([("created_at", -1)], background=True)
            support_tickets.create_index([("updated_at", -1)], background=True)
            # Compound indexes for common queries
            support_tickets.create_index([("user_id", 1), ("status", 1)], background=True)
            support_tickets.create_index([("status", 1), ("priority", 1)], background=True)
        except Exception as index_error:
            print(f"Warning: Could not create indexes: {index_error}")
        
        # Return the human-readable ticket ID instead of ObjectId
        return ticket_doc.get("ticket_id", str(result.inserted_id))
        
    except Exception as e:
        print(f"Error creating support ticket: {e}")
        raise e


# FIXED VERSION for database.py

def get_support_ticket(ticket_id: str) -> dict:
    """Get support ticket by ID (human-readable or ObjectId)"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        # Search by the correct 'ticketId' field first
        ticket = support_tickets.find_one({"ticketId": ticket_id})
        
        # If not found, try searching by the internal _id as a fallback
        if not ticket:
            try:
                ticket = support_tickets.find_one({"_id": ObjectId(ticket_id)})
            except:
                return None # Not a valid ObjectId, so return None

        if ticket:
            ticket['_id'] = str(ticket['_id'])
            
        return ticket
        
    except Exception as e:
        print(f"Error getting support ticket: {e}")
        raise e


def update_support_ticket(ticket_id: str, update_data: dict) -> bool:
    """Update support ticket"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        update_data["updated_at"] = datetime.utcnow()
        
        result = support_tickets.update_one(
            {"_id": ObjectId(ticket_id)},
            {"$set": update_data}
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating support ticket: {e}")
        raise e


def update_support_ticket_by_ticket_id(ticket_id: str, update_data: dict) -> bool:
    """Update support ticket by human-readable ticket ID"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        update_data["updated_at"] = datetime.utcnow()
        
        # Try to update by ticket_id first (snake_case as stored in database)
        result = support_tickets.update_one(
            {"ticket_id": ticket_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            # Try by MongoDB _id as fallback
            try:
                result = support_tickets.update_one(
                    {"_id": ObjectId(ticket_id)},
                    {"$set": update_data}
                )
            except:
                pass
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating support ticket by ticket ID: {e}")
        raise e


def add_support_message(ticket_id: str, message_data: dict) -> bool:
    """Add a message to support ticket"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        message = {
            **message_data,
            "timestamp": datetime.utcnow()
        }
        
        result = support_tickets.update_one(
            {"_id": ObjectId(ticket_id)},
            {
                "$push": {"messages": message},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error adding support message: {e}")
        raise e


def add_support_message_by_ticket_id(ticket_id: str, message_data: dict) -> bool:
    """Add a message to support ticket by human-readable ticket ID"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        message = {
            **message_data,
            "timestamp": datetime.utcnow()
        }
        
        # Try to update by ticket_id first (snake_case as stored in database)
        result = support_tickets.update_one(
            {"ticket_id": ticket_id},
            {
                "$push": {"messages": message},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        
        if result.matched_count == 0:
            # Try by MongoDB _id as fallback
            try:
                result = support_tickets.update_one(
                    {"_id": ObjectId(ticket_id)},
                    {
                        "$push": {"messages": message},
                        "$set": {"updated_at": datetime.utcnow()}
                    }
                )
            except:
                pass
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error adding support message by ticket ID: {e}")
        raise e


def get_support_tickets(category: str = None, status: str = None, 
                       limit: int = 50, skip: int = 0) -> list:
    """Get support tickets with optional filters"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        query = {}
        if category:
            query["category"] = category
        if status:
            query["status"] = status
        
        tickets = list(support_tickets.find(query)
                      .sort("created_at", -1)
                      .skip(skip)
                      .limit(limit))
        
        # Convert ObjectId to string
        for ticket in tickets:
            ticket['_id'] = str(ticket['_id'])
            
        return tickets
        
    except Exception as e:
        print(f"Error getting support tickets: {e}")
        raise e


# Enhanced Ticket Database Functions

def get_support_ticket_by_ticket_id(ticket_id: str) -> dict:
    """Get support ticket by human-readable ticket ID"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        # Use ticket_id (snake_case) as that's how it's stored in the database
        ticket = support_tickets.find_one({"ticket_id": ticket_id})
        
        if ticket:
            ticket['_id'] = str(ticket['_id'])
            
        return ticket
        
    except Exception as e:
        print(f"Error getting support ticket by ticket ID: {e}")
        raise e


def get_user_support_tickets(user_id: str, status: str = None, category: str = None, 
                           limit: int = 50, skip: int = 0) -> list:
    """Get support tickets for a specific user with filters"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        query = {"userId": user_id}
        if status:
            query["status"] = status
        if category:
            query["category"] = category
        
        tickets = list(support_tickets.find(query)
                      .sort("created_at", -1)
                      .skip(skip)
                      .limit(limit))
        
        # Convert ObjectId to string
        for ticket in tickets:
            ticket['_id'] = str(ticket['_id'])
            
        return tickets
        
    except Exception as e:
        print(f"Error getting user support tickets: {e}")
        raise e


def search_support_tickets(search_term: str, user_id: str = None, 
                         limit: int = 50, skip: int = 0) -> list:
    """Search support tickets by subject, description, or ticket ID"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        # Build search query
        search_conditions = [
            {"subject": {"$regex": search_term, "$options": "i"}},
            {"description": {"$regex": search_term, "$options": "i"}},
            {"ticketId": {"$regex": search_term, "$options": "i"}}
        ]
        
        query = {"$or": search_conditions}
        
        # Add user filter if specified
        if user_id:
            query["userId"] = user_id
        
        tickets = list(support_tickets.find(query)
                      .sort("created_at", -1)
                      .skip(skip)
                      .limit(limit))
        
        # Convert ObjectId to string
        for ticket in tickets:
            ticket['_id'] = str(ticket['_id'])
            
        return tickets
        
    except Exception as e:
        print(f"Error searching support tickets: {e}")
        raise e


def get_support_ticket_stats(user_id: str = None) -> dict:
    """Get statistics about support tickets"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        # Build base query
        base_query = {}
        if user_id:
            base_query["userId"] = user_id
        
        # Get total counts
        total_tickets = support_tickets.count_documents(base_query)
        
        # Get counts by status
        status_counts = {}
        for status in ["open", "in_progress", "resolved", "closed"]:
            query = {**base_query, "status": status}
            status_counts[f"{status}Tickets"] = support_tickets.count_documents(query)
        
        # Get counts by priority
        priority_counts = {}
        for priority in ["low", "medium", "high", "critical"]:
            query = {**base_query, "priority": priority}
            priority_counts[f"{priority}PriorityTickets"] = support_tickets.count_documents(query)
        
        # Get counts by category
        category_counts = {}
        for category in ["tournament", "payment", "technical", "account", "other"]:
            query = {**base_query, "category": category}
            category_counts[category] = support_tickets.count_documents(query)
        
        # Calculate average resolution time for resolved tickets
        pipeline = [
            {"$match": {**base_query, "status": "resolved", "resolvedAt": {"$exists": True}}},
            {"$project": {
                "resolutionTime": {
                    "$divide": [
                        {"$subtract": ["$resolvedAt", "$created_at"]},
                        3600000  # Convert to hours
                    ]
                }
            }},
            {"$group": {
                "_id": None,
                "avgResolutionTime": {"$avg": "$resolutionTime"}
            }}
        ]
        
        avg_resolution_result = list(support_tickets.aggregate(pipeline))
        avg_resolution_time = avg_resolution_result[0]["avgResolutionTime"] if avg_resolution_result else 0.0
        
        return {
            "totalTickets": total_tickets,
            **status_counts,
            **priority_counts,
            "averageResolutionTime": avg_resolution_time,
            "ticketsByCategory": category_counts,
            "ticketsByPriority": {
                "low": priority_counts.get("lowPriorityTickets", 0),
                "medium": priority_counts.get("mediumPriorityTickets", 0),
                "high": priority_counts.get("highPriorityTickets", 0),
                "critical": priority_counts.get("criticalPriorityTickets", 0)
            }
        }
        
    except Exception as e:
        print(f"Error getting support ticket stats: {e}")
        raise e


def update_support_ticket_status(ticket_id: str, status: str, assigned_to: str = None, 
                               resolution: str = None) -> bool:
    """Update support ticket status with optional assignment and resolution"""
    try:
        db = get_database()
        support_tickets = db.support_tickets
        
        update_data = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if assigned_to:
            update_data["assignedTo"] = assigned_to
        
        if resolution:
            update_data["resolution"] = resolution
        
        if status == "resolved":
            update_data["resolvedAt"] = datetime.utcnow()
        
        # Try to update by ticketId first, then by _id
        result = support_tickets.update_one(
            {"ticketId": ticket_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            # Try by MongoDB _id
            try:
                result = support_tickets.update_one(
                    {"_id": ObjectId(ticket_id)},
                    {"$set": update_data}
                )
            except:
                pass
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating support ticket status: {e}")
        raise e


def process_automated_refund(tournament_id: str, refund_reason: str, admin_id: str = None, 
                           partial_refund: bool = False, refund_percentage: float = 100.0) -> dict:
    """
    Process automated refund for tournament cancellations or disputes
    
    Args:
        tournament_id: ID of the tournament
        refund_reason: Reason for refund (e.g., "Tournament cancelled by admin")
        admin_id: ID of admin initiating refund
        partial_refund: If True, only refund a percentage of payments
        refund_percentage: Percentage to refund (0-100), default 100%
    
    Returns:
        dict: Refund processing results including total amount and affected users
    """
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        payments_collection = db.payments
        
        # Validate refund percentage
        if refund_percentage < 0 or refund_percentage > 100:
            raise ValueError("Refund percentage must be between 0 and 100")
        
        # Get tournament details
        tournament = tournaments_collection.find_one({"_id": ObjectId(tournament_id)})
        if not tournament:
            raise ValueError(f"Tournament not found: {tournament_id}")
        
        tournament_slug = tournament.get("slug", "")
        tournament_title = tournament.get("title", "Unknown Tournament")
        
        print(f"Processing refund for tournament: {tournament_title} ({tournament_slug})")
        
        # Get all successful payments for this tournament
        tournament_payments = list(payments_collection.find({
            "tournamentSlug": tournament_slug,
            "status": "success"
        }))
        
        if not tournament_payments:
            return {
                "success": True,
                "message": "No payments found to refund",
                "total_refund_amount": 0,
                "refunded_payments": [],
                "refund_count": 0
            }
        
        total_refund_amount = 0
        refunded_payments = []
        failed_refunds = []
        
        # Process refunds for each payment
        for payment in tournament_payments:
            try:
                original_amount = payment.get("amount", 0)
                refund_amount = original_amount * (refund_percentage / 100)
                
                # Update payment status to refunded
                update_result = payments_collection.update_one(
                    {"_id": payment["_id"]},
                    {
                        "$set": {
                            "status": "refunded" if refund_percentage == 100 else "partially_refunded",
                            "refund_amount": refund_amount,
                            "original_amount": original_amount,
                            "refund_percentage": refund_percentage,
                            "refund_reason": refund_reason,
                            "refunded_at": datetime.utcnow().isoformat(),
                            "refunded_by": admin_id,
                            "refund_type": "full" if refund_percentage == 100 else "partial"
                        }
                    }
                )
                
                if update_result.modified_count > 0:
                    total_refund_amount += refund_amount
                    refunded_payments.append({
                        "payment_id": str(payment["_id"]),
                        "transaction_id": payment.get("transactionId", "N/A"),
                        "user_email": payment.get("userEmail", "N/A"),
                        "team_name": payment.get("teamName", "N/A"),
                        "original_amount": original_amount,
                        "refund_amount": refund_amount,
                        "refund_percentage": refund_percentage
                    })
                    print(f"✅ Refunded ₹{refund_amount:.2f} to {payment.get('userEmail')}")
                else:
                    failed_refunds.append({
                        "payment_id": str(payment["_id"]),
                        "user_email": payment.get("userEmail", "N/A"),
                        "error": "Failed to update payment record"
                    })
                    print(f"❌ Failed to refund payment: {payment.get('_id')}")
                    
            except Exception as payment_error:
                failed_refunds.append({
                    "payment_id": str(payment.get("_id", "unknown")),
                    "user_email": payment.get("userEmail", "N/A"),
                    "error": str(payment_error)
                })
                print(f"❌ Error processing refund for payment {payment.get('_id')}: {payment_error}")
        
        # Update tournament status with refund information
        tournament_update = {
            "refund_processed": True,
            "refund_initiated_at": datetime.utcnow().isoformat(),
            "refund_reason": refund_reason,
            "total_refund_amount": total_refund_amount,
            "refund_count": len(refunded_payments),
            "refund_percentage": refund_percentage,
            "updatedAt": datetime.utcnow().isoformat()
        }
        
        if refund_percentage == 100:
            tournament_update["status"] = "cancelled"
            tournament_update["cancelled_at"] = datetime.utcnow().isoformat()
            tournament_update["cancellation_reason"] = refund_reason
        
        if admin_id:
            tournament_update["refunded_by"] = admin_id
        
        tournaments_collection.update_one(
            {"_id": ObjectId(tournament_id)},
            {"$set": tournament_update}
        )
        
        # Log activity
        try:
            from database import create_activity
            create_activity({
                "type": "tournament_refund_processed",
                "title": f"Refunds Processed: {tournament_title}",
                "description": f"{refund_percentage}% refund processed for {len(refunded_payments)} payments. Total: ₹{total_refund_amount:,.2f}",
                "tournamentId": tournament_id,
                "tournamentTitle": tournament_title,
                "tournamentSlug": tournament_slug,
                "priority": "high",
                "metadata": {
                    "action": "refund_processed",
                    "refund_reason": refund_reason,
                    "refund_count": len(refunded_payments),
                    "total_amount": total_refund_amount,
                    "refund_percentage": refund_percentage,
                    "admin_id": admin_id
                }
            })
        except Exception as activity_error:
            print(f"Warning: Failed to log refund activity: {activity_error}")
        
        result = {
            "success": True,
            "message": f"Processed {len(refunded_payments)} refunds successfully",
            "tournament_id": tournament_id,
            "tournament_title": tournament_title,
            "total_refund_amount": total_refund_amount,
            "refunded_payments": refunded_payments,
            "refund_count": len(refunded_payments),
            "failed_refunds": failed_refunds,
            "refund_percentage": refund_percentage,
            "refund_type": "full" if refund_percentage == 100 else "partial"
        }
        
        print(f"✅ Refund processing complete: {len(refunded_payments)} successful, {len(failed_refunds)} failed")
        return result
        
    except Exception as e:
        print(f"❌ Error processing automated refund: {e}")
        return {
            "success": False,
            "error": str(e),
            "total_refund_amount": 0,
            "refunded_payments": [],
            "refund_count": 0
        }

        
# Privacy and Compliance Database Functions

def store_audit_log(audit_entry: dict) -> str:
    """Store audit log entry in database"""
    try:
        db = get_database()
        audit_logs_collection = db.audit_logs
        
        audit_entry['created_at'] = datetime.utcnow()
        
        result = audit_logs_collection.insert_one(audit_entry)
        print(f"✅ Audit log stored: {audit_entry.get('event_type', 'unknown')}")
        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error storing audit log: {e}")
        raise e


def get_audit_logs(user_id: str = None, event_type: str = None, limit: int = 100, skip: int = 0) -> list:
    """Get audit logs with optional filtering"""
    try:
        db = get_database()
        audit_logs_collection = db.audit_logs
        
        query = {}
        if user_id:
            query["user_id"] = user_id
        if event_type:
            query["event_type"] = event_type
        
        logs = list(audit_logs_collection.find(query)
                   .sort("created_at", -1)
                   .skip(skip)
                   .limit(limit))
        
        # Convert ObjectId to string
        for log in logs:
            log['_id'] = str(log['_id'])
            if 'created_at' in log:
                log['created_at'] = log['created_at'].isoformat() if hasattr(log['created_at'], 'isoformat') else str(log['created_at'])
        
        return logs
        
    except Exception as e:
        print(f"Error fetching audit logs: {e}")
        raise e


def store_user_consent(user_id: str, consent_data: dict) -> str:
    """Store user consent record"""
    try:
        db = get_database()
        user_consents_collection = db.user_consents
        
        consent_record = {
            "user_id": user_id,
            **consent_data,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        # Remove existing consent of same type
        user_consents_collection.delete_many({
            "user_id": user_id,
            "consent_type": consent_data.get("consent_type")
        })
        
        result = user_consents_collection.insert_one(consent_record)
        print(f"✅ User consent stored: {user_id} - {consent_data.get('consent_type')}")
        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error storing user consent: {e}")
        raise e


def get_user_consents(user_id: str) -> list:
    """Get all consent records for a user"""
    try:
        db = get_database()
        user_consents_collection = db.user_consents
        
        consents = list(user_consents_collection.find({"user_id": user_id})
                       .sort("created_at", -1))
        
        # Convert ObjectId to string and format dates
        for consent in consents:
            consent['_id'] = str(consent['_id'])
            if 'created_at' in consent:
                consent['created_at'] = consent['created_at'].isoformat() if hasattr(consent['created_at'], 'isoformat') else str(consent['created_at'])
            if 'updated_at' in consent:
                consent['updated_at'] = consent['updated_at'].isoformat() if hasattr(consent['updated_at'], 'isoformat') else str(consent['updated_at'])
        
        return consents
        
    except Exception as e:
        print(f"Error fetching user consents: {e}")
        raise e


def store_data_export_request(export_request: dict) -> str:
    """Store data export request"""
    try:
        db = get_database()
        data_export_requests_collection = db.data_export_requests
        
        export_request['created_at'] = datetime.utcnow()
        export_request['updated_at'] = datetime.utcnow()
        
        result = data_export_requests_collection.insert_one(export_request)
        print(f"✅ Data export request stored: {export_request.get('request_id')}")
        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error storing data export request: {e}")
        raise e


def get_data_export_request(request_id: str) -> dict:
    """Get data export request by ID"""
    try:
        db = get_database()
        data_export_requests_collection = db.data_export_requests
        
        request = data_export_requests_collection.find_one({"request_id": request_id})
        if request:
            request['_id'] = str(request['_id'])
            # Format datetime fields
            for field in ['created_at', 'updated_at', 'completed_at', 'expires_at']:
                if field in request and request[field]:
                    request[field] = request[field].isoformat() if hasattr(request[field], 'isoformat') else str(request[field])
        
        return request
        
    except Exception as e:
        print(f"Error fetching data export request: {e}")
        raise e


def update_data_export_request(request_id: str, update_data: dict) -> bool:
    """Update data export request"""
    try:
        db = get_database()
        data_export_requests_collection = db.data_export_requests
        
        update_data['updated_at'] = datetime.utcnow()
        
        result = data_export_requests_collection.update_one(
            {"request_id": request_id},
            {"$set": update_data}
        )
        
        print(f"✅ Data export request updated: {request_id}")
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating data export request: {e}")
        raise e


def store_data_deletion_request(deletion_request: dict) -> str:
    """Store data deletion request"""
    try:
        db = get_database()
        data_deletion_requests_collection = db.data_deletion_requests
        
        deletion_request['created_at'] = datetime.utcnow()
        deletion_request['updated_at'] = datetime.utcnow()
        
        result = data_deletion_requests_collection.insert_one(deletion_request)
        print(f"✅ Data deletion request stored: {deletion_request.get('request_id')}")
        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error storing data deletion request: {e}")
        raise e


def get_data_deletion_request(request_id: str) -> dict:
    """Get data deletion request by ID"""
    try:
        db = get_database()
        data_deletion_requests_collection = db.data_deletion_requests
        
        request = data_deletion_requests_collection.find_one({"request_id": request_id})
        if request:
            request['_id'] = str(request['_id'])
            # Format datetime fields
            for field in ['created_at', 'updated_at', 'completed_at']:
                if field in request and request[field]:
                    request[field] = request[field].isoformat() if hasattr(request[field], 'isoformat') else str(request[field])
        
        return request
        
    except Exception as e:
        print(f"Error fetching data deletion request: {e}")
        raise e


def update_data_deletion_request(request_id: str, update_data: dict) -> bool:
    """Update data deletion request"""
    try:
        db = get_database()
        data_deletion_requests_collection = db.data_deletion_requests
        
        update_data['updated_at'] = datetime.utcnow()
        
        result = data_deletion_requests_collection.update_one(
            {"request_id": request_id},
            {"$set": update_data}
        )
        
        print(f"✅ Data deletion request updated: {request_id}")
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating data deletion request: {e}")
        raise e


def anonymize_user_data(user_id: str) -> bool:
    """Anonymize user data across all collections"""
    try:
        db = get_database()
        
        # Generate anonymous identifier
        import hashlib
        anonymous_id = hashlib.sha256(f"{user_id}_{datetime.utcnow()}".encode()).hexdigest()[:16]
        anonymous_email = f"anonymous_{anonymous_id}@deleted.local"
        anonymous_username = f"anonymous_{anonymous_id}"
        
        # Anonymize user profile
        users_collection = db.users
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "email": anonymous_email,
                "username": anonymous_username,
                "anonymized": True,
                "anonymized_at": datetime.utcnow()
            }}
        ) 
        
        # Anonymize activity logs
        activities_collection = db.activities
        activities_collection.update_many(
            {"userId": user_id},
            {"$set": {
                "username": anonymous_username,
                "anonymized": True
            }}
        )
        
        print(f"✅ User data anonymized: {user_id} -> {anonymous_id}")
        return True
        
    except Exception as e:
        print(f"Error anonymizing user data: {e}")
        raise e


def delete_user_data_by_category(user_id: str, category: str, retention_cutoff: datetime = None) -> bool:
    """Delete user data by category with retention policy"""
    try:
        db = get_database()
        
        if category == "profile":
            # Delete user profile (except anonymized records)
            users_collection = db.users
            result = users_collection.delete_one({
                "_id": ObjectId(user_id),
                "anonymized": {"$ne": True}
            })
            print(f"✅ Profile data deleted for user: {user_id}")
            
        elif category == "tournaments":
            # No user tournament data to delete - user hosting removed
            print(f"✅ No tournament data to delete for user: {user_id} (user hosting disabled)")
            
        elif category == "activities":
            # Delete activity logs older than retention period
            activities_collection = db.activities
            query = {"userId": user_id}
            if retention_cutoff:
                query["timestamp"] = {"$lt": retention_cutoff.isoformat()}
            
            result = activities_collection.delete_many(query)
            print(f"✅ Activity data deleted for user: {user_id}, count: {result.deleted_count}")
            
        elif category == "communications":
            # Delete communication logs
            # This would include notification logs, messages, etc.
            print(f"✅ Communication data deletion requested for user: {user_id}")
            
        elif category == "analytics":
            # Delete analytics data older than retention period
            tournament_analytics_collection = db.tournament_analytics
            query = {"organizerId": user_id}
            if retention_cutoff:
                query["lastUpdated"] = {"$lt": retention_cutoff.isoformat()}
            
            result = tournament_analytics_collection.delete_many(query)
            print(f"✅ Analytics data deleted for user: {user_id}, count: {result.deleted_count}")
        
        return True
        
    except Exception as e:
        print(f"Error deleting user data by category: {e}")
        raise e


def get_user_data_summary(user_id: str) -> dict:
    """Get summary of user's data across all categories"""
    try:
        db = get_database()
        
        summary = {
            "user_id": user_id,
            "profile": {"record_count": 0, "last_updated": None},
            "activities": {"record_count": 0, "last_updated": None},
            "communications": {"record_count": 0, "last_updated": None},
        }
        
        # Profile data
        users_collection = db.users
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            summary["profile"]["record_count"] = 1
            summary["profile"]["last_updated"] = user.get("updated_at", user.get("created_at"))
        
        
        # Activity data
        activities_collection = db.activities
        activity_count = activities_collection.count_documents({"userId": user_id})
        summary["activities"]["record_count"] = activity_count
        
        latest_activity = activities_collection.find_one(
            {"userId": user_id},
            sort=[("timestamp", -1)]
        )
        if latest_activity:
            summary["activities"]["last_updated"] = latest_activity.get("timestamp")
        
        return summary
        
    except Exception as e:
        print(f"Error getting user data summary: {e}")
        raise e


def create_database_indexes():
    """Create database indexes for privacy and compliance collections"""
    try:
        db = get_database()
        
        # Audit logs indexes
        audit_logs_collection = db.audit_logs
        audit_logs_collection.create_index("user_id")
        audit_logs_collection.create_index("event_type")
        audit_logs_collection.create_index("created_at")
        audit_logs_collection.create_index([("user_id", 1), ("event_type", 1)])
        
        # User consents indexes
        user_consents_collection = db.user_consents
        user_consents_collection.create_index("user_id")
        user_consents_collection.create_index("consent_type")
        user_consents_collection.create_index([("user_id", 1), ("consent_type", 1)])
        
        # Data export requests indexes
        data_export_requests_collection = db.data_export_requests
        data_export_requests_collection.create_index("request_id", unique=True)
        data_export_requests_collection.create_index("user_id")
        data_export_requests_collection.create_index("created_at")
        
        # Data deletion requests indexes
        data_deletion_requests_collection = db.data_deletion_requests
        data_deletion_requests_collection.create_index("request_id", unique=True)
        data_deletion_requests_collection.create_index("user_id")
        data_deletion_requests_collection.create_index("created_at")
        
        print("✅ Privacy and compliance database indexes created")
        
    except Exception as e:
        print(f"Error creating database indexes: {e}")
        raise e


def get_user_by_id(user_id: str) -> dict:
    """Get user by ID"""
    try:
        db = get_database()
        users_collection = db.users
        
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            user['_id'] = str(user['_id'])
        
        return user
        
    except Exception as e:
        print(f"Error fetching user by ID: {e}")
        return None


# Content Moderation Functions

def create_moderation_review(review_data: dict) -> str:
    """Create moderation review"""
    try:
        db = get_database()
        moderation_reviews = db.moderation_reviews
        
        review_data["createdAt"] = datetime.utcnow().isoformat()
        review_data["updatedAt"] = datetime.utcnow().isoformat()
        
        result = moderation_reviews.insert_one(review_data)
        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error creating moderation review: {e}")
        raise e


def get_moderation_queue(status: str = "pending", limit: int = 50, skip: int = 0) -> list:
    """Get moderation queue items"""
    try:
        db = get_database()
        moderation_reviews = db.moderation_reviews
        
        query = {}
        if status:
            query["status"] = status
            
        reviews = list(moderation_reviews.find(query)
                      .sort("createdAt", -1)
                      .skip(skip)
                      .limit(limit))
        
        # Convert ObjectId to string
        for review in reviews:
            review["_id"] = str(review["_id"])
            
        return reviews
        
    except Exception as e:
        print(f"Error getting moderation queue: {e}")
        return []


def update_tournament_moderation_status(tournament_id: str, status: str, reviewer_id: str, notes: str = "") -> bool:
    """Update tournament moderation status (admin tournaments only)"""
    try:
        db = get_database()
        tournaments = db.tournaments
        
        result = tournaments.update_one(
            {"_id": ObjectId(tournament_id)},
            {
                "$set": {
                    "moderationStatus": status,
                    "moderationReviewedAt": datetime.utcnow().isoformat(),
                    "moderationReviewedBy": reviewer_id,
                    "moderationNotes": notes,
                    "updatedAt": datetime.utcnow().isoformat()
                }
            }
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error updating tournament moderation status: {e}")
        return False


def get_moderation_stats() -> dict:
    """Get moderation statistics"""
    try:
        db = get_database()
        moderation_reviews = db.moderation_reviews
        
        total_reviews = moderation_reviews.count_documents({})
        pending_reviews = moderation_reviews.count_documents({"status": "pending"})
        approved_today = moderation_reviews.count_documents({
            "status": "approved",
            "reviewedAt": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()}
        })
        rejected_today = moderation_reviews.count_documents({
            "status": "rejected",
            "reviewedAt": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()}
        })
        
        return {
            "totalReviews": total_reviews,
            "pendingReviews": pending_reviews,
            "approvedToday": approved_today,
            "rejectedToday": rejected_today,
            "averageReviewTime": 0.0,  # TODO: Calculate actual average
            "topReviewers": []  # TODO: Get top reviewers
        }
        
    except Exception as e:
        print(f"Error getting moderation stats: {e}")
        return {
            "totalReviews": 0,
            "pendingReviews": 0,
            "approvedToday": 0,
            "rejectedToday": 0,
            "averageReviewTime": 0.0,
            "topReviewers": []
        }
    
# In database.py

from datetime import datetime
import uuid # Make sure uuid is imported at the top of the file

def credit_host_for_payment(payment_record: dict):
    """
    Calculates host earnings for a single successful payment and credits their wallet.
    """
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        wallets_collection = db.wallets
        transactions_collection = db.transactions

        # 1. Get payment details
        payment_amount = payment_record.get("amount", 0)
        tournament_slug = payment_record.get("tournamentSlug")
        
        if not tournament_slug or payment_amount <= 0:
            print(f"Payout Info: Skipping host credit for payment {payment_record.get('transactionId')} due to missing slug or zero amount.")
            return

        # 2. Find the tournament to get hostId and commission
        tournament = tournaments_collection.find_one({"slug": tournament_slug})
        if not tournament:
            print(f"Payout Error: Tournament {tournament_slug} not found for payment.")
            return

        host_id = tournament.get("hostId")
        # Defaulting to 10% commission (0.10) if not set on tournament
        host_commission_percentage = tournament.get("hostCommission", 0.10) 
        
        if not host_id:
            print(f"Payout Info: No host found for tournament '{tournament.get('title')}'. No commission paid.")
            return

        # 3. Calculate earnings for this single payment
        # The host gets their commission percentage of the fee.
        # So if commission is 10% (0.10), the host earns 90%.
        host_earning = payment_amount * (1 - host_commission_percentage)
        company_earning = payment_amount * host_commission_percentage

        # 4. Update the host's wallet immediately
        wallets_collection.update_one(
            {"userId": host_id},
            {
                "$inc": {
                    "availableBalance": host_earning,
                    "totalEarnings": host_earning,
                },
                "$set": {"lastUpdated": datetime.utcnow().isoformat()},
                "$setOnInsert": { # Creates the wallet if it doesn't exist
                    "userId": host_id,
                    "pendingBalance": 0.0,
                    "totalWithdrawals": 0.0,
                    "currency": "INR",
                    "createdAt": datetime.utcnow().isoformat()
                }
            },
            upsert=True # This is crucial to create a wallet for the host on their first earning
        )

        # 5. Create a transaction record for the host's history
        earning_transaction = {
            "userId": host_id,
            "type": "earning",
            "status": "completed",
            "amount": host_earning,
            "description": f"Earning from team '{payment_record.get('teamData', {}).get('teamName', 'N/A')}' for tournament: {tournament.get('title')}",
            "relatedTournamentId": str(tournament.get("_id")),
            "relatedPaymentId": payment_record.get("transactionId"),
            "createdAt": datetime.utcnow().isoformat()
        }
        transactions_collection.insert_one(earning_transaction)
        
        print(f"✅ Host Credit Success: Credited ₹{host_earning:.2f} to host {host_id} for payment {payment_record.get('transactionId')}.")
        return True

    except Exception as e:
        print(f"❌ CRITICAL HOST CREDIT ERROR for payment {payment_record.get('transactionId')}: {e}")
        return False
    
# In database.py

def get_tournament_by_id(tournament_id: str):
    """Get a single tournament by its MongoDB _id."""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        # Ensure the ID is a valid ObjectId before querying
        if not ObjectId.is_valid(tournament_id):
            print(f"Warning: Invalid ObjectId format for tournament_id: {tournament_id}")
            return None
            
        tournament = tournaments_collection.find_one({"_id": ObjectId(tournament_id)})
        
        if tournament:
            tournament['_id'] = str(tournament['_id'])
            
        return tournament
    except Exception as e:
        print(f"Error fetching tournament by id {tournament_id}: {e}")
        return None
    
# In database.py

def get_host_dashboard_metrics(host_id: str):
    """Calculate dashboard metrics for a specific host."""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        wallets_collection = db.wallets

        # Base query for all tournaments by this host
        query = {"hostId": host_id}

        # --- Calculate Tournament Metrics ---
        total_tournaments = tournaments_collection.count_documents(query)
        active_tournaments = tournaments_collection.count_documents({**query, "status": {"$in": ["registration_open", "ongoing"]}})
        completed_tournaments = tournaments_collection.count_documents({**query, "status": "ended"}) # Assuming 'ended' is the final status
        upcoming_tournaments = tournaments_collection.count_documents({**query, "status": "upcoming"})

        # --- Calculate Participant Metrics ---
        total_participants = 0
        host_tournaments = list(tournaments_collection.find(query, {"participants": 1}))
        for tournament in host_tournaments:
            total_participants += len(tournament.get("participants", []))

        # --- Get Financial Metrics from the Wallet ---
        wallet = wallets_collection.find_one({"userId": host_id})
        total_earnings = 0.0
        pending_withdrawals = 0.0
        if wallet:
            total_earnings = wallet.get("totalEarnings", 0.0)
            pending_withdrawals = wallet.get("pendingBalance", 0.0)

        return {
            "totalTournaments": total_tournaments,
            "activeTournaments": active_tournaments,
            "completedTournaments": completed_tournaments,
            "upcomingTournaments": upcoming_tournaments,
            "totalParticipants": total_participants,
            "totalEarnings": total_earnings,
            "pendingWithdrawals": pending_withdrawals
        }

    except Exception as e:
        print(f"Error calculating dashboard metrics for host {host_id}: {e}")
        # Return zeroed-out metrics on error
        return {
            "totalTournaments": 0, "activeTournaments": 0, "completedTournaments": 0,
            "upcomingTournaments": 0, "totalParticipants": 0, "totalEarnings": 0.0,
            "pendingWithdrawals": 0.0
        }
    
# In database.py

def get_participants_for_host_tournament(host_id: str, tournament_id: str):
    """Get all participants for a specific tournament owned by a host."""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        # Find the tournament and ensure it belongs to the host
        tournament = tournaments_collection.find_one(
            {"_id": ObjectId(tournament_id), "hostId": host_id},
            {"participants": 1} # Only fetch the participants field
        )
        
        if not tournament:
            return None # Return None if tournament not found or not owned by host

        participants = tournament.get("participants", [])
        
        # Convert all ObjectIds to strings for JSON serialization
        for p in participants:
            if '_id' in p:
                p['_id'] = str(p['_id'])
        
        return participants
    except Exception as e:
        print(f"Error fetching participants for tournament {tournament_id}: {e}")
        raise e

def update_participant_status_for_host(host_id: str, tournament_id: str, participant_id: str, new_status: str):
    """Update the status of a participant in a tournament owned by a host."""
    try:
        db = get_database()
        tournaments_collection = db.tournaments
        
        # Use a positional operator '$' to update the specific participant in the array
        result = tournaments_collection.update_one(
            {
                "_id": ObjectId(tournament_id), 
                "hostId": host_id, 
                "participants._id": ObjectId(participant_id)
            },
            {
                "$set": { "participants.$.status": new_status }
            }
        )
        
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating participant status for {participant_id}: {e}")
        raise e
    
# In database.py

def get_tournament_for_host(host_id: str, tournament_id: str):
    """Get a single tournament owned by a specific host."""
    try:
        db = get_database()
        tournaments_collection = db.tournaments

        # Find the tournament and ensure it belongs to the host
        tournament = tournaments_collection.find_one(
            {"_id": ObjectId(tournament_id), "hostId": host_id}
        )

        if not tournament:
            return None # Return None if tournament not found or not owned by host

        # Convert all ObjectIds to strings for JSON serialization
        tournament['_id'] = str(tournament['_id'])
        participants = tournament.get("participants", [])
        for p in participants:
            if '_id' in p:
                p['_id'] = str(p['_id'])

        return tournament
    except Exception as e:
        print(f"Error fetching tournament for host {host_id}: {e}")
        raise e

# In database.py

def get_host_revenue_over_time(host_id: str, days: int = 90):
    """
    Aggregates host's earnings by day for the last X days.
    """
    try:
        db = get_database()
        transactions_collection = db.transactions
        
        # Calculate the start date for the query
        start_date = datetime.utcnow() - timedelta(days=days)
        
        pipeline = [
            # 1. Match relevant transactions for the host within the date range
            {
                "$match": {
                    "userId": host_id,
                    "type": "earning",
                    "status": "completed",
                    "createdAt": {"$gte": start_date.isoformat()}
                }
            },
            # 2. Group by date and sum the earnings
            {
                "$group": {
                    "_id": {
                        "$dateToString": { "format": "%Y-%m-%d", "date": {"$dateFromString": {"dateString": "$createdAt"}} }
                    },
                    "totalRevenue": { "$sum": "$amount" }
                }
            },
            # 3. Format the output fields
            {
                "$project": {
                    "_id": 0,
                    "date": "$_id",
                    "revenue": "$totalRevenue"
                }
            },
            # 4. Sort by date ascending
            {
                "$sort": { "date": 1 }
            }
        ]
        
        revenue_data = list(transactions_collection.aggregate(pipeline))
        return revenue_data

    except Exception as e:
        print(f"Error getting host revenue over time for host {host_id}: {e}")
        raise e


def get_host_participant_growth(host_id: str, days: int = 90):
    """
    Aggregates new participant registrations by day for the host's tournaments over the last X days.
    """
    try:
        db = get_database()
        tournaments_collection = db.tournaments

        start_date = datetime.utcnow() - timedelta(days=days)

        pipeline = [
            # 1. Match tournaments owned by the host
            {
                "$match": { "hostId": host_id }
            },
            # 2. Deconstruct the participants array
            {
                "$unwind": "$participants"
            },
            # 3. Match participants who registered within the date range
            {
                "$match": {
                    "participants.registrationDate": {"$gte": start_date.isoformat()}
                }
            },
            # 4. Group by registration date and count participants
            {
                "$group": {
                    "_id": {
                        "$dateToString": { "format": "%Y-%m-%d", "date": {"$dateFromString": {"dateString": "$participants.registrationDate"}} }
                    },
                    "newParticipants": { "$sum": 1 }
                }
            },
            # 5. Format the output fields
            {
                "$project": {
                    "_id": 0,
                    "date": "$_id",
                    "participants": "$newParticipants"
                }
            },
            # 6. Sort by date ascending
            {
                "$sort": { "date": 1 }
            }
        ]
        
        growth_data = list(tournaments_collection.aggregate(pipeline))
        return growth_data

    except Exception as e:
        print(f"Error getting host participant growth for host {host_id}: {e}")
        raise e
    
# In database.py, add the following functions:

def get_admin_withdrawal_requests(status: str = None, limit: int = 50, skip: int = 0) -> list:
    """Get all withdrawal requests for admin review with pagination and filtering."""
    try:
        db = get_database()
        withdrawals_collection = db.withdrawals

        query = {}
        if status:
            query["status"] = status
        
        requests = list(
            withdrawals_collection.find(query)
            .sort("requestedAt", -1)
            .skip(skip)
            .limit(limit)
        )

        # Convert ObjectId to string
        for request in requests:
            request["_id"] = str(request["_id"])
            
        return requests
    except Exception as e:
        print(f"Error fetching admin withdrawal requests: {e}")
        raise e

def finalize_withdrawal_status(withdrawal_id: str, new_status: str, admin_id: str, notes: str = None) -> bool:
    """
    Update withdrawal and transaction status, and reconcile host wallet balance.
    New status must be 'completed' or 'failed'.
    """
    try:
        db = get_database()
        withdrawals_collection = db.withdrawals
        wallets_collection = db.wallets
        transactions_collection = db.transactions

        # 1. Get the original withdrawal request
        withdrawal_request = withdrawals_collection.find_one({"withdrawalId": withdrawal_id})
        if not withdrawal_request:
            raise ValueError(f"Withdrawal request {withdrawal_id} not found.")

        host_id = withdrawal_request["userId"]
        amount = withdrawal_request["amount"]

        # 2. Update the withdrawal request record
        update_data = {
            "status": new_status,
            "processedAt": datetime.utcnow().isoformat(),
            "processedBy": admin_id,
            "adminNotes": notes
        }

        result = withdrawals_collection.update_one(
            {"withdrawalId": withdrawal_id},
            {"$set": update_data}
        )

        if result.modified_count == 0:
            print(f"Warning: Finalize withdrawal status failed to update request {withdrawal_id}.")
            return False

        # 3. Update the corresponding transaction record
        transactions_collection.update_one(
            {"metadata.withdrawalId": withdrawal_id, "type": "withdrawal"},
            {"$set": {"status": new_status, "updatedAt": datetime.utcnow().isoformat()}}
        )

        # 4. Reconcile the Host Wallet
        if new_status == "completed":
            # Success: Move funds from pending to total withdrawals
            wallets_collection.update_one(
                {"userId": host_id},
                {
                    "$inc": {
                        "pendingBalance": -amount,  # Deduct from pending
                        "totalWithdrawals": amount # Add to total withdrawn
                    },
                    "$set": {"lastUpdated": datetime.utcnow().isoformat()}
                }
            )
            print(f"✅ Withdrawal {withdrawal_id} completed. Wallet reconciled.")
        
        elif new_status == "failed":
            # Failure: Move funds back from pending to available
            wallets_collection.update_one(
                {"userId": host_id},
                {
                    "$inc": {
                        "availableBalance": amount, # Return to available
                        "pendingBalance": -amount  # Deduct from pending
                    },
                    "$set": {"lastUpdated": datetime.utcnow().isoformat()}
                }
            )
            print(f"❌ Withdrawal {withdrawal_id} failed. Funds returned to available balance.")
        
        return True

    except Exception as e:
        print(f"CRITICAL ERROR finalizing withdrawal {withdrawal_id}: {e}")
        raise e