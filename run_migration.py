#!/usr/bin/env python3
"""
Script to run historical data migration for tournament registration tracking
"""
import requests
import json
import sys
import os

# Configuration
API_BASE_URL = "https://gamingnexus.onrender.com"  # Update with your actual API URL
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")  # Set this environment variable with admin JWT token

def run_migration():
    """Run the historical data migration"""
    if not ADMIN_TOKEN:
        print("❌ Error: ADMIN_TOKEN environment variable not set")
        print("Please set your admin JWT token: export ADMIN_TOKEN='your_admin_jwt_token'")
        return False
    
    headers = {
        "Authorization": f"Bearer {ADMIN_TOKEN}",
        "Content-Type": "application/json"
    }
    
    print("🚀 Starting historical data migration...")
    
    # Step 1: Get migration status before enhancement
    print("\n📊 Checking current migration status...")
    try:
        response = requests.get(f"{API_BASE_URL}/api/admin/migration-status", headers=headers)
        if response.status_code == 200:
            status_data = response.json()["data"]
            print(f"   Current progress: {status_data['migration_progress']:.1f}%")
            print(f"   Total tournaments: {status_data['total_tournaments']}")
            print(f"   Total participants: {status_data['total_participants']}")
        else:
            print(f"   ⚠️ Could not get status: {response.status_code}")
    except Exception as e:
        print(f"   ⚠️ Error getting status: {e}")
    
    # Step 2: Validate current data
    print("\n🔍 Validating current registration data...")
    try:
        response = requests.get(f"{API_BASE_URL}/api/admin/validate-registration-data", headers=headers)
        if response.status_code == 200:
            validation_data = response.json()["data"]
            print(f"   Issues found: {validation_data['issues_found']}")
            if validation_data['issues_found'] > 0:
                print("   Sample issues:")
                for issue in validation_data['issues'][:3]:  # Show first 3 issues
                    print(f"     - {issue['tournament']}: {', '.join(issue['issues'])}")
        else:
            print(f"   ⚠️ Could not validate data: {response.status_code}")
    except Exception as e:
        print(f"   ⚠️ Error validating data: {e}")
    
    # Step 3: Run enhancement in batches
    print("\n🔧 Running historical data enhancement...")
    batch_size = 50
    total_processed = 0
    total_enhanced = 0
    
    while True:
        try:
            response = requests.post(
                f"{API_BASE_URL}/api/admin/enhance-historical-registrations?limit={batch_size}",
                headers=headers
            )
            
            if response.status_code == 200:
                batch_data = response.json()["data"]
                batch_processed = batch_data["processed"]
                batch_enhanced = batch_data["enhanced"]
                
                total_processed += batch_processed
                total_enhanced += batch_enhanced
                
                print(f"   Batch: processed {batch_processed}, enhanced {batch_enhanced}")
                
                # If we processed fewer than the batch size, we're done
                if batch_processed < batch_size:
                    break
            else:
                print(f"   ❌ Enhancement failed: {response.status_code}")
                print(f"   Response: {response.text}")
                break
                
        except Exception as e:
            print(f"   ❌ Error during enhancement: {e}")
            break
    
    print(f"\n✅ Enhancement complete: processed {total_processed}, enhanced {total_enhanced}")
    
    # Step 4: Clean up inconsistencies
    print("\n🧹 Cleaning up data inconsistencies...")
    try:
        response = requests.post(f"{API_BASE_URL}/api/admin/cleanup-duplicate-user-ids", headers=headers)
        if response.status_code == 200:
            cleanup_data = response.json()["data"]
            print(f"   Fixed {cleanup_data['participants_fixed']} participants")
            print(f"   Fixed {cleanup_data['players_fixed']} players")
            print(f"   Errors: {cleanup_data['errors']}")
        else:
            print(f"   ⚠️ Cleanup failed: {response.status_code}")
    except Exception as e:
        print(f"   ⚠️ Error during cleanup: {e}")
    
    # Step 5: Get final migration status
    print("\n📊 Final migration status...")
    try:
        response = requests.get(f"{API_BASE_URL}/api/admin/migration-status", headers=headers)
        if response.status_code == 200:
            status_data = response.json()["data"]
            print(f"   Final progress: {status_data['migration_progress']:.1f}%")
            print(f"   Captain user IDs: {status_data['enhancement_coverage']['captain_user_ids']}")
            print(f"   Player user IDs: {status_data['enhancement_coverage']['player_user_ids']}")
            print(f"   Registered by fields: {status_data['enhancement_coverage']['registered_by_fields']}")
            
            if status_data.get('recommendations'):
                print("   Recommendations:")
                for rec in status_data['recommendations']:
                    print(f"     - {rec}")
        else:
            print(f"   ⚠️ Could not get final status: {response.status_code}")
    except Exception as e:
        print(f"   ⚠️ Error getting final status: {e}")
    
    print("\n🎉 Migration process completed!")
    return True

def validate_migration():
    """Validate that the migration was successful"""
    if not ADMIN_TOKEN:
        print("❌ Error: ADMIN_TOKEN environment variable not set")
        return False
    
    headers = {
        "Authorization": f"Bearer {ADMIN_TOKEN}",
        "Content-Type": "application/json"
    }
    
    print("🔍 Validating migration results...")
    
    try:
        # Get validation report
        response = requests.get(f"{API_BASE_URL}/api/admin/validate-registration-data", headers=headers)
        if response.status_code == 200:
            validation_data = response.json()["data"]
            issues_found = validation_data['issues_found']
            
            if issues_found == 0:
                print("✅ Validation passed: No data consistency issues found")
                return True
            else:
                print(f"⚠️ Validation found {issues_found} issues:")
                for issue in validation_data['issues'][:5]:  # Show first 5 issues
                    print(f"   - {issue['tournament']}: {', '.join(issue['issues'])}")
                return False
        else:
            print(f"❌ Validation failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error during validation: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "validate":
        success = validate_migration()
    else:
        success = run_migration()
    
    sys.exit(0 if success else 1)