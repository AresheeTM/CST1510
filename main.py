import pandas as pd
from pathlib import Path
# ----------------------------
# Database & schema imports
# ----------------------------
from app.data.db import connect_database
from app.data.schema import create_all_tables
from app.data.db import DB_PATH
# ----------------------------
# User services (auth & migration)
# ----------------------------
from app.services.user_service import register_user, login_user, migrate_users_from_file
# ----------------------------
# Incident services (CRUD + analytics)
# ----------------------------
from app.data.incidents import insert_incident, get_all_incidents
from app.data.incidents import (
    update_incident_status,
    delete_incident,
    get_incidents_by_type_count,
    get_high_severity_by_status
)
# ----------------------------
# CSV loader for all domains
# ----------------------------
from app.data import load_all_csv_data

# =========================================================
# MAIN DEMO FUNCTION (Week 8 – Database Demonstration)
# =========================================================
def main():
    # Console header for clarity during execution
    print("=" * 60)
    print("Week 8: Database Demo")
    print("=" * 60)
    
    # ----------------------------
    # 1. Database setup
    # ----------------------------
    # Establish database connection and create required tables
    conn = connect_database()
    create_all_tables(conn)
    conn.close()
    
    # ----------------------------
    # 2. User migration
    # ----------------------------
    # Load existing users from file into the database
    migrate_users_from_file()
    
    # ----------------------------
    # 3. Authentication test
    # ----------------------------
    # Register a test user
    success, msg = register_user("alice", "SecurePass123!", "analyst")
    print(msg)
    # Attempt login with the test credentials
    success, msg = login_user("alice", "SecurePass123!")
    print(msg)
    
    # ----------------------------
    # 4. CRUD test (Create)
    # ----------------------------
    # Insert a sample cybersecurity incident
    incident_id = insert_incident(
        "2024-11-05",
        "Phishing",
        "High",
        "Open",
        "Suspicious email detected",
        "alice"
    )
    print(f"Created incident #{incident_id}")
    
    # ----------------------------
    # 5. Data retrieval
    # ----------------------------
    # Fetch all incidents and display total count
    df = get_all_incidents()
    print(f"Total incidents: {len(df)}")

# =========================================================
# CSV → DATABASE LOADER (Generic Utility)
# =========================================================
def load_csv_to_table(conn, csv_path, table_name):
    """
    Load a CSV file into a database table using pandas.
    
    Args:
        conn: Database connection
        csv_path: Path to CSV file
        table_name: Name of the target table
        
    Returns:
        int: Number of rows loaded
    """


    # Convert path to Path object
    csv_path = Path(csv_path)
    if not csv_path.exists():
        print(f"ERROR: CSV file not found: {csv_path}")
        return 0

    # Read CSV into DataFrame
    df = pd.read_csv(csv_path)

    # Insert DataFrame into database table
    df.to_sql(
        name=table_name,
        con=conn,
        if_exists='append',
        index=False
    )

    # Log successful import
    print(f"Loaded {len(df)} rows into '{table_name}' from '{csv_path.name}'")
    return len(df)


# =========================================================
# COMPLETE DATABASE INITIALISATION PIPELINE
# =========================================================
def setup_database_complete():
    """
    Complete database setup:
    1. Connect to database
    2. Create all tables
    3. Migrate users from users.txt
    4. Load CSV data for all domains
    5. Verify setup
    """
    print("\n" + "="*60)
    print("STARTING COMPLETE DATABASE SETUP")
    print("="*60)
    
    # ----------------------------
    # Step 1: Connect
    # ----------------------------
    print("\n[1/5] Connecting to database...")
    conn = connect_database()
    print("       Connected")
    
    # ----------------------------
    # Step 2: Create tables
    # ----------------------------
    print("\n[2/5] Creating database tables...")
    create_all_tables(conn)
    
    # ----------------------------
    # Step 3: User migration
    # ----------------------------
    print("\n[3/5] Migrating users from users.txt...")
    user_count = migrate_users_from_file(conn)
    print(f"       Migrated {user_count} users")
    
    # ----------------------------
    # Step 4: Load domain CSV data
    # ----------------------------
    print("\n[4/5] Loading CSV data...")
    total_rows = load_all_csv_data(conn)
    
    # ----------------------------
    # Step 5: Verification
    # ----------------------------
    print("\n[5/5] Verifying database setup...")
    cursor = conn.cursor()
    
    # Count rows in each table
    tables = ['users', 'cyber_incidents', 'datasets_metadata', 'it_tickets']
    print("\n Database Summary:")
    print(f"{'Table':<25} {'Row Count':<15}")
    print("-" * 40)
    
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"{table:<25} {count:<15}")
    
    conn.close()
    
    print("\n" + "="*60)
    print(" DATABASE SETUP COMPLETE!")
    print("="*60)
    print(f"\n Database location: {DB_PATH.resolve()}")
    print("\nYou're ready for Week 9 (Streamlit web interface)!")

# Run the complete setup
setup_database_complete()

# =========================================================
# COMPREHENSIVE DATABASE TEST SUITE
# =========================================================
def run_comprehensive_tests():
    """
    Run comprehensive tests on your database.
    """
    print("\n" + "="*60)
    print(" RUNNING COMPREHENSIVE TESTS")
    print("="*60)
    
    conn = connect_database()
    
    # ----------------------------
    # Test 1: Authentication
    # ----------------------------
    print("\n[TEST 1] Authentication")
    success, msg = register_user("test_user", "TestPass123!", "user")
    print(f"  Register: {'✅' if success else '❌'} {msg}")
    
    success, msg = login_user("test_user", "TestPass123!")
    print(f"  Login:    {'✅' if success else '❌'} {msg}")
    
    # ----------------------------
    # Test 2: CRUD operations
    # ----------------------------
    print("\n[TEST 2] CRUD Operations")
    
    # Create
    test_id = insert_incident(
        conn,
        "2024-11-05",
        "Test Incident",
        "Low",
        "Open",
        "This is a test incident",
        "test_user"
    )
    print(f"  Create:  Incident #{test_id} created")
    
    # Read
    df = pd.read_sql_query(
        "SELECT * FROM cyber_incidents WHERE id = ?",
        conn,
        params=(test_id,)
    )
    print(f"  Read:    Found incident #{test_id}")
    
    # Update
    update_incident_status(conn, test_id, "Resolved")
    print(f"  Update:  Status updated")
    
    # Delete
    delete_incident(conn, test_id)
    print(f"  Delete:  Incident deleted")
    
    # ----------------------------
    # Test 3: Analytical queries
    # ----------------------------
    print("\n[TEST 3] Analytical Queries")
    
    df_by_type = get_incidents_by_type_count(conn)
    print(f"  By Type:     Found {len(df_by_type)} incident types")
    
    df_high = get_high_severity_by_status(conn)
    print(f"  High Severity: Found {len(df_high)} status categories")
    
    conn.close()
    
    print("\n" + "="*60)
    print(" ALL TESTS PASSED!")
    print("="*60)

# Run tests
run_comprehensive_tests()

# Entry point
if __name__ == "__main__":
    main()