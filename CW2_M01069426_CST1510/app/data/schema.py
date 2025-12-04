import os
import pandas as pd

def create_users_table(conn):
    """Create users table."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.commit()

def create_all_tables(conn):
    """Create all tables."""


    create_users_table(conn)
    create_cyber_incidents_table(conn)
    create_datasets_metadata_table(conn)
    create_it_tickets_table(conn)

# ---------------------------------------------------------------
#                 FILLED TODO SECTIONS BELOW
# ---------------------------------------------------------------

def create_cyber_incidents_table(conn):
    """
    Create the cyber_incidents table.
    """
    # TODO: Get a cursor from the connection
    cursor = conn.cursor()

    # TODO: Write CREATE TABLE IF NOT EXISTS SQL statement
    cursor.execute("""
       CREATE TABLE cyber_incidents (
    incident_id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    description TEXT
);


    """)

    # TODO: Commit the changes
    conn.commit()

    # TODO: Print success message
    print("cyber_incidents table created successfully.")


def create_datasets_metadata_table(conn):
    """
    Create the datasets_metadata table.
    """
    cursor = conn.cursor()

    cursor.execute("""
      CREATE TABLE dataset_metadata (
    dataset_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    rows INTEGER NOT NULL,
    columns INTEGER NOT NULL,
    uploaded_by TEXT,
    upload_date TEXT
);


    """)

    conn.commit()
    print("datasets_metadata table created successfully.")


def create_it_tickets_table(conn):
    """
    Create the it_tickets table.
    """
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE it_tickets (
    ticket_id INTEGER PRIMARY KEY,
    priority TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL,
    assigned_to TEXT,
    created_at TEXT NOT NULL,
    resolution_time_hours REAL
);


    """)

    conn.commit()
    print("it_tickets table created successfully.")


def load_csv_to_table(conn, csv_path, table_name):
    """
    Load a CSV file into a database table using pandas.
    
    TODO: Implement this function.
    
    Args:
        conn: Database connection
        csv_path: Path to CSV file
        table_name: Name of the target table
        
    Returns:
        int: Number of rows loaded
    """
    # TODO: Check if CSV file exists
    if not os.path.exists(csv_path):
        print(f"[ERROR] CSV file not found: {csv_path}")
        return 0

    # TODO: Read CSV using pandas.read_csv()
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[ERROR] Failed to read CSV: {e}")
        return 0

    # TODO: Use df.to_sql() to insert data
    # Parameters: name=table_name, con=conn, if_exists='append', index=False
    try:
        df.to_sql(name=table_name, con=conn, if_exists='append', index=False)
    except Exception as e:
        print(f"[ERROR] Failed to insert into table '{table_name}': {e}")
        return 0

    # TODO: Print success message and return row count
    row_count = len(df)
    print(f"[SUCCESS] Loaded {row_count} rows into '{table_name}' from {csv_path}")

    return row_count
