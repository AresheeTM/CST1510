import sqlite3
from pathlib import Path
import pandas as pd

# Database path
DB_PATH = Path("DATA") / "intelligence_platform.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def connect_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create main tables if they don't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cyber_incidents (
            incident_id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL,
            description TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dataset_metadata (
            dataset_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            rows INTEGER NOT NULL,
            columns INTEGER NOT NULL,
            uploaded_by TEXT,
            upload_date TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS it_tickets (
            ticket_id INTEGER PRIMARY KEY,
            priority TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL,
            assigned_to TEXT,
            created_at TEXT NOT NULL,
            resolution_time_hours REAL
        )
    """)

    # New users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT,
            role TEXT,
            join_date TEXT
        )
    """)

    conn.commit()
    return conn


def load_csv_to_db(file_path, table_name, conn, sep=','):
    """
    Load a CSV or TXT file into the SQLite database and preview the table.
    
    Args:
        file_path (Path): Path to the CSV/TXT file
        table_name (str): Target table name in the database
        conn (sqlite3.Connection): Active database connection
        sep (str): Separator character (default ',')
    """
    try:
        # Load CSV/TXT with pandas
        df = pd.read_csv(file_path, sep=sep)

        # Clean column names
        df.columns = [c.strip().replace(" ", "_").replace("-", "_") for c in df.columns]

        # Insert into SQLite (replace table if it exists)
        df.to_sql(table_name, conn, if_exists="replace", index=False)

        # Preview table
        print(f"\n✅ Table '{table_name}' preview:")
        print(df.head())
        print(f"Loaded {len(df)} rows into table '{table_name}' successfully!\n")
    except FileNotFoundError:
        print(f"⚠️ Warning: '{file_path.name}' not found. Skipping this file.")
    except pd.errors.EmptyDataError:
        print(f"⚠️ Warning: '{file_path.name}' is empty. Skipping this file.")
    except Exception as e:
        print(f"❌ Error loading '{file_path.name}': {e}")


if __name__ == "__main__":
    conn = connect_database()

    # Files to load: CSVs and TXT
    files_to_load = {
        "cyber_incidents.csv": "cyber_incidents",
        "datasets_metadata.csv": "dataset_metadata",
        "it_tickets.csv": "it_tickets",
    }

    for file_name, table_name in files_to_load.items():
        file_path = Path("DATA") / file_name
        # Detect separator: TXT as tab by default, CSV as comma
        sep = '\t' if file_path.suffix.lower() == '.txt' else ','
        load_csv_to_db(file_path, table_name, conn, sep=sep)

    conn.close()
    print("All files processed successfully!")
