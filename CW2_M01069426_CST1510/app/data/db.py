import sqlite3
from pathlib import Path
import pandas as pd

# Database path
DB_PATH = Path("DATA") / "intelligence_platform.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def connect_database(db_path=DB_PATH):
    """Connect to the SQLite database."""
    return sqlite3.connect(str(db_path))

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
        "cyber_incidents.csv": "cyber_incident",
        "datasets_metadata.csv": "datasets_metadata",
        "it_tickets.csv": "it_tickets",
        "users.txt": "users"  # New TXT file
    }

    for file_name, table_name in files_to_load.items():
        file_path = Path("DATA") / file_name
        # Use comma separator by default; change sep='\t' if TXT is tab-separated
        load_csv_to_db(file_path, table_name, conn, sep=',')

    conn.close()
    print("All files processed successfully!")
