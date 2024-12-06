import psycopg2
from psycopg2 import sql
import os

def create_database():
    conn = psycopg2.connect(
        dbname="postgres",  # Default database to connect to
        user=os.environ['POSTGRES_USER'],
        password=os.environ['POSTGRES_PASSWORD'],
        host=os.environ['POSTGRES_HOST'],
        port=os.environ.get('POSTGRES_PORT','POSTGRES_PORTT')  # Use environment variable for the port
    )
    conn.autocommit = True
    cursor = conn.cursor()

    try:
        cursor.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{os.environ['POSTGRES_DB']}'")
        if cursor.fetchone():
            print(f"Database '{os.environ['POSTGRES_DB']}' already exists.")
        else:
            print(f"Creating database '{os.environ['POSTGRES_DB']}'...")
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(os.environ['POSTGRES_DB'])))
            print(f"Database '{os.environ['POSTGRES_DB']}' created.")
    except Exception as e:
        print(f"Error occurred while creating database: {e}")
    finally:
        cursor.close()
        conn.close()

def run_init_scripts():
    print("Running initialization scripts...")

    conn = psycopg2.connect(
        dbname=os.environ['POSTGRES_DB'],
        user=os.environ['POSTGRES_USER'],
        password=os.environ['POSTGRES_PASSWORD'],
        host=os.environ['POSTGRES_HOST'],
        port=os.environ.get('POSTGRES_PORT','POSTGRES_PORTT')   # Use environment variable for the port
    )

    cursor = conn.cursor()

    try:
        with open('/app/backend/scripts/initialize.sql', 'r') as f:
            cursor.execute(f.read())
        print("Initialization scripts executed.")
    except Exception as e:
        print(f"Error executing initialization scripts: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    create_database()
    run_init_scripts()
