import sqlite3
import ipaddress
import logging

DB_NAME = "data.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    """Initialize the database tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Cloudflare Ranges Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cloudflare_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr TEXT UNIQUE
        )
    ''')
    
    # Results Table (as requested, we save results, not just targets)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            result_data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def insert_cloudflare_ranges(ranges):
    """Insert Cloudflare CIDR ranges into the database."""
    conn = get_connection()
    cursor = conn.cursor()
    
    count = 0
    for cidr in ranges:
        try:
            # Validate CIDR before inserting
            ipaddress.ip_network(cidr.strip())
            cursor.execute('INSERT OR IGNORE INTO cloudflare_ranges (cidr) VALUES (?)', (cidr.strip(),))
            if cursor.rowcount > 0:
                count += 1
        except ValueError:
            print(f"Skipping invalid CIDR: {cidr}")
            
    conn.commit()
    conn.close()
    return count

def get_cloudflare_ranges():
    """Retrieve all Cloudflare ranges from DB."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT cidr FROM cloudflare_ranges')
    rows = cursor.fetchall()
    conn.close()
    return [row[0] for row in rows]

def is_cloudflare_ip(ip_str):
    """Check if an IP address belongs to any Cloudflare range in the DB."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    ranges = get_cloudflare_ranges()
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip in network:
                return True
        except ValueError:
            continue
            
    return False

# Initial Cloudflare Ranges provided by user
CLOUDFLARE_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32"
]

if __name__ == "__main__":
    # If run directly, initialize DB and insert default CF ranges
    print("Initializing Database...")
    init_db()
    print("Inserting Cloudflare Ranges...")
    added = insert_cloudflare_ranges(CLOUDFLARE_RANGES)
    print(f"Added {added} new Cloudflare ranges.")
