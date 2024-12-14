import sqlite3

def setup_pattern_database(db_file="patterns.db"):
    """
    Setup a SQLite database with known traffic patterns and their purposes.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Create a table to store known patterns and their purposes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT,
            pattern TEXT,
            purpose TEXT
        )
    ''')
    conn.commit()
    
    # Insert some known patterns (this can be expanded)
    known_patterns = [
        ("HTTP", "GET /index.html", "Normal Web Browsing"),
        ("HTTP", "POST /login", "User Authentication"),
        ("HTTPS", "TLS Handshake", "Secure Web Browsing"),
        ("DNS", "www.example.com", "Domain Resolution"),
        ("FTP", "USER admin", "File Transfer Login Attempt"),
        ("SMTP", "MAIL FROM:<user@example.com>", "Email Sending"),
        ("SSH", "SSH-", "Remote Server Access"),
        ("HTTP", "GET /malicious", "Potential Malicious Web Request"),
        ("FTP", "PASS password", "FTP Login Attempt"),
        ("SMTP", "EHLO spammer", "Spam Email Activity")
    ]
    
    # Insert patterns into the database
    cursor.executemany('''
        INSERT OR IGNORE INTO traffic_patterns (protocol, pattern, purpose)
        VALUES (?, ?, ?)
    ''', known_patterns)
    conn.commit()
    conn.close()
    print("Pattern database setup complete.")

def analyze_purpose(patterns, db_file="patterns.db"):
    """
    Analyze traffic patterns to determine their purpose.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    results = {}

    # Compare each protocol's patterns to the database
    for protocol, detected_patterns in patterns.items():
        if isinstance(detected_patterns, int):  # For count-based protocols like HTTPS
            if protocol == "HTTPS" and detected_patterns > 0:
                results[protocol] = "Secure Web Browsing (TLS Handshakes detected)"
            continue

        results[protocol] = []
        for pattern in detected_patterns:
            cursor.execute('''
                SELECT purpose FROM traffic_patterns
                WHERE protocol = ? AND pattern LIKE ?
            ''', (protocol, f"%{pattern}%"))
            match = cursor.fetchone()
            if match:
                results[protocol].append(match[0])
            else:
                results[protocol].append("Unknown Purpose")
    
    conn.close()
    return results

pcap_file = "top6_capture.pcap"  # Replace with your pcap file path
    
# Step 1: Set up the pattern database
setup_pattern_database()

# Step 3: Analyze purpose
print("\n--- Analyzing Traffic Purpose ---")
results = analyze_purpose(patterns)

# Display results
print("\n--- Purpose Identification Results ---")
for protocol, purposes in results.items():
    print(f"{protocol}:")
    if isinstance(purposes, list):
        for purpose in purposes:
            print(f"  - {purpose}")
    else:
        print(f"  - {purposes}")