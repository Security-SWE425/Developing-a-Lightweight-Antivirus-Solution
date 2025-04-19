import hashlib
import os
import shutil
import datetime
import re
import pefile
import yara
import sqlite3
from typing import List, Dict

class LightweightAntivirus:
    def __init__(self, database_path: str = "signatures.db", quarantine_dir: str = "quarantine"):
        self.database_path = database_path
        self.quarantine_dir = quarantine_dir
        self.yara_rules_path = "malware_rules.yar"
        self.setup_database()
        self.setup_quarantine()
        self.setup_yara_rules()

    def setup_database(self) -> None:
        """Initialize SQLite database for storing malware signatures."""
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT UNIQUE,
                    name TEXT,
                    description TEXT
                )
            """)
            conn.commit()

    def setup_quarantine(self) -> None:
        """Create quarantine directory if it doesn't exist."""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def setup_yara_rules(self) -> None:
        """Create basic YARA rules for heuristic detection."""
        rules = """
        rule SuspiciousStrings {
            strings:
                $malware1 = "malicious" nocase
                $malware2 = "backdoor" nocase
                $malware3 = "ransomware" nocase
            condition:
                any of them
        }
        """
        # Ensure the YARA rules file is overwritten with the correct content
        try:
            with open(self.yara_rules_path, "w") as f:
                f.write(rules.strip())
            # Verify file content
            with open(self.yara_rules_path, "r") as f:
                content = f.read()
                if "pe.imports" in content or "pe." in content:
                    raise ValueError("YARA rules file contains invalid 'pe' references")
            # Compile YARA rules
            self.yara_rules = yara.compile(self.yara_rules_path)
        except yara.SyntaxError as e:
            print(f"YARA compilation error: {e}")
            raise
        except Exception as e:
            print(f"Error setting up YARA rules: {e}")
            raise

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return ""

    def add_signature(self, file_hash: str, name: str, description: str) -> None:
        """Add a malware signature to the database."""
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO signatures (hash, name, description) VALUES (?, ?, ?)",
                    (file_hash, name, description)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                print(f"Signature {file_hash} already exists.")

    def signature_scan(self, file_path: str) -> Dict[str, str]:
        """Perform signature-based scan on a file."""
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return {}

        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, description FROM signatures WHERE hash = ?", (file_hash,))
            result = cursor.fetchone()
            if result:
                return {"name": result[0], "description": result[1], "type": "signature"}
        return {}

    def heuristic_scan(self, file_path: str) -> Dict[str, str]:
        """Perform heuristic scan using YARA rules and PE analysis."""
        try:
            # YARA scan
            matches = self.yara_rules.match(file_path)
            if matches:
                return {
                    "name": "Heuristic Match",
                    "description": f"YARA rules matched: {', '.join([m.rule for m in matches])}",
                    "type": "heuristic"
                }

            # PE analysis for executables
            if file_path.lower().endswith((".exe", ".dll")):
                try:
                    pe = pefile.PE(file_path)
                    suspicious = False
                    description = []

                    # Check for suspicious imports
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            for imp in entry.imports:
                                if imp.name and b"CreateRemoteThread" in imp.name:
                                    suspicious = True
                                    description.append("Suspicious import: CreateRemoteThread")

                    # Check for low section entropy (possible packing)
                    for section in pe.sections:
                        if section.get_entropy() < 1.0:
                            suspicious = True
                            description.append(f"Low entropy section: {section.Name.decode().strip()}")

                    if suspicious:
                        return {
                            "name": "Suspicious PE",
                            "description": "; ".join(description),
                            "type": "heuristic"
                        }
                except pefile.PEFormatError:
                    print(f"Invalid PE file format: {file_path}")
        except Exception as e:
            print(f"Error in heuristic scan for {file_path}: {e}")
        return {}

    def scan_file(self, file_path: str) -> Dict[str, str]:
        """Scan a file using both signature and heuristic methods."""
        result = self.signature_scan(file_path)
        if not result:
            result = self.heuristic_scan(file_path)
        return result

    def quarantine_file(self, file_path: str) -> bool:
        """Move a detected malicious file to quarantine."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"{timestamp}_{filename}")
            shutil.move(file_path, quarantine_path)
            print(f"File quarantined: {quarantine_path}")
            return True
        except Exception as e:
            print(f"Error quarantining file {file_path}: {e}")
            return False

    def remove_file(self, file_path: str) -> bool:
        """Permanently delete a malicious file."""
        try:
            os.remove(file_path)
            print(f"File removed: {file_path}")
            return True
        except Exception as e:
            print(f"Error removing file {file_path}: {e}")
            return False

    def scan_directory(self, directory: str) -> List[Dict[str, str]]:
        """Scan all files in a directory and return detected threats."""
        threats = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                result = self.scan_file(file_path)
                if result:
                    result["file_path"] = file_path
                    threats.append(result)
        return threats

    def run(self) -> None:
        """Run the antivirus with a command-line interface."""
        print("Lightweight Antivirus Solution")
        while True:
            print("\nOptions:")
            print("1. Scan directory")
            print("2. Add signature")
            print("3. Quarantine threat")
            print("4. Remove threat")
            print("5. Exit")
            choice = input("Select an option (1-5): ")

            if choice == "1":
                directory = input("Enter directory to scan: ")
                if os.path.exists(directory):
                    threats = self.scan_directory(directory)
                    if threats:
                        print("\nThreats detected:")
                        for threat in threats:
                            print(f"File: {threat['file_path']}")
                            print(f"Name: {threat['name']}")
                            print(f"Description: {threat['description']}")
                            print(f"Type: {threat['type']}\n")
                    else:
                        print("No threats detected.")
                else:
                    print("Directory not found.")

            elif choice == "2":
                file_path = input("Enter file path for signature: ")
                if os.path.exists(file_path):
                    file_hash = self.calculate_file_hash(file_path)
                    name = input("Enter malware name: ")
                    description = input("Enter description: ")
                    self.add_signature(file_hash, name, description)
                    print("Signature added successfully.")
                else:
                    print("File not found.")

            elif choice == "3":
                file_path = input("Enter file path to quarantine: ")
                if os.path.exists(file_path):
                    self.quarantine_file(file_path)
                else:
                    print("File not found.")

            elif choice == "4":
                file_path = input("Enter file path to remove: ")
                if os.path.exists(file_path):
                    self.remove_file(file_path)
                else:
                    print("File not found.")

            elif choice == "5":
                print("Exiting...")
                break

            else:
                print("Invalid option.")

if __name__ == "__main__":
    antivirus = LightweightAntivirus()
    antivirus.run()