import os
import hashlib


SCAN_FOLDER = "Testfolder"
MALWARE_DB = "malware_db.txt"


def load_signatures():
    signatures = set()

    if os.path.exists(MALWARE_DB):
        with open(MALWARE_DB, "r") as file:
            for line in file:
                line = line.strip()

                if line:
                    signatures.add(line)

    return signatures


def get_sha256(file_path):

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            while True:

                chunk = file.read(4096)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None







def scan_file(file_path):

    signatures = load_signatures()

    file_hash = get_sha256(file_path)

    if file_hash is None:

        return {
            "infected": False,
            "score": 0
        }

    if file_hash in signatures:

        return {
            "infected": True,
            "score": 100
        }

    return {
        "infected": False,
        "score": 0
    }
    print("\n========== SCAN REPORT ==========")
    print("Total Files    :", total_files)
    print("Infected Files :", infected_files)
    print("Safe Files     :", total_files - infected_files)
    print("=================================")




if __name__ == "__main__":
    scan_folder(SCAN_FOLDER)
    scan_file