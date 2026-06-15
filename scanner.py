import os
import hashlib
import shutil

SCAN_FOLDER = "Testfolder"
MALWARE_DB = "malware_db.txt"
QUARANTINE_FOLDER = "quarantine"


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


def quarantine_file(file_path):

    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

    file_name = os.path.basename(file_path)

    destination = os.path.join(
        QUARANTINE_FOLDER,
        file_name
    )

    shutil.move(file_path, destination)

    print(f"Moved to quarantine -> {file_name}")


def scan_folder(folder_path):

    signatures = load_signatures()

    total_files = 0
    infected_files = 0

    print("\nScanning Started...\n")

    for root, dirs, files in os.walk(folder_path):

        for file in files:

            file_path = os.path.join(root, file)

            total_files += 1

            file_hash = get_sha256(file_path)

            if file_hash is None:
                continue

            print(f"Scanning: {file}")

            if file_hash in signatures:

                print("[INFECTED]")

                infected_files += 1

                quarantine_file(file_path)

            else:

                print("[SAFE]")

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