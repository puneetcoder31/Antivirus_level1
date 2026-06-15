import hashlib
import os

def get_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()

file_name = input("Enter file name: ")

if os.path.exists(file_name):
    file_hash = get_sha256(file_name)

    print("SHA-256 Hash:")
    print(file_hash)

    with open("malwaredb.txt", "a") as db:
        db.write(file_hash + "\n")

    print("Hash saved to malwaredb.txt")
else:
    print("File not found!")