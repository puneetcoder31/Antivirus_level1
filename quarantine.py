import os
import shutil

QUARANTINE_FOLDER = "quarantine"

def quarantine_file(filepath):

    os.makedirs(
        QUARANTINE_FOLDER,
        exist_ok=True
    )

    filename = os.path.basename(filepath)

    destination = os.path.join(
        QUARANTINE_FOLDER,
        filename
    )

    shutil.move(
        filepath,
        destination
    )

    print(
        f"[QUARANTINED] {filename}"
    )