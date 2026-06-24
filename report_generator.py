from datetime import datetime

LOG_FILE = "scan_log.txt"


def write_log(
        filename,
        verdict,
        score,
        details=""
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    log_entry = (
        f"[{timestamp}] | "
        f"{filename} | "
        f"{verdict} | "
        f"Score={score} | "
        f"{details}\n"
    )

    with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
    ) as log:

        log.write(log_entry)