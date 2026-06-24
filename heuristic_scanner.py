import os

# Suspicious keywords and risk score
SUSPICIOUS_KEYWORDS = {
    "eval": 15,
    "exec": 15,
    "socket": 15,
    "subprocess": 10,
    "os.system": 15,
    "powershell": 20,
    "base64": 10,
    "ctypes": 15,
    "winreg": 20,
    "pynput": 25,
    "requests": 10,
    "urllib": 10,
    "ftp": 10,
    "VirtualAlloc": 20,
"VirtualProtect": 15,
"WriteProcessMemory": 25,
"CreateRemoteThread": 25,
"WinExec": 15,
"ShellExecuteA": 15,
"InternetOpenA": 15,
"URLDownloadToFileA": 20,
"GetAsyncKeyState": 25,
"SetWindowsHookExA": 25}

# Suspicious extensions
DANGEROUS_EXTENSIONS = {
    ".exe": 15,
    ".bat": 20,
    ".vbs": 20,
    ".scr": 20,
    ".ps1": 20,
    ".cmd": 15
}


def heuristic_scan(filepath):

    score = 0
    findings = []

    # Extension Analysis
    extension = os.path.splitext(filepath)[1].lower()

    if extension in DANGEROUS_EXTENSIONS:
        score += DANGEROUS_EXTENSIONS[extension]
        findings.append(
            f"Dangerous Extension Found: {extension}"
        )

    # File Size Analysis
    try:
        file_size = os.path.getsize(filepath)

        if file_size < 1024:
            score += 5
            findings.append("Very Small File")

        elif file_size > 50 * 1024 * 1024:
            score += 5
            findings.append("Very Large File")

    except Exception:
        pass

    # Content Analysis
    try:

        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            content = file.read()

        for keyword, risk in SUSPICIOUS_KEYWORDS.items():

            if keyword.lower() in content.lower():

                score += risk

                findings.append(
                    f"Keyword Found: {keyword}"
                )

    except Exception:
        findings.append(
            "Binary/Unreadable File"
        )

    # Final Verdict
    if score >= 60:
        verdict = "MALICIOUS"

    elif score >= 30:
        verdict = "SUSPICIOUS"

    else:
        verdict = "SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings
    }


# Testing
if __name__ == "__main__":

    filepath = "Testfolder"

    result = heuristic_scan(filepath)

    print("\n===== HEURISTIC SCAN REPORT =====")

    print("Threat Score :", result["score"])
    print("Verdict      :", result["verdict"])

    print("\nFindings:")

    if result["findings"]:
        for item in result["findings"]:
            print("•", item)
    else:
        print("No suspicious indicators found.")