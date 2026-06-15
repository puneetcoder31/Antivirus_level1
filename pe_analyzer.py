import pefile


SUSPICIOUS_IMPORTS = {
    "VirtualAlloc": 20,
    "VirtualProtect": 15,
    "WriteProcessMemory": 25,
    "CreateRemoteThread": 25,
    "WinExec": 15,
    "ShellExecuteA": 10,
    "ShellExecuteW": 10,
    "URLDownloadToFileA": 20,
    "URLDownloadToFileW": 20,
    "InternetOpenA": 15,
    "InternetOpenW": 15,
    "InternetReadFile": 15,
    "GetAsyncKeyState": 25,
    "SetWindowsHookExA": 25,
    "SetWindowsHookExW": 25
}


def analyze_pe(filepath):

    score = 0
    findings = []

    try:

        pe = pefile.PE(filepath)

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return {
                "score": 0,
                "findings": ["No Import Table"]
            }

        for dll in pe.DIRECTORY_ENTRY_IMPORT:

            for imp in dll.imports:

                if imp.name:

                    func = imp.name.decode(
                        errors="ignore"
                    )

                    if func in SUSPICIOUS_IMPORTS:

                        score += SUSPICIOUS_IMPORTS[func]

                        findings.append(
                            f"Suspicious API: {func}"
                        )

        return {
            "score": score,
            "findings": findings
        }

    except Exception:

        return {
            "score": 0,
            "findings": [
                "Not a PE File"
            ]
        }


if __name__ == "__main__":

    file_path = "Testfolder"

    result = analyze_pe(file_path)

    print("\n===== PE ANALYSIS =====")

    print(
        "PE Score:",
        result["score"]
    )

    print("\nFindings:")

    for item in result["findings"]:
        print("-", item)