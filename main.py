import os

from scanner.signature_scanner import scan_file
from scanner.heuristic_scanner import heuristic_scan
from scanner.pe_analyzer import analyze_pe

from scanner.threat_engine import (
    calculate_threat_score,
    get_verdict
)


def scan_target(filepath):

    print("\n")
    print("=" * 60)
    print("Scanning :", filepath)
    print("=" * 60)

    # ---------------------------------
    # Signature Scanner
    # ---------------------------------

    signature_result = scan_file(filepath)

    print("\n[1] SIGNATURE SCAN")

    if signature_result:
        print("Result : INFECTED")
    else:
        print("Result : SAFE")

    # ---------------------------------
    # Heuristic Scanner
    # ---------------------------------

    heuristic_result = heuristic_scan(filepath)

    print("\n[2] HEURISTIC SCAN")

    print("Score   :",
          heuristic_result["score"])

    print("Verdict :",
          heuristic_result["verdict"])

    print("\nFindings:")

    if heuristic_result["findings"]:

        for item in heuristic_result["findings"]:
            print("-", item)

    else:
        print("No suspicious indicators")

    # ---------------------------------
    # PE Analysis
    # ---------------------------------

    pe_result = analyze_pe(filepath)

    print("\n[3] PE ANALYSIS")

    print("Score :",
          pe_result["score"])

    print("\nFindings:")

    if pe_result["findings"]:

        for item in pe_result["findings"]:
            print("-", item)

    else:
        print("No PE indicators")

    # ---------------------------------
    # Threat Engine
    # ---------------------------------

    final_score = calculate_threat_score(
        signature_result,
        heuristic_result["score"],
        pe_result["score"]
    )

    final_verdict = get_verdict(
        final_score
    )

    print("\n[4] THREAT ENGINE")

    print("Final Score   :",
          final_score)

    print("Final Verdict :",
          final_verdict)

    return final_verdict


def scan_folder(folder):

    total_files = 0
    threats = 0

    for root, dirs, files in os.walk(folder):

        for file in files:

            filepath = os.path.join(
                root,
                file
            )

            total_files += 1

            verdict = scan_target(
                filepath
            )

            if verdict != "SAFE":
                threats += 1

    print("\n")
    print("=" * 60)
    print("FINAL REPORT")
    print("=" * 60)

    print("Total Files   :", total_files)
    print("Threats Found :", threats)
    print("Safe Files    :",
          total_files - threats)

    print("=" * 60)


if __name__ == "__main__":

    folder = input(
        "Enter Folder Path : "
    )

    scan_folder(folder)