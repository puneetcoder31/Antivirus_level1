def calculate_threat_score(
        signature_result,
        heuristic_score,
        pe_score):

    score = 0

    # Signature Detection
    if signature_result["infected"]:
        score += 100

    # Heuristic Detection
    score += heuristic_score

    # PE Analysis
    score += pe_score

    # Cap score at 100
    if score > 100:
        score = 100

    return score


def get_verdict(score):

    if score >= 80:
        return "MALICIOUS"

    elif score >= 40:
        return "SUSPICIOUS"

    else:
        return "SAFE"