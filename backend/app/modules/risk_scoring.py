from typing import Dict, Any, List, Tuple

# Deductions
SCORE_CRITICAL = 30
SCORE_HIGH = 20
SCORE_MEDIUM = 10
SCORE_LOW = 5
SCORE_INFO = 0

def calculate_risk_score(findings: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates a deterministic risk score (0-100) based on findings.
    Input: Dictionary of findings/scan data.
    Output: Dictionary with 'score', 'grade', 'risks_list'.
    
    Security: Rule-based, no ML.
    """
    score = 100
    risks = []

    # 1. Missing Security Headers
    sec_headers = findings.get("security_headers", {})
    if isinstance(sec_headers, dict):
        missing = sec_headers.get("missing_headers", [])
        if missing:
            count = len(missing)
            deduction = min(50, count * 5) # Cap deduction for headers
            score -= deduction
            risks.append({
                "severity": "Medium",
                "finding": f"Missing {count} critical security headers",
                "deduction": deduction
            })

    # 2. Exposed Directories
    dir_exp = findings.get("directory_exposure", {})
    if isinstance(dir_exp, dict):
        exposed = dir_exp.get("exposed_directories", [])
        if exposed:
            # High risk
            deduction = SCORE_HIGH * len(exposed)
            score -= deduction
            risks.append({
                "severity": "High",
                "finding": f"Exposed Directory Listing ({len(exposed)} paths)",
                "deduction": deduction
            })

    # 3. Public Files Findings
    pub_files = findings.get("public_files", {})
    if isinstance(pub_files, dict):
        findings_list = pub_files.get("interesting_findings", [])
        if findings_list:
             deduction = SCORE_LOW * len(findings_list)
             score -= deduction
             risks.append({
                "severity": "Low",
                "finding": f"Sensitive Info in Public Files ({len(findings_list)} items)",
                "deduction": deduction
            })

    # 4. Code Leaks
    leaks = findings.get("code_leaks", {})
    if isinstance(leaks, dict) and leaks.get("count", 0) > 0:
         # Critical/High
         deduction = SCORE_HIGH # Flat deduction for presence of leaks
         score -= deduction
         risks.append({
             "severity": "High",
             "finding": "Potential Code/Credential Leak detected",
             "deduction": deduction
         })

    # 5. SSL Issues
    ssl_data = findings.get("ssl", {})
    if isinstance(ssl_data, dict):
        if ssl_data.get("is_expired"):
             deduction = SCORE_CRITICAL
             score -= deduction
             risks.append({
                 "severity": "Critical",
                 "finding": "SSL Certificate Expired",
                 "deduction": deduction
             })
        elif not ssl_data.get("valid"):
             deduction = SCORE_MEDIUM
             score -= deduction
             risks.append({
                 "severity": "Medium",
                 "finding": "SSL Configuration Invalid",
                 "deduction": deduction
             })

    # Floor score at 0
    score = max(0, score)

    # Calculate Grade
    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else: grade = "F"

    return {
        "score": score,
        "grade": grade,
        "risks": risks
    }
