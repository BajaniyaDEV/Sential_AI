MITRE_MAPPINGS = {
    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "reason": (
            "Multiple failed authentication attempts were detected "
            "from the same source within a short time window."
        ),
        "investigation_steps": [
            "Review authentication logs for the source IP.",
            "Check whether the targeted account was successfully accessed.",
            "Look for additional accounts targeted by the same IP.",
            "Consider blocking or monitoring the source IP if appropriate."
        ]
    },

    "LOGIN_AFTER_FAILURES": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "reason": (
            "A successful login occurred after multiple failed "
            "authentication attempts, which may indicate use of valid credentials."
        ),
        "investigation_steps": [
            "Verify whether the login was expected.",
            "Review the user's recent authentication history.",
            "Check for unusual source IPs or devices.",
            "Consider resetting credentials if account compromise is suspected."
        ]
    },

    "SUSPICIOUS_PUBLIC_IP": {
        "technique_id": None,
        "technique_name": "External Network Activity",
        "tactic": "Investigation Required",
        "reason": (
            "Activity originated from a public IP address that was flagged "
            "as suspicious by the SentinelAI detection logic."
        ),
        "investigation_steps": [
            "Review activity associated with the source IP.",
            "Check whether the IP belongs to an expected user or service.",
            "Correlate the IP with other alerts and events."
        ]
    },

    "ANOMALY": {
        "technique_id": None,
        "technique_name": "Behavioral Anomaly",
        "tactic": "Investigation Required",
        "reason": (
            "The machine learning model identified behavior that differs "
            "significantly from the learned baseline."
        ),
        "investigation_steps": [
            "Review the features that contributed to the anomaly.",
            "Compare the activity with the user's normal behavior.",
            "Correlate the anomaly with rule-based alerts.",
            "Determine whether additional investigation is required."
        ]
    }
}


def get_mitre_mapping(alert_type: str):
    """
    Return MITRE ATT&CK context for a SentinelAI alert type.
    """

    normalized_type = alert_type.upper().strip()

    return MITRE_MAPPINGS.get(
        normalized_type,
        {
            "technique_id": None,
            "technique_name": "No MITRE mapping available",
            "tactic": "Unknown",
            "reason": "No supported MITRE mapping exists for this alert type.",
            "investigation_steps": [
                "Review the alert and supporting evidence manually."
            ]
        }
    )