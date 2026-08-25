from mitre.mapper import get_mitre_mapping

alert_types = [
    "BRUTE_FORCE",
    "LOGIN_AFTER_FAILURES",
    "SUSPICIOUS_PUBLIC_IP",
    "ANOMALY"
]

for alert_type in alert_types:
    print("\n" + "=" * 50)
    print(f"ALERT TYPE: {alert_type}")

    mapping = get_mitre_mapping(alert_type)

    for key, value in mapping.items():
        print(f"{key}: {value}")