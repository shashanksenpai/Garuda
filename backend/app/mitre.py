MITRE_TECHNIQUES = {
    "recon_port_scan": {"id": "T1046", "name": "Network Service Discovery"},
    "brute_force": {"id": "T1110", "name": "Brute Force"},
    "valid_accounts": {"id": "T1078", "name": "Valid Accounts"},
    "privilege_escalation": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    "c2": {"id": "T1071", "name": "Application Layer Protocol (C2)"},
    "web_attack": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "dos": {"id": "T1498", "name": "Network Denial of Service"},
    "persistence": {"id": "T1543", "name": "Create or Modify System Process"},
}


def technique(key: str) -> dict:
    return MITRE_TECHNIQUES.get(key, {"id": None, "name": None})
