"""
Response Agent.

Turns the investigation result + risk assessment into concrete recommendations,
grouped into immediate containment / investigation / recovery. These are always
presented as recommendations for a human analyst to execute — GARUDA does not
take response actions automatically.
"""
from .state import InvestigationState


def run(state: InvestigationState) -> InvestigationState:
    findings = {f["finding"] for f in state.get("log_analysis_findings", [])}
    entities = state.get("entities", {})
    src_ips = entities.get("source_ips", [])
    users = entities.get("users", [])
    hosts = entities.get("hosts", [])

    immediate, investigation, recovery = [], [], []

    if src_ips:
        immediate.append(f"Block source IP(s): {', '.join(src_ips)} at the perimeter firewall/IDS.")
    if hosts:
        immediate.append(f"Isolate affected host(s): {', '.join(hosts)} from the network.")
    if "Possible Credential Compromise" in findings and users:
        immediate.append(f"Disable or force password reset for account(s): {', '.join(users)}.")
    if "Suspicious Outbound Communication" in findings:
        immediate.append("Terminate the suspicious outbound session(s) and block the destination.")
    if "Denial of Service Flood" in findings and src_ips:
        immediate.append(f"Rate-limit or null-route source IP(s): {', '.join(src_ips)} to mitigate the flood.")
    if not immediate:
        immediate.append("Continue monitoring; no immediate containment action is required yet.")

    # Machine-actionable mirror of the immediate-containment recommendations above, consumed
    # by response_engine.py under the manual/hybrid/auto policy. Kept in lockstep with the
    # prose so the two never disagree about what's being recommended.
    structured_actions: list[dict] = []
    if src_ips:
        structured_actions.append({"action": "block_ip", "params": {"ip_addresses": sorted(src_ips)}})
    if ("Port Scan" in findings or "Denial of Service Flood" in findings) and src_ips:
        structured_actions.append({"action": "rate_limit", "params": {"ip_addresses": sorted(src_ips)}})
    if hosts:
        structured_actions.append({"action": "isolate_host", "params": {"hostnames": sorted(hosts)}})
    if "Possible Credential Compromise" in findings and users:
        structured_actions.append({"action": "disable_account", "params": {"usernames": sorted(users)}})
    if "Suspicious Outbound Communication" in findings:
        structured_actions.append({"action": "kill_session", "params": {"hostnames": sorted(hosts) or sorted(src_ips)}})
    structured_actions.append({"action": "alert_soc", "params": {}})

    investigation.append("Review full authentication history for the affected account(s)/host(s).")
    if "Privilege Escalation" in findings:
        investigation.append("Inspect running processes and scheduled tasks for signs of persistence.")
    if "Suspicious Outbound Communication" in findings:
        investigation.append("Analyze outbound connection destinations for known C2 infrastructure.")
    if "Web Attack" in findings:
        investigation.append("Review web server / application logs around the alert timestamp for exploitation evidence.")
    investigation.append("Check related hosts for the same source IP or indicators of compromise.")

    if "Possible Credential Compromise" in findings:
        recovery.append("Rotate credentials for all potentially compromised accounts.")
    if "Privilege Escalation" in findings:
        recovery.append("Remove any unauthorized persistence mechanisms found during investigation.")
    recovery.append("Patch or harden the exposed service that was targeted.")
    recovery.append("Restore affected systems from a known-good state if compromise is confirmed.")

    state["recommended_actions"] = {
        "immediate": immediate,
        "investigation": investigation,
        "recovery": recovery,
    }
    state["structured_actions"] = structured_actions
    return state
