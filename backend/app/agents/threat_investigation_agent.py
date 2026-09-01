"""
Threat Investigation Agent.

Does not just repeat the Log Analysis Agent's findings — it reconstructs the
*sequence* of the incident from the correlated timeline and writes a narrative
that explicitly cites the stages observed. Every sentence traces back to a real
timeline/detection entry stored on the incident, so the conclusion is
evidence-backed rather than speculative.
"""
from .state import InvestigationState

_STAGE_VERBS = {
    "Port Scan": "reconnaissance activity was observed",
    "SSH Brute Force": "a brute-force authentication attempt was launched",
    "Possible Credential Compromise": "a successful authentication followed the failed attempts, "
                                       "suggesting the brute-force attempt succeeded",
    "Privilege Escalation": "privilege escalation was then observed on the target host",
    "Suspicious Outbound Communication": "suspicious outbound communication consistent with "
                                          "command-and-control activity followed",
    "Web Attack": "an IDS signature matched a known web-application attack pattern",
}


def run(state: InvestigationState) -> InvestigationState:
    timeline = state.get("timeline", [])
    findings = state.get("log_analysis_findings", [])
    entities = state.get("entities", {})

    stage_order = []
    for entry in timeline:
        threat = entry["description"].split(":", 1)[0].strip()
        if threat not in stage_order:
            stage_order.append(threat)

    if not stage_order:
        state["investigation_summary"] = "No correlated detections are available for this incident yet."
        return state

    sentences = []
    for threat in stage_order:
        verb = _STAGE_VERBS.get(threat, f"a {threat} event was recorded")
        sentences.append(verb[0].upper() + verb[1:] + ".")

    src_ips = entities.get("source_ips", [])
    dest_ips = entities.get("dest_ips", [])
    lead_in = (
        f"Reconstructed timeline for source"
        f"{'s' if len(src_ips) != 1 else ''} {', '.join(src_ips) or 'unknown'} against "
        f"target{'s' if len(dest_ips) != 1 else ''} {', '.join(dest_ips) or 'unknown'}: "
    )

    is_multi_stage = len(stage_order) >= 3
    compromise = any(f["finding"] == "Possible Credential Compromise" for f in findings)
    privesc = any(f["finding"] == "Privilege Escalation" for f in findings)
    c2 = any(f["finding"] == "Suspicious Outbound Communication" for f in findings)

    if is_multi_stage and compromise:
        conclusion = (
            "The available telemetry indicates a likely multi-stage compromise. "
            "Repeated authentication failures were followed by a successful login from the same "
            "source, and " + ("subsequent privilege escalation and " if privesc else "")
            + ("suspicious outbound communication " if c2 else "")
            + "provide additional evidence consistent with host compromise."
        ).replace("  ", " ")
    elif compromise:
        conclusion = (
            "A successful authentication immediately followed repeated failures from the same "
            "source, which is consistent with a successful credential-guessing attack."
        )
    else:
        conclusion = (
            "The correlated events show early-stage attacker activity. No confirmed successful "
            "authentication has been observed yet, but the pattern warrants continued monitoring."
        )

    state["investigation_summary"] = lead_in + " ".join(sentences) + " " + conclusion
    return state
