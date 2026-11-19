"""Orchestrator for Aegis AI Security Analyst.

Combines prompt construction, provider invocation, schema validation, and
deterministic risk enforcement.
"""

import logging
import os
from datetime import datetime

from .prompts import (
    SYSTEM_PROMPT,
    build_offline_fallback_assessment,
    build_user_prompt,
)
from .provider import AIProviderError, call_chat_completion

logger = logging.getLogger(__name__)


class AIAnalystError(Exception):
    """User-displayable security analyst error."""


def analyze_scan(scan_data: dict, force_live: bool = False) -> dict:
    """Orchestrates an AI security assessment for a completed scan.

    Args:
        scan_data: Dictionary containing target, ports list, overall_risk, etc.
        force_live: If True, raises AIAnalystError when OPENAI_API_KEY is missing
                    instead of falling back to offline heuristic assessment.

    Returns:
        Structured dictionary matching the security assessment schema.
    """
    if not isinstance(scan_data, dict):
        raise AIAnalystError("Invalid scan data supplied for analysis.")

    api_key = os.environ.get("GEMINI_API_KEY", "").strip() or os.environ.get("OPENAI_API_KEY", "").strip()

    # If no API key configured and not forcing live call, use expert heuristic engine
    if not api_key:
        if force_live:
            raise AIAnalystError("OPENAI_API_KEY is not configured in the server environment.")
        logger.info("OPENAI_API_KEY not configured. Generating offline heuristic security assessment.")
        fallback = build_offline_fallback_assessment(scan_data)
        fallback["generated_at"] = datetime.now().strftime("%d %B %Y, %H:%M")
        return fallback

    # Prepare input prompts
    user_prompt = build_user_prompt(scan_data)

    try:
        raw_analysis, model_used = call_chat_completion(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )
    except AIProviderError as err:
        logger.warning("Live AI provider failed (%s). Checking fallback availability.", err)
        if force_live:
            raise AIAnalystError(str(err)) from err
        # Graceful fallback: return offline assessment on transient provider failure
        fallback = build_offline_fallback_assessment(scan_data)
        fallback["_provider_warning"] = str(err)
        fallback["generated_at"] = datetime.now().strftime("%d %B %Y, %H:%M")
        return fallback

    # Validate and enforce deterministic risk constraints
    validated = validate_and_enforce_risks(raw_analysis, scan_data)
    validated["_model"] = model_used
    validated["generated_at"] = datetime.now().strftime("%d %B %Y, %H:%M")
    return validated


def validate_and_enforce_risks(raw_analysis: dict, scan_data: dict) -> dict:
    """Validates the structure of the AI analysis and strictly enforces Aegis's

    deterministic risk levels so the LLM cannot overwrite or downgrade them.
    """
    if not isinstance(raw_analysis, dict):
        raise AIAnalystError("AI returned non-object response format.")

    summary = str(raw_analysis.get("summary", "")).strip()
    if not summary:
        summary = f"Security exposure assessment for {scan_data.get('target', 'target host')}."

    # Build reference lookup from Aegis's verified deterministic port findings
    scan_ports = scan_data.get("ports", [])
    scan_port_lookup = {}
    for p in scan_ports:
        try:
            port_num = int(p.get("port"))
            scan_port_lookup[port_num] = {
                "risk": str(p.get("risk", "LOW")).upper(),
                "service": str(p.get("service", "unknown")),
                "reason": str(p.get("reason", "")),
            }
        except (ValueError, TypeError):
            continue

    raw_findings = raw_analysis.get("findings", [])
    sanitized_findings = []

    if isinstance(raw_findings, list):
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            try:
                p_num = int(item.get("port"))
            except (ValueError, TypeError):
                continue

            # Only retain findings for ports actually verified in the scan
            if p_num not in scan_port_lookup:
                logger.warning("Dropping unverified hallucinated port %s from AI findings", p_num)
                continue

            ref = scan_port_lookup[p_num]
            # MANDATORY CONSTRAINT: Force deterministic Aegis risk level
            enforced_risk = ref["risk"]
            service = str(item.get("service", ref["service"])).strip() or ref["service"]

            why = str(item.get("why_it_matters", "")).strip() or ref["reason"]
            concern = str(item.get("security_concern", "")).strip() or (
                f"Potential security exposure on service '{service}'."
            )

            sanitized_findings.append({
                "port": p_num,
                "service": service,
                "aegis_risk": enforced_risk,
                "why_it_matters": why,
                "security_concern": concern,
            })

    # Ensure every scanned port has an entry in findings
    covered_ports = {f["port"] for f in sanitized_findings}
    for p_num, ref in scan_port_lookup.items():
        if p_num not in covered_ports:
            sanitized_findings.append({
                "port": p_num,
                "service": ref["service"],
                "aegis_risk": ref["risk"],
                "why_it_matters": ref["reason"],
                "security_concern": f"Exposed network service on port {p_num}.",
            })

    # Sort findings by port number for neat presentation
    sanitized_findings.sort(key=lambda x: x["port"])

    # Validate recommendations
    raw_recs = raw_analysis.get("recommendations", [])
    recommendations = []
    if isinstance(raw_recs, list):
        for r in raw_recs:
            if isinstance(r, str) and r.strip():
                recommendations.append(r.strip())

    if not recommendations:
        recommendations = [
            "1. Review exposed listening ports and restrict unnecessary public access.",
            "2. Enforce host-based firewall rules to restrict services to authorized subnets.",
        ]

    # Validate beginner explanation
    beginner_explanation = str(raw_analysis.get("beginner_explanation", "")).strip()
    if not beginner_explanation:
        beginner_explanation = (
            "Network ports are like digital doors into a computer. Open ports allow "
            "data to flow in and out. Securing a system means keeping only essential "
            "doors open and guarding them with passwords and encryption."
        )

    # Validate verification steps
    raw_verify = raw_analysis.get("verification_steps", [])
    verification_steps = []
    if isinstance(raw_verify, list):
        for v in raw_verify:
            if isinstance(v, str) and v.strip():
                verification_steps.append(v.strip())

    if not verification_steps:
        target = scan_data.get("target", "127.0.0.1")
        verification_steps = [f"Run 'nmap -sT -F {target}' to verify that remediated ports are closed."]

    return {
        "summary": summary,
        "findings": sanitized_findings,
        "recommendations": recommendations,
        "beginner_explanation": beginner_explanation,
        "verification_steps": verification_steps,
    }
