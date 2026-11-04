from typing import List, Dict, Any, Optional
import requests
import config as cfg


def get_prediction(features: dict) -> dict:
    payload = {
        "endpoint_id": cfg.ENDPOINT_ID,
        "organization_id": cfg.ORGANIZATION_ID,
        "features": features,
    }
    response = requests.post(f"{cfg.ML_SERVICE_URL}/predict/", json=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def report_detection(
    risk_score: int,
    indicators: list,
    attack_type: str = "RANSOMWARE",
    rule_id: Optional[str] = None,
    confidence_tier: Optional[str] = None,
    evidence: Optional[List[Dict[str, Any]]] = None,
    mitre: Optional[List[Dict[str, Any]]] = None,
    model_version: str = "agent-v1.0.0",
):
    payload = {
        "organizationId": cfg.ORGANIZATION_ID,
        "endpointId": cfg.ENDPOINT_ID,
        "riskScore": int(risk_score),
        "attackType": attack_type,
        "ruleId": rule_id,
        "confidenceTier": confidence_tier,
        "indicators": indicators,
        "evidence": evidence or [],
        "mitre": mitre or [],
        "modelVersion": model_version,
    }
    headers = {"x-api-key": cfg.BACKEND_API_KEY}
    response = requests.post(
        f"{cfg.BACKEND_API_URL}/api/detections/ingest", json=payload, headers=headers, timeout=10
    )
    response.raise_for_status()
    return response.json()