from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class BehaviourFeatures(BaseModel):
    """
    Behavioural features computed by the agent over sliding windows.
    Matches the 21 features extracted from Sysmon/simulated telemetry.
    """
    process_create_count: float = 0.0
    process_terminated_count: float = 0.0
    file_create_count: float = 0.0
    file_creation_time_changed: float = 0.0
    registry_write_count: float = 0.0
    pipe_create_count: float = 0.0
    network_connection_count: float = 0.0
    dns_query_count: float = 0.0
    file_activity_rate: float = 0.0
    process_activity_rate: float = 0.0
    network_activity_rate: float = 0.0
    registry_activity_rate: float = 0.0
    pipe_activity_rate: float = 0.0
    unique_extensions_written: float = 0.0
    unique_directories_touched: float = 0.0
    known_encrypted_ext_count: float = 0.0
    file_operation_ratio: float = 0.0
    file_name_entropy: float = 0.0
    average_file_path_length: float = 0.0
    suspicious_path_ratio: float = 0.0
    network_unique_destinations: float = 0.0

    class Config:
        extra = "allow"
        populate_by_name = True


class PredictionRequest(BaseModel):
    endpoint_id: str
    organization_id: str
    features: BehaviourFeatures


class PredictionResponse(BaseModel):
    risk_score: int
    is_ransomware: bool
    confidence: float
    model_version: str