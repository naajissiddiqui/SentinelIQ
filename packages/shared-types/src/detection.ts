import { DetectionStatus, DetectionSeverity, AttackType, ConfidenceTier, DataOrigin, DetectorStatus } from "./enums";

export interface BehaviourIndicator {
  type: string;
  description: string;
  observedAt: string;
}

export interface MitreMapping {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  attackVersion: string;
  referenceUrl: string;
  evidenceRef?: string[];
  /** Why this technique was assigned (rule mapping, detection behaviour or indicator). */
  mappingReason?: string;
}

export interface EvidenceItem {
  id: string;
  source: string;
  eventId?: number;
  time: string;
  description: string;
  fields?: Record<string, any>;
}

export interface Detection {
  _id: string;
  organizationId: string;
  endpointId: string;
  endpointName: string;
  attackType?: AttackType | string;
  ruleId?: string;
  confidenceTier?: ConfidenceTier | string;
  riskScore: number;
  severity: DetectionSeverity;
  status: DetectionStatus;
  indicators: BehaviourIndicator[];
  evidence?: EvidenceItem[];
  mitre?: MitreMapping[];
  modelVersion?: string;
  detectedAt: string;
  resolvedAt?: string;
  resolvedByUserId?: string;
  createdAt: string;
  updatedAt: string;
  ctiMatch?: any;
  cascadeId?: string;
  dataOrigin?: DataOrigin | string;
  detectorStatus?: DetectorStatus | string;
}