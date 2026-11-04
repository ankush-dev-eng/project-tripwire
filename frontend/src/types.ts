export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'VERIFIED' | 'FIXED' | 'REGRESSION';

export interface DoubleProof {
  primary_payload: unknown;
  primary_request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: unknown;
    params?: Record<string, unknown>;
  };
  primary_response: {
    status_code: number;
    body_preview?: string;
  };
  primary_succeeded: boolean;
  negative_control_payload: unknown;
  negative_control_request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: unknown;
    params?: Record<string, unknown>;
  };
  negative_control_response: {
    status_code: number;
    body_preview?: string;
  };
  negative_control_succeeded: boolean;
  reproduction_curl: string;
  confidence_score: number;
  evidence_notes?: string;
}

export interface VulnerabilityFinding {
  finding_id: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  target_endpoint: string;
  method: string;
  description: string;
  proof: DoubleProof;
  cwe_id: string;
  remediation: string;
  status: FindingStatus;
  discovered_at: string;
  metadata: {
    triage?: {
      score: number;
      base_class: string;
      asset_category: string;
      exploitability: string;
      inventory_boost: number;
      rationale: string;
    };
    retest_history?: Array<{
      timestamp: string;
      status_code: number;
      is_fixed: boolean;
      previous_status: string;
      new_status: string;
      rationale: string;
    }>;
    [key: string]: unknown;
  };
}

export interface InventoryItem {
  path: string;
  method: string;
  last_seen: string | null;
  request_count: number;
  status: 'ACTIVE' | 'ZOMBIE' | 'SHADOW';
  risk_level: string;
  recommendation: string;
}

export interface InventoryData {
  active: InventoryItem[];
  zombie: InventoryItem[];
  shadow: InventoryItem[];
}

export interface GraphNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: {
    label: string;
    node_type?: string;
    method?: string;
    path?: string;
    auth_required?: boolean;
    roles?: string[];
    [key: string]: unknown;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  data?: unknown;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface OrchestratorState {
  status: 'IDLE' | 'RECON' | 'INVENTORY' | 'PLANNING' | 'ATTACKING' | 'TRIAGING' | 'COMPLETED' | 'PAUSED' | 'ERROR';
  progress: number;
  current_step: string;
  target_url: string;
  last_scan_time: string | null;
  endpoints_count: number;
  findings_count: number;
  severity_breakdown: Record<SeverityLevel, number>;
  status_breakdown: Record<FindingStatus, number>;
  kill_switch_active: boolean;
  pending_approvals_count: number;
}

export interface ApprovalRequest {
  id: string;
  method: string;
  url: string;
  path: string;
  action_type: string;
  description: string;
  context: Record<string, unknown>;
  requested_at: number;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
}

export interface WebSocketEvent {
  type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

