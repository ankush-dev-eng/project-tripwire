import {
  ApprovalRequest,
  GraphData,
  InventoryData,
  OrchestratorState,
  VulnerabilityFinding,
} from '../types';

const API_BASE = '/api';

export const api = {
  async getScanStatus(): Promise<OrchestratorState> {
    const res = await fetch(`${API_BASE}/scan/status`);
    if (!res.ok) throw new Error('Failed to fetch scan status');
    return res.json();
  },

  async startScan(targetUrl = 'http://127.0.0.1:8000'): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: targetUrl }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to start scan' }));
      throw new Error(err.detail || 'Failed to start scan');
    }
    return res.json();
  },

  async getGraph(): Promise<GraphData> {
    const res = await fetch(`${API_BASE}/graph`);
    if (!res.ok) throw new Error('Failed to fetch knowledge graph');
    return res.json();
  },

  async getInventory(): Promise<InventoryData> {
    const res = await fetch(`${API_BASE}/inventory`);
    if (!res.ok) throw new Error('Failed to fetch inventory');
    return res.json();
  },

  async getFindings(): Promise<VulnerabilityFinding[]> {
    const res = await fetch(`${API_BASE}/findings`);
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async getFinding(findingId: string): Promise<VulnerabilityFinding> {
    const res = await fetch(`${API_BASE}/findings/${findingId}`);
    if (!res.ok) throw new Error('Failed to fetch finding details');
    return res.json();
  },

  async triggerRetest(findingId?: string): Promise<unknown[]> {
    const res = await fetch(`${API_BASE}/retest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: findingId }),
    });
    if (!res.ok) throw new Error('Failed to trigger retest');
    return res.json();
  },

  async getApprovals(): Promise<ApprovalRequest[]> {
    const res = await fetch(`${API_BASE}/approvals`);
    if (!res.ok) throw new Error('Failed to fetch approvals');
    return res.json();
  },

  async approveRequest(requestId: string, operatorId = 'human_lead'): Promise<{ status: string; approval_token: string }> {
    const res = await fetch(`${API_BASE}/approvals/${requestId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ operator_id: operatorId }),
    });
    if (!res.ok) throw new Error('Failed to approve request');
    return res.json();
  },

  async rejectRequest(requestId: string, reason = 'Operator rejected'): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/approvals/${requestId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) throw new Error('Failed to reject request');
    return res.json();
  },

  async getSafety(): Promise<{
    kill_switch_active: boolean;
    scope_allowlist: string[];
    pending_approvals: ApprovalRequest[];
    rate_limits: { rpm: number; concurrency: number };
  }> {
    const res = await fetch(`${API_BASE}/safety`);
    if (!res.ok) throw new Error('Failed to fetch safety status');
    return res.json();
  },

  async triggerKill(reason = 'Operator emergency stop'): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/safety/kill?reason=${encodeURIComponent(reason)}`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to activate kill switch');
    return res.json();
  },

  async disarmKill(): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/safety/disarm`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to disarm kill switch');
    return res.json();
  },

  async downloadOpenAPISpec(): Promise<void> {
    const res = await fetch(`${API_BASE}/spec/openapi.json`);
    if (!res.ok) throw new Error('Failed to download OpenAPI spec');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'tripwire_synthesized_openapi.json';
    a.click();
    window.URL.revokeObjectURL(url);
  },
};

