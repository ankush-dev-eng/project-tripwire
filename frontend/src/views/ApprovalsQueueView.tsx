import React, { useEffect, useState } from 'react';
import { UserCheck, ShieldCheck, XCircle, CheckCircle2, Clock, RefreshCw } from 'lucide-react';
import { ApprovalRequest } from '../types';
import { api } from '../services/api';

export const ApprovalsQueueView: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [actingId, setActingId] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<{ id: string; msg: string; success: boolean } | null>(null);

  const loadApprovals = async () => {
    try {
      setIsLoading(true);
      const data = await api.getApprovals();
      setApprovals(data);
    } catch {
      // ignore
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
  }, []);

  const handleApprove = async (id: string) => {
    try {
      setActingId(id);
      const res = await api.approveRequest(id, 'lead_operator');
      setStatusMsg({
        id,
        msg: `Approved successfully. Auth token: ${res.approval_token.substring(0, 16)}...`,
        success: true,
      });
      await loadApprovals();
    } catch {
      setStatusMsg({ id, msg: 'Approval failed', success: false });
    } finally {
      setActingId(null);
    }
  };

  const handleReject = async (id: string) => {
    try {
      setActingId(id);
      await api.rejectRequest(id, 'Operator rejected from UI');
      setStatusMsg({ id, msg: 'Request rejected', success: false });
      await loadApprovals();
    } catch {
      // ignore
    } finally {
      setActingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-basalt border border-basalt-border rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-bone flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-copper" />
            <span>Human-in-the-Loop Approvals Queue</span>
          </h2>
          <p className="text-sm text-bone-muted">
            State-changing, disruptive, or dangerous probe vectors pause automatically until authorized by a human operator.
          </p>
        </div>

        <button
          onClick={loadApprovals}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-ink border border-basalt-border hover:border-sage text-xs font-mono text-bone rounded-lg transition-colors cursor-pointer self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {statusMsg && (
        <div className={`p-4 rounded-xl border text-xs font-mono flex items-center justify-between ${
          statusMsg.success ? 'bg-moss/10 border-moss/30 text-moss' : 'bg-brick/10 border-brick/30 text-brick'
        }`}>
          <span>{statusMsg.msg}</span>
          <button onClick={() => setStatusMsg(null)} className="cursor-pointer">✕</button>
        </div>
      )}

      <div className="bg-basalt border border-basalt-border rounded-xl overflow-hidden shadow-xl">
        {approvals.length === 0 ? (
          <div className="py-16 text-center space-y-3">
            <ShieldCheck className="w-10 h-10 text-moss mx-auto opacity-70" />
            <div className="text-bone font-semibold text-sm">Queue is Clean</div>
            <p className="text-stone-muted text-xs max-w-sm mx-auto">
              No pending approval requests. All agent probes are executing within autonomous safety boundaries.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-basalt-border">
            {approvals.map((req) => (
              <div key={req.id} className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4 hover:bg-basalt-light/40 transition-colors">
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-copper/20 text-copper border border-copper/30">
                      {req.action_type.toUpperCase()}
                    </span>
                    <span className="text-stone-muted flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      <span>{new Date(req.requested_at * 1000).toLocaleTimeString()}</span>
                    </span>
                  </div>
                  <div className="text-sm font-bold text-bone">
                    <span className="text-moss mr-2">{req.method}</span>
                    <span>{req.path}</span>
                  </div>
                  <div className="text-stone-muted text-xs font-sans">
                    {req.description}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleReject(req.id)}
                    disabled={actingId === req.id}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 bg-ink hover:bg-brick/20 border border-basalt-border hover:border-brick/40 text-brick text-xs font-mono font-medium rounded-lg transition-colors cursor-pointer"
                  >
                    <XCircle className="w-4 h-4" />
                    <span>Reject</span>
                  </button>

                  <button
                    onClick={() => handleApprove(req.id)}
                    disabled={actingId === req.id}
                    className="flex items-center gap-1.5 px-4 py-1.5 bg-moss hover:bg-moss-light text-bone text-xs font-mono font-bold rounded-lg transition-colors shadow-md hover:shadow-moss/20 cursor-pointer"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Authorize Probe</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

