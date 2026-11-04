import React, { useEffect, useState } from 'react';
import { RotateCcw, History, ArrowRight } from 'lucide-react';
import { VulnerabilityFinding } from '../types';
import { api } from '../services/api';

export const RetestHistoryView: React.FC = () => {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [isRetesting, setIsRetesting] = useState(false);
  const [retestResults, setRetestResults] = useState<Array<{
    finding_id: string;
    target_endpoint: string;
    method: string;
    previous_status: string;
    new_status: string;
    is_fixed: boolean;
    status_code: number;
    rationale: string;
    retested_at: string;
  }>>([]);

  const loadData = async () => {
    try {
      const data = await api.getFindings();
      setFindings(data);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRetestAll = async () => {
    try {
      setIsRetesting(true);
      const res = (await api.triggerRetest()) as typeof retestResults;
      setRetestResults(res);
      await loadData();
    } catch {
      // ignore
    } finally {
      setIsRetesting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-basalt border border-basalt-border rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-bone flex items-center gap-2">
            <RotateCcw className="w-5 h-5 text-moss" />
            <span>Automated Regression & Retest Engine</span>
          </h2>
          <p className="text-sm text-bone-muted">
            Replays verifiable Double-Proof reproduction vectors against target services to verify patch efficacy and alert on regressions.
          </p>
        </div>

        <button
          onClick={handleRetestAll}
          disabled={isRetesting || findings.length === 0}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-mono text-xs font-bold transition-all shadow-md cursor-pointer ${
            isRetesting || findings.length === 0
              ? 'bg-basalt-light text-stone-muted cursor-not-allowed border border-basalt-border'
              : 'bg-moss hover:bg-moss-light text-bone shadow-moss/20'
          }`}
        >
          <RotateCcw className={`w-4 h-4 ${isRetesting ? 'animate-spin' : ''}`} />
          <span>{isRetesting ? 'Replaying Vectors...' : `Retest All Flaws (${findings.length})`}</span>
        </button>
      </div>

      {/* Retest Execution Summary Table */}
      <div className="bg-basalt border border-basalt-border rounded-xl overflow-hidden shadow-xl">
        <div className="bg-ink px-4 py-3 border-b border-basalt-border flex items-center justify-between text-xs font-mono text-stone-muted">
          <span className="font-semibold text-bone flex items-center gap-2">
            <History className="w-4 h-4 text-sage" />
            <span>RETEST REPLAY LOG & LIFECYCLE TRANSITIONS</span>
          </span>
          <span>{retestResults.length} vectors re-evaluated</span>
        </div>

        <div className="divide-y divide-basalt-border">
          {retestResults.length === 0 ? (
            <div className="py-16 text-center space-y-2 text-stone-muted">
              <RotateCcw className="w-8 h-8 mx-auto opacity-40" />
              <div className="text-xs font-mono">No recent retest runs executed in this session.</div>
              <p className="text-xs text-bone-muted max-w-sm mx-auto font-sans">
                Click "Retest All Flaws" above to verify active patches against Voyager lab services.
              </p>
            </div>
          ) : (
            retestResults.map((res, idx) => (
              <div key={idx} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono hover:bg-basalt-light/40 transition-colors">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      res.is_fixed ? 'bg-moss/20 text-moss border border-moss/30' : 'bg-brick/20 text-brick border border-brick/30'
                    }`}>
                      {res.is_fixed ? 'PATCH VERIFIED (FIXED)' : 'STILL VULNERABLE'}
                    </span>
                    <span className="text-stone-muted">HTTP {res.status_code}</span>
                  </div>
                  <div className="text-bone font-semibold">
                    <span className="text-sage mr-2">{res.method}</span>
                    <span>{res.target_endpoint}</span>
                  </div>
                  <div className="text-stone-muted text-[11px] font-sans">
                    {res.rationale}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="flex items-center gap-1.5 bg-ink px-3 py-1.5 rounded-lg border border-basalt-border text-xs">
                    <span className="text-stone-muted">{res.previous_status}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-sage" />
                    <span className={res.is_fixed ? 'text-moss font-bold' : 'text-brick font-bold'}>
                      {res.new_status}
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
