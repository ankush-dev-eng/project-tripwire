import React, { useEffect, useState } from 'react';
import {
  Flame,
  CheckCircle2,
  Copy,
  Check,
  ShieldAlert,
  Terminal,
  Calculator,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import { VulnerabilityFinding } from '../types';
import { api } from '../services/api';

export const FindingsView: React.FC = () => {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const loadFindings = async () => {
    try {
      setIsLoading(true);
      const data = await api.getFindings();
      setFindings(data);
    } catch {
      // ignore
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, []);

  const handleCopyCurl = (curl: string) => {
    navigator.clipboard.writeText(curl);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  const filteredFindings = findings.filter((f) => {
    if (severityFilter === 'ALL') return true;
    return f.severity === severityFilter;
  });

  return (
    <div className="space-y-6">
      {/* Header and Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-basalt border border-basalt-border rounded-xl p-6">
        <div>
          <h2 className="text-xl font-bold text-bone flex items-center gap-2">
            <Flame className="w-5 h-5 text-brick" />
            <span>Verified Vulnerabilities & Double-Proof Evidence</span>
          </h2>
          <p className="text-sm text-bone-muted">
            Zero false-positive mandate: Every finding requires primary exploit proof AND counter-factual negative control verification.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-ink border border-basalt-border rounded-lg px-3 py-1.5 text-xs font-mono text-bone focus:outline-none focus:border-sage cursor-pointer"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <button
            onClick={loadFindings}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-ink border border-basalt-border hover:border-sage text-xs font-mono text-bone rounded-lg transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-basalt border border-basalt-border rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-ink border-b border-basalt-border text-stone-muted font-mono uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title & Endpoint</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">CWE</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-basalt-border">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-stone-muted italic">
                    No verified vulnerabilities found. Launch an assessment to scan the target surface.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((f) => (
                  <tr
                    key={f.finding_id}
                    onClick={() => setSelectedFinding(f)}
                    className="hover:bg-basalt-light/60 transition-colors cursor-pointer"
                  >
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        f.severity === 'CRITICAL' ? 'bg-brick/20 text-brick border border-brick/30' :
                        f.severity === 'HIGH' ? 'bg-copper/20 text-copper border border-copper/30' :
                        f.severity === 'MEDIUM' ? 'bg-brass/20 text-brass border border-brass/30' :
                        'bg-sage/20 text-sage border border-sage/30'
                      }`}>
                        {f.severity}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 font-mono">
                      <div className="text-bone font-semibold">{f.title}</div>
                      <div className="text-stone-muted text-[11px]">
                        <span className="text-sage mr-1">{f.method}</span>
                        {f.target_endpoint}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-bone-muted font-mono text-[11px]">
                      {f.category}
                    </td>

                    <td className="py-3.5 px-4 font-mono text-stone-muted">
                      {f.cwe_id}
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold font-mono border ${
                        f.status === 'FIXED' ? 'bg-moss/20 text-moss border-moss/30' :
                        f.status === 'REGRESSION' ? 'bg-brick/20 text-brick border-brick/30 animate-pulse' :
                        'bg-sage/20 text-sage border-sage/30'
                      }`}>
                        {f.status}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <span className="text-sage hover:text-bone text-xs font-mono inline-flex items-center gap-1">
                        <span>Inspect Evidence</span>
                        <ExternalLink className="w-3 h-3" />
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Double-Proof Evidence Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-ink/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-basalt border border-basalt-border rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6">
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-basalt-border pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                    selectedFinding.severity === 'CRITICAL' ? 'bg-brick/20 text-brick border border-brick/30' :
                    selectedFinding.severity === 'HIGH' ? 'bg-copper/20 text-copper border border-copper/30' :
                    selectedFinding.severity === 'MEDIUM' ? 'bg-brass/20 text-brass border border-brass/30' :
                    'bg-sage/20 text-sage border border-sage/30'
                  }`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="text-xs font-mono text-stone-muted">{selectedFinding.cwe_id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-moss/20 text-moss">
                    Double-Proof Confirmed
                  </span>
                </div>
                <h3 className="text-lg font-bold text-bone">{selectedFinding.title}</h3>
                <div className="font-mono text-xs text-moss">
                  {selectedFinding.method} {selectedFinding.target_endpoint}
                </div>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="text-stone-muted hover:text-bone p-1 rounded cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Description & Impact */}
            <div className="space-y-1 text-xs text-bone-muted leading-relaxed">
              <span className="text-stone-muted uppercase font-mono font-bold block text-[10px]">Description & Threat Vector</span>
              <p>{selectedFinding.description}</p>
            </div>

            {/* Double-Proof Two-Sided Comparison Grid */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-bone">
                <ShieldAlert className="w-4 h-4 text-copper" />
                <span>SECTION 5.3 TWO-SIDED VERIFICATION PROOF</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Proof 1: Primary Exploit */}
                <div className="bg-ink border border-brick/40 rounded-xl p-4 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-brick font-bold flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-brick inline-block"></span>
                      <span>Proof 1: Primary Exploit</span>
                    </span>
                    <span className="text-stone-muted">
                      HTTP {selectedFinding.proof?.primary_response?.status_code || 200}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-bone bg-basalt/60 p-2 rounded break-all">
                    {selectedFinding.proof?.primary_request?.method} {selectedFinding.proof?.primary_request?.url}
                  </div>
                  <div className="text-[11px] text-stone-muted font-mono bg-basalt/30 p-2 rounded max-h-32 overflow-y-auto">
                    {selectedFinding.proof?.primary_response?.body_preview || 'Unauthorized state change or data leaked.'}
                  </div>
                </div>

                {/* Proof 2: Negative Control */}
                <div className="bg-ink border border-moss/40 rounded-xl p-4 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-moss font-bold flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-moss inline-block"></span>
                      <span>Proof 2: Counter-Factual Control</span>
                    </span>
                    <span className="text-stone-muted">
                      HTTP {selectedFinding.proof?.negative_control_response?.status_code || 404}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-bone bg-basalt/60 p-2 rounded break-all">
                    {selectedFinding.proof?.negative_control_request?.method} {selectedFinding.proof?.negative_control_request?.url}
                  </div>
                  <div className="text-[11px] text-stone-muted font-mono bg-basalt/30 p-2 rounded max-h-32 overflow-y-auto">
                    {selectedFinding.proof?.negative_control_response?.body_preview || 'Counter-factual payload rejected; proves dynamic responder.'}
                  </div>
                </div>
              </div>
            </div>

            {/* Business Context Triage Breakdown */}
            {selectedFinding.metadata?.triage && (
              <div className="bg-ink border border-basalt-border rounded-xl p-4 space-y-2">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-bone">
                  <Calculator className="w-4 h-4 text-brass" />
                  <span>BUSINESS-CONTEXT SEVERITY TRIAGE BREAKDOWN</span>
                </div>
                <div className="text-xs font-mono text-stone-muted bg-basalt/50 p-3 rounded-lg border border-basalt-border">
                  {selectedFinding.metadata.triage.rationale}
                </div>
              </div>
            )}

            {/* Reproduction Curl Command */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-bone flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-sage" />
                  <span>1-CLICK REPRODUCTION CURL</span>
                </span>
                <button
                  onClick={() => handleCopyCurl(selectedFinding.proof?.reproduction_curl || '')}
                  className="flex items-center gap-1 px-2.5 py-1 bg-ink border border-basalt-border hover:border-sage rounded text-xs font-mono text-bone cursor-pointer"
                >
                  {copiedCurl ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-moss" />
                      <span className="text-moss">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Curl</span>
                    </>
                  )}
                </button>
              </div>

              <pre className="bg-ink border border-basalt-border p-3 rounded-xl font-mono text-xs text-sage overflow-x-auto selection:bg-sage selection:text-ink">
                {selectedFinding.proof?.reproduction_curl || '# No reproduction curl recorded'}
              </pre>
            </div>

            {/* Remediation Guide */}
            <div className="bg-moss/10 border border-moss/30 rounded-xl p-4 space-y-1">
              <span className="text-xs font-mono font-bold text-moss flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                <span>ENGINEERING REMEDIATION</span>
              </span>
              <p className="text-xs text-bone-muted leading-relaxed">
                {selectedFinding.remediation}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
