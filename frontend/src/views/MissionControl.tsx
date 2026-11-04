import React, { useState } from 'react';
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Shield,
  Layers,
  Activity,
  Terminal,
} from 'lucide-react';
import { OrchestratorState, WebSocketEvent } from '../types';
import { api } from '../services/api';

interface MissionControlProps {
  state: OrchestratorState | null;
  events: WebSocketEvent[];
  onRefresh: () => void;
}

export const MissionControl: React.FC<MissionControlProps> = ({ state, events, onRefresh }) => {
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8000');
  const [isStarting, setIsStarting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const isScanning = state?.status && !['IDLE', 'COMPLETED', 'ERROR'].includes(state.status);

  const handleStartScan = async () => {
    try {
      setIsStarting(true);
      setErrorMsg(null);
      await api.startScan(targetUrl);
      onRefresh();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg('Failed to start scan');
      }
    } finally {
      setIsStarting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Target Launch & Status Banner */}
      <div className="bg-basalt border border-basalt-border rounded-xl p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="flex h-3 w-3 relative">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${isScanning ? 'bg-copper' : 'bg-moss'} opacity-75`}></span>
                <span className={`relative inline-flex rounded-full h-3 w-3 ${isScanning ? 'bg-copper' : 'bg-moss'}`}></span>
              </span>
              <h2 className="text-xl font-bold tracking-tight text-bone">Autonomous DAST Engine</h2>
              <span className={`px-2.5 py-0.5 text-xs font-mono font-semibold rounded-full border ${
                isScanning ? 'bg-copper/20 text-copper border-copper/30' : 'bg-moss/20 text-moss border-moss/30'
              }`}>
                {state?.status || 'IDLE'}
              </span>
            </div>
            <p className="text-sm text-bone-muted">
              Continuous agentic surface reconnaissance, shadow API discovery, and double-proof verification.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 sm:w-80">
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isScanning}
                placeholder="Target URL (e.g. http://127.0.0.1:8000)"
                className="w-full bg-ink border border-basalt-border rounded-lg px-3.5 py-2 text-sm font-mono text-bone placeholder-stone-muted focus:outline-none focus:border-sage disabled:opacity-50"
              />
            </div>
            <button
              onClick={handleStartScan}
              disabled={isScanning || isStarting || state?.kill_switch_active}
              className={`flex items-center gap-2 px-5 py-2 rounded-lg font-medium text-sm transition-all shadow-md ${
                isScanning || state?.kill_switch_active
                  ? 'bg-basalt-light text-stone-muted cursor-not-allowed border border-basalt-border'
                  : 'bg-moss hover:bg-moss-light text-bone hover:shadow-moss/20 cursor-pointer'
              }`}
            >
              {isScanning ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Scanning Surface...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Launch Assessment</span>
                </>
              )}
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="mt-4 p-3 bg-brick/10 border border-brick/30 rounded-lg flex items-center gap-2 text-brick text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Scan Progress Bar */}
        {isScanning && (
          <div className="mt-6 space-y-2">
            <div className="flex justify-between text-xs text-bone-muted font-mono">
              <span>{state?.current_step || 'Initializing scan...'}</span>
              <span>{state?.progress || 0}%</span>
            </div>
            <div className="w-full bg-ink rounded-full h-2.5 overflow-hidden border border-basalt-border">
              <div
                className="bg-gradient-to-r from-sage to-moss h-full rounded-full transition-all duration-500 ease-out"
                style={{ width: `${state?.progress || 5}%` }}
              ></div>
            </div>
          </div>
        )}
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Endpoints */}
        <div className="bg-basalt border border-basalt-border rounded-xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-stone-muted text-xs font-mono uppercase tracking-wider">
            <span>Discovered Endpoints</span>
            <Layers className="w-4 h-4 text-sage" />
          </div>
          <div className="text-3xl font-bold font-mono text-bone">
            {state?.endpoints_count || 0}
          </div>
          <div className="text-xs text-bone-muted flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-sage inline-block"></span>
            <span>Mapped in Knowledge Graph</span>
          </div>
        </div>

        {/* API Inventory Breakdown */}
        <div className="bg-basalt border border-basalt-border rounded-xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-stone-muted text-xs font-mono uppercase tracking-wider">
            <span>Inventory Classification</span>
            <Activity className="w-4 h-4 text-brass" />
          </div>
          <div className="flex items-baseline gap-3">
            <span className="text-xl font-bold font-mono text-copper">
              {state?.pending_approvals_count ?? 0}
            </span>
            <span className="text-xs text-bone-muted">Guarded Actions</span>
          </div>
          <div className="text-xs text-bone-muted flex gap-2">
            <span className="text-moss">Active</span> • <span className="text-brass">Zombie</span> • <span className="text-copper">Shadow</span>
          </div>
        </div>

        {/* Verified Findings */}
        <div className="bg-basalt border border-basalt-border rounded-xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-stone-muted text-xs font-mono uppercase tracking-wider">
            <span>Verified Vulnerabilities</span>
            <Flame className="w-4 h-4 text-brick" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-brick">
              {state?.severity_breakdown?.CRITICAL || 0}
            </span>
            <span className="text-xs font-mono text-copper">
              +{state?.severity_breakdown?.HIGH || 0} High
            </span>
            <span className="text-xs font-mono text-stone-muted">
              ({state?.findings_count || 0} total)
            </span>
          </div>
          <div className="text-xs text-bone-muted flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-moss" />
            <span>100% Double-Proof Verified</span>
          </div>
        </div>

        {/* Safety Gate Status */}
        <div className="bg-basalt border border-basalt-border rounded-xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-stone-muted text-xs font-mono uppercase tracking-wider">
            <span>Safety Isolation</span>
            <Shield className={`w-4 h-4 ${state?.kill_switch_active ? 'text-brick' : 'text-moss'}`} />
          </div>
          <div className="text-lg font-bold font-mono">
            {state?.kill_switch_active ? (
              <span className="text-brick animate-pulse">KILL SWITCH ACTIVE</span>
            ) : (
              <span className="text-moss">ARMED & PROTECTED</span>
            )}
          </div>
          <div className="text-xs text-bone-muted">
            Strict Egress • SafeHttpClient AST Locked
          </div>
        </div>
      </div>

      {/* Real-time Terminal Log Console */}
      <div className="bg-ink border border-basalt-border rounded-xl overflow-hidden shadow-2xl">
        <div className="bg-basalt px-4 py-3 border-b border-basalt-border flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-bone-muted">
            <Terminal className="w-4 h-4 text-sage" />
            <span className="font-semibold text-bone">LIVE TELEMETRY STREAM</span>
            <span>(WebSocket Duplex)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-moss animate-pulse"></span>
            <span className="text-xs font-mono text-moss">CONNECTED</span>
          </div>
        </div>

        <div className="p-4 font-mono text-xs space-y-1.5 h-72 overflow-y-auto">
          {events.length === 0 ? (
            <div className="text-stone-muted italic py-8 text-center">
              Listening on real-time event stream... Launch assessment to stream telemetry.
            </div>
          ) : (
            events.map((ev, idx) => (
              <div key={idx} className="flex items-start gap-3 py-0.5 hover:bg-basalt/40 px-2 rounded">
                <span className="text-stone-muted shrink-0 text-[10px]">
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
                <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0 ${
                  ev.type.includes('FINDING') ? 'bg-brick/20 text-brick' :
                  ev.type.includes('APPROVAL') ? 'bg-brass/20 text-brass' :
                  ev.type.includes('INVENTORY') ? 'bg-copper/20 text-copper' :
                  'bg-sage/20 text-sage'
                }`}>
                  {ev.type}
                </span>
                <span className="text-bone-muted truncate">
                  {typeof ev.data === 'object' ? JSON.stringify(ev.data) : String(ev.data)}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
