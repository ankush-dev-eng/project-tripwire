import React, { useEffect, useState } from 'react';
import { Shield, AlertOctagon, Lock, Activity, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

export const SafetyConsoleView: React.FC = () => {
  const [safety, setSafety] = useState<{
    kill_switch_active: boolean;
    scope_allowlist: string[];
    rate_limits: { rpm: number; concurrency: number };
  } | null>(null);
  const [isActing, setIsActing] = useState(false);
  const [killReason, setKillReason] = useState('Manual emergency stop via UI Console');

  const loadSafety = async () => {
    try {
      const data = await api.getSafety();
      setSafety(data);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadSafety();
  }, []);

  const handleToggleKill = async () => {
    try {
      setIsActing(true);
      if (safety?.kill_switch_active) {
        await api.disarmKill();
      } else {
        await api.triggerKill(killReason);
      }
      await loadSafety();
    } catch {
      // ignore
    } finally {
      setIsActing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-basalt border border-basalt-border rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-bone flex items-center gap-2">
            <Shield className="w-5 h-5 text-moss" />
            <span>Safety Isolation & Egress Controller</span>
          </h2>
          <p className="text-sm text-bone-muted">
            All outbound network requests traverse the unified SafeHttpClient. AST linter guarantees strict egress boundaries.
          </p>
        </div>

        <button
          onClick={loadSafety}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-ink border border-basalt-border hover:border-sage text-xs font-mono text-bone rounded-lg transition-colors cursor-pointer self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Kill Switch Card */}
        <div className={`col-span-1 lg:col-span-2 rounded-xl p-6 border shadow-xl flex flex-col justify-between gap-6 transition-all ${
          safety?.kill_switch_active
            ? 'bg-brick/10 border-brick/40 shadow-brick/10'
            : 'bg-basalt border-basalt-border'
        }`}>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase font-bold tracking-wider text-stone-muted">
                EMERGENCY KILL SWITCH
              </span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                safety?.kill_switch_active ? 'bg-brick text-bone animate-pulse' : 'bg-moss/20 text-moss'
              }`}>
                {safety?.kill_switch_active ? 'TRIPPED & PAUSED' : 'DISARMED & HEALTHY'}
              </span>
            </div>

            <p className="text-sm text-bone-muted leading-relaxed">
              When tripped, the atomic global kill switch immediately halts all running agents, terminates ongoing HTTP probes,
              and writes an immutable trigger signal to disk (`.tripwire_kill`).
            </p>

            {!safety?.kill_switch_active && (
              <div className="pt-2">
                <input
                  type="text"
                  value={killReason}
                  onChange={(e) => setKillReason(e.target.value)}
                  placeholder="Reason for triggering kill switch"
                  className="w-full bg-ink border border-basalt-border rounded-lg px-3 py-2 text-xs font-mono text-bone placeholder-stone-muted focus:outline-none focus:border-brick"
                />
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-basalt-border/50">
            <button
              onClick={handleToggleKill}
              disabled={isActing}
              className={`w-full py-3 px-4 rounded-xl font-bold font-mono text-sm flex items-center justify-center gap-2 transition-all cursor-pointer ${
                safety?.kill_switch_active
                  ? 'bg-moss hover:bg-moss-light text-bone shadow-lg shadow-moss/20'
                  : 'bg-brick hover:bg-brick-light text-bone shadow-lg shadow-brick/20'
              }`}
            >
              <AlertOctagon className="w-5 h-5" />
              <span>
                {safety?.kill_switch_active
                  ? 'DISARM KILL SWITCH & RESUME NORMAL OPERATIONS'
                  : 'TRIGGER EMERGENCY GLOBAL KILL SWITCH'}
              </span>
            </button>
          </div>
        </div>

        {/* Scope Allowlist & Rate Limits Card */}
        <div className="space-y-6">
          {/* Scope Boundaries */}
          <div className="bg-basalt border border-basalt-border rounded-xl p-5 shadow-xl space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-bone">
              <Lock className="w-4 h-4 text-copper" />
              <span>IMMUTABLE SCOPE ALLOWLIST</span>
            </div>
            <p className="text-xs text-bone-muted">
              Defined in `scope.yaml` and verified at runtime before DNS resolution.
            </p>
            <div className="bg-ink p-3 rounded-lg font-mono text-xs space-y-1 border border-basalt-border text-moss">
              {(safety?.scope_allowlist || ['127.0.0.1', 'localhost', '127.0.0.1:8000']).map((item, idx) => (
                <div key={idx} className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-moss"></span>
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Rate Limiting */}
          <div className="bg-basalt border border-basalt-border rounded-xl p-5 shadow-xl space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-bone">
              <Activity className="w-4 h-4 text-brass" />
              <span>TOKEN BUCKET RATE LIMITER</span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between text-stone-muted">
                <span>Max Requests / Minute</span>
                <span className="text-bone font-bold">{safety?.rate_limits?.rpm || 300} RPM</span>
              </div>
              <div className="flex justify-between text-stone-muted">
                <span>Max Concurrency</span>
                <span className="text-bone font-bold">{safety?.rate_limits?.concurrency || 5} concurrent</span>
              </div>
              <div className="flex justify-between text-stone-muted">
                <span>Target Strain Multiplier</span>
                <span className="text-moss font-bold">1.0x (Normal)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
