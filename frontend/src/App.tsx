import React, { useEffect, useState } from 'react';
import {
  Shield,
  Activity,
  Layers,
  Flame,
  UserCheck,
  RotateCcw,
  AlertOctagon,
  Radio,
  FileCode,
} from 'lucide-react';
import { MissionControl } from './views/MissionControl';
import { KnowledgeGraphView } from './views/KnowledgeGraphView';
import { ApiInventoryView } from './views/ApiInventoryView';
import { FindingsView } from './views/FindingsView';
import { SafetyConsoleView } from './views/SafetyConsoleView';
import { ApprovalsQueueView } from './views/ApprovalsQueueView';
import { RetestHistoryView } from './views/RetestHistoryView';
import { OrchestratorState } from './types';
import { useWebSocket } from './hooks/useWebSocket';
import { api } from './services/api';

type TabView = 'mission' | 'graph' | 'inventory' | 'findings' | 'safety' | 'approvals' | 'retest';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<TabView>('mission');
  const [state, setState] = useState<OrchestratorState | null>(null);

  const refreshState = async () => {
    try {
      const s = await api.getScanStatus();
      setState(s);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    refreshState();
    const interval = setInterval(refreshState, 5000);
    return () => clearInterval(interval);
  }, []);

  const { isConnected, events } = useWebSocket({
    onStateUpdate: (updatedState) => setState(updatedState),
  });

  return (
    <div className="min-h-screen flex flex-col bg-ink text-bone font-sans">
      {/* Kill Switch Top Banner if active */}
      {state?.kill_switch_active && (
        <div className="bg-brick px-4 py-2 text-center text-xs font-mono font-bold text-bone flex items-center justify-center gap-2 animate-pulse sticky top-0 z-50 shadow-lg">
          <AlertOctagon className="w-4 h-4" />
          <span>EMERGENCY KILL SWITCH ACTIVE — ALL OUTBOUND EGRESS IS CURRENTLY HALTED</span>
        </div>
      )}

      {/* Main Top Header */}
      <header className="bg-basalt border-b border-basalt-border px-6 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4 sticky top-0 z-40">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-moss/20 border border-moss/40 flex items-center justify-center text-moss shadow-inner">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold font-mono tracking-tight text-bone">PROJECT TRIPWIRE</h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-moss/20 text-moss border border-moss/30 rounded">
                v1.0.0
              </span>
            </div>
            <p className="text-xs text-bone-muted">
              Agentic Real-Time DAST for B2B Travel Platforms • TBO Hackathon 2026
            </p>
          </div>
        </div>

        {/* Live System Status Badges */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2 bg-ink px-3 py-1.5 rounded-lg border border-basalt-border">
            <Radio className={`w-3.5 h-3.5 ${isConnected ? 'text-moss animate-pulse' : 'text-stone-muted'}`} />
            <span className="text-stone-muted">WS:</span>
            <span className={isConnected ? 'text-moss font-bold' : 'text-brick'}>
              {isConnected ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>

          <div className="flex items-center gap-2 bg-ink px-3 py-1.5 rounded-lg border border-basalt-border">
            <span className="text-stone-muted">Engine:</span>
            <span className="text-bone font-bold">{state?.status || 'IDLE'}</span>
          </div>
        </div>
      </header>

      {/* Navigation Sub-header */}
      <nav className="bg-basalt/80 backdrop-blur-md border-b border-basalt-border px-6 py-2 overflow-x-auto">
        <div className="flex items-center gap-1.5 min-w-max">
          <button
            onClick={() => setCurrentView('mission')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              currentView === 'mission'
                ? 'bg-moss/20 text-bone font-bold border border-moss/30'
                : 'text-stone-muted hover:text-bone hover:bg-basalt-light/50'
            }`}
          >
            <Activity className="w-4 h-4 text-sage" />
            <span>Mission Control</span>
          </button>

          <button
            onClick={() => setCurrentView('graph')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              currentView === 'graph'
                ? 'bg-moss/20 text-bone font-bold border border-moss/30'
                : 'text-stone-muted hover:text-bone hover:bg-basalt-light/50'
            }`}
          >
            <Layers className="w-4 h-4 text-moss" />
            <span>Knowledge Graph</span>
          </button>

          <button
            onClick={() => setCurrentView('inventory')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              currentView === 'inventory'
                ? 'bg-moss/20 text-bone font-bold border border-moss/30'
                : 'text-stone-muted hover:text-bone hover:bg-basalt-light/50'
            }`}
          >
            <FileCode className="w-4 h-4 text-brass" />
            <span>API Inventory</span>
          </button>

          <button
            onClick={() => setCurrentView('findings')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              currentView === 'findings'
                ? 'bg-moss/20 text-bone font-bold border border-moss/30'
                : 'text-stone-muted hover:text-bone hover:bg-basalt-light/50'
            }`}
          >
            <Flame className="w-4 h-4 text-brick" />
            <span>Findings & Evidence</span>
            {(state?.findings_count ?? 0) > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-brick text-bone font-mono font-bold">
                {state?.findings_count}
              </span>
            )}
          </button>

          <button
            onClick={() => setCurrentView('safety')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              currentView === 'safety'
                ? 'bg-moss/20 text-bone font-bold border border-moss/30'
                : 'text-stone-muted hover:text-bone hover:bg-basalt-light/50'
            }`}
          >
            <Shield className="w-4 h-4 text-moss" />
            <span>Safety Console</span>
          </button>

          <button
            onClick={() => setCurrentView('approvals')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              currentView === 'approvals'
                ? 'bg-moss/20 text-bone font-bold border border-moss/30'
                : 'text-stone-muted hover:text-bone hover:bg-basalt-light/50'
            }`}
          >
            <UserCheck className="w-4 h-4 text-copper" />
            <span>Approvals Queue</span>
            {(state?.pending_approvals_count ?? 0) > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-copper text-bone font-mono font-bold animate-pulse">
                {state?.pending_approvals_count}
              </span>
            )}
          </button>

          <button
            onClick={() => setCurrentView('retest')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              currentView === 'retest'
                ? 'bg-moss/20 text-bone font-bold border border-moss/30'
                : 'text-stone-muted hover:text-bone hover:bg-basalt-light/50'
            }`}
          >
            <RotateCcw className="w-4 h-4 text-sage" />
            <span>Retest History</span>
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
        {currentView === 'mission' && (
          <MissionControl state={state} events={events} onRefresh={refreshState} />
        )}
        {currentView === 'graph' && <KnowledgeGraphView />}
        {currentView === 'inventory' && <ApiInventoryView />}
        {currentView === 'findings' && <FindingsView />}
        {currentView === 'safety' && <SafetyConsoleView />}
        {currentView === 'approvals' && <ApprovalsQueueView />}
        {currentView === 'retest' && <RetestHistoryView />}
      </main>

      {/* Footer */}
      <footer className="bg-basalt border-t border-basalt-border px-6 py-4 text-center text-xs font-mono text-stone-muted flex flex-col sm:flex-row items-center justify-between gap-2">
        <div>
          PROJECT TRIPWIRE • Built for TBO Security Hackathon 2026
        </div>
        <div className="flex items-center gap-3">
          <span>Target: Voyager Travel Lab</span>
          <span>•</span>
          <span>Zero False-Positive Engine</span>
          <span>•</span>
          <span className="text-moss">SafeHttpClient Locked</span>
        </div>
      </footer>
    </div>
  );
};

