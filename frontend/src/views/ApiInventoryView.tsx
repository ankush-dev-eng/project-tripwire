import React, { useEffect, useState } from 'react';
import { Download, Search, CheckCircle2, Ghost, ShieldAlert } from 'lucide-react';
import { InventoryData, InventoryItem } from '../types';
import { api } from '../services/api';

export const ApiInventoryView: React.FC = () => {
  const [inventory, setInventory] = useState<InventoryData | null>(null);
  const [activeTab, setActiveTab] = useState<'all' | 'active' | 'zombie' | 'shadow'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isExporting, setIsExporting] = useState(false);

  useEffect(() => {
    api.getInventory().then(setInventory).catch(() => {});
  }, []);

  const handleExport = async () => {
    try {
      setIsExporting(true);
      await api.downloadOpenAPISpec();
    } catch {
      // ignore
    } finally {
      setIsExporting(false);
    }
  };

  const getFilteredItems = (): InventoryItem[] => {
    if (!inventory) return [];
    let items: InventoryItem[] = [];

    if (activeTab === 'all') {
      items = [...inventory.active, ...inventory.zombie, ...inventory.shadow];
    } else if (activeTab === 'active') {
      items = inventory.active;
    } else if (activeTab === 'zombie') {
      items = inventory.zombie;
    } else if (activeTab === 'shadow') {
      items = inventory.shadow;
    }

    if (!searchQuery) return items;
    const q = searchQuery.toLowerCase();
    return items.filter(
      (item) => item.path.toLowerCase().includes(q) || item.method.toLowerCase().includes(q)
    );
  };

  const items = getFilteredItems();

  return (
    <div className="space-y-6">
      {/* Header with Search and Export */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-basalt border border-basalt-border rounded-xl p-6">
        <div>
          <h2 className="text-xl font-bold text-bone">Surface API Inventory Matrix</h2>
          <p className="text-sm text-bone-muted">
            Section 4.2 Tri-Classification: Active production routes, Zombie deprecated APIs, and Undocumented Shadow endpoints.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-stone-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search endpoints..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-ink border border-basalt-border rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-bone placeholder-stone-muted focus:outline-none focus:border-sage w-56"
            />
          </div>

          <button
            onClick={handleExport}
            disabled={isExporting}
            className="flex items-center gap-2 px-4 py-2 bg-sage hover:bg-sage-light text-ink font-semibold text-xs rounded-lg transition-colors cursor-pointer"
          >
            <Download className="w-4 h-4" />
            <span>Export OpenAPI 3.1</span>
          </button>
        </div>
      </div>

      {/* Classification Tabs */}
      <div className="flex gap-2 border-b border-basalt-border pb-2">
        <button
          onClick={() => setActiveTab('all')}
          className={`px-4 py-2 text-xs font-medium rounded-lg transition-colors cursor-pointer ${
            activeTab === 'all'
              ? 'bg-basalt-light text-bone font-semibold border border-basalt-border'
              : 'text-stone-muted hover:text-bone'
          }`}
        >
          All Endpoints ({(inventory?.active.length || 0) + (inventory?.zombie.length || 0) + (inventory?.shadow.length || 0)})
        </button>

        <button
          onClick={() => setActiveTab('active')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg transition-colors cursor-pointer ${
            activeTab === 'active'
              ? 'bg-moss/20 text-moss font-semibold border border-moss/30'
              : 'text-stone-muted hover:text-bone'
          }`}
        >
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>Active APIs ({inventory?.active.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('zombie')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg transition-colors cursor-pointer ${
            activeTab === 'zombie'
              ? 'bg-brass/20 text-brass font-semibold border border-brass/30'
              : 'text-stone-muted hover:text-bone'
          }`}
        >
          <Ghost className="w-3.5 h-3.5" />
          <span>Zombie APIs ({inventory?.zombie.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('shadow')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg transition-colors cursor-pointer ${
            activeTab === 'shadow'
              ? 'bg-copper/20 text-copper font-semibold border border-copper/30'
              : 'text-stone-muted hover:text-bone'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Shadow APIs ({inventory?.shadow.length || 0})</span>
        </button>
      </div>

      {/* Inventory Table */}
      <div className="bg-basalt border border-basalt-border rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-ink border-b border-basalt-border text-stone-muted font-mono uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">Method & Path</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Traffic (30d)</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Recommended Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-basalt-border">
              {items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-stone-muted italic">
                    No matching inventory records discovered. Run an assessment to populate inventory.
                  </td>
                </tr>
              ) : (
                items.map((row, idx) => (
                  <tr key={idx} className="hover:bg-basalt-light/50 transition-colors">
                    <td className="py-3.5 px-4 font-mono">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          row.method === 'GET' ? 'bg-sage/20 text-sage' :
                          row.method === 'POST' ? 'bg-moss/20 text-moss' :
                          row.method === 'DELETE' ? 'bg-brick/20 text-brick' : 'bg-brass/20 text-brass'
                        }`}>
                          {row.method}
                        </span>
                        <span className="text-bone font-medium">{row.path}</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold font-mono border ${
                        row.status === 'ACTIVE' ? 'bg-moss/10 text-moss border-moss/30' :
                        row.status === 'ZOMBIE' ? 'bg-brass/10 text-brass border-brass/30' :
                        'bg-copper/10 text-copper border-copper/30'
                      }`}>
                        {row.status}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-bone-muted">
                      <div>{row.request_count} hits</div>
                      {row.last_seen && (
                        <div className="text-[10px] text-stone-muted truncate">
                          {new Date(row.last_seen).toLocaleDateString()}
                        </div>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        row.risk_level === 'CRITICAL' ? 'bg-brick/20 text-brick' :
                        row.risk_level === 'HIGH' ? 'bg-copper/20 text-copper' :
                        row.risk_level === 'MEDIUM' ? 'bg-brass/20 text-brass' :
                        'bg-sage/20 text-sage'
                      }`}>
                        {row.risk_level}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-bone-muted text-xs">
                      {row.recommendation}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
