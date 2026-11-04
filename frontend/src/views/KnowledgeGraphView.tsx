import React, { useEffect, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  useNodesState,
  useEdgesState,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Layers, Key, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

export const KnowledgeGraphView: React.FC = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const loadGraph = async () => {
    try {
      setIsLoading(true);
      const data = await api.getGraph();

      // Position nodes in radial or grid coordinates
      const mappedNodes: Node[] = data.nodes.map((n, i) => {
        const cols = 5;
        const col = i % cols;
        const row = Math.floor(i / cols);
        const isParam = n.type === 'parameter' || n.data?.node_type === 'parameter';

        return {
          id: n.id,
          type: 'default',
          position: { x: col * 260 + (isParam ? 30 : 0), y: row * 160 + (isParam ? 40 : 0) },
          data: {
            ...n.data,
            label: (
              <div className="text-left font-sans text-xs">
                <div className="flex items-center gap-1.5 mb-1">
                  {n.data.method && (
                    <span className={`px-1.5 py-0.5 text-[10px] font-mono font-bold rounded ${
                      n.data.method === 'GET' ? 'bg-sage/20 text-sage' :
                      n.data.method === 'POST' ? 'bg-moss/20 text-moss' :
                      n.data.method === 'DELETE' ? 'bg-brick/20 text-brick' : 'bg-brass/20 text-brass'
                    }`}>
                      {String(n.data.method)}
                    </span>
                  )}
                  {n.data.auth_required && (
                    <Key className="w-3 h-3 text-copper inline" />
                  )}
                </div>
                <div className="font-mono text-[11px] font-semibold text-bone truncate max-w-[190px]">
                  {n.data.path ? String(n.data.path) : String(n.data.label)}
                </div>
              </div>
            ),
          },
          style: {
            background: isParam ? '#181E22' : '#1D2327',
            borderColor: isParam ? '#2A3339' : '#4F7A5A',
            borderWidth: 1.5,
            borderRadius: 8,
            color: '#F2EFE8',
            width: 220,
            padding: '8px 12px',
          },
        };
      });

      const mappedEdges: Edge[] = data.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: true,
        style: { stroke: '#4F7A5A', strokeWidth: 1.5 },
      }));

      setNodes(mappedNodes);
      setEdges(mappedEdges);
    } catch {
      // ignore load errors
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadGraph();
  }, []);

  return (
    <div className="space-y-4">
      {/* Header controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-basalt border border-basalt-border rounded-xl p-4">
        <div>
          <h2 className="text-lg font-bold text-bone flex items-center gap-2">
            <Layers className="w-5 h-5 text-moss" />
            <span>Interactive Knowledge Graph</span>
          </h2>
          <p className="text-xs text-bone-muted">
            Topology map of discovered endpoints, path parameters, authenticated roles, and business workflows.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadGraph}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-ink border border-basalt-border hover:border-sage text-xs font-mono text-bone rounded-lg transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Reload Topology</span>
          </button>
        </div>
      </div>

      {/* Main Graph Area */}
      <div className="relative h-[650px] bg-ink border border-basalt-border rounded-xl overflow-hidden shadow-2xl">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={(_, node) => setSelectedNode(node)}
          fitView
        >
          <Background color="#2A3339" gap={20} size={1} />
          <Controls className="bg-basalt border border-basalt-border text-bone rounded-lg overflow-hidden fill-bone" />
          <MiniMap
            nodeColor="#4F7A5A"
            maskColor="rgba(20, 24, 27, 0.7)"
            className="bg-basalt border border-basalt-border rounded-lg"
          />
        </ReactFlow>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 bg-basalt/95 backdrop-blur-md border border-basalt-border rounded-xl p-4 shadow-2xl space-y-3 z-10">
            <div className="flex items-center justify-between border-b border-basalt-border pb-2">
              <span className="text-xs font-mono text-sage font-bold uppercase tracking-wider">Node Details</span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-stone-muted hover:text-bone text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>
            <div className="space-y-2 text-xs">
              <div>
                <span className="text-stone-muted block">Identifier</span>
                <span className="font-mono text-bone break-all">{selectedNode.id}</span>
              </div>
              {selectedNode.data?.path && (
                <div>
                  <span className="text-stone-muted block">Path</span>
                  <span className="font-mono text-moss">{String(selectedNode.data.path)}</span>
                </div>
              )}
              {selectedNode.data?.method && (
                <div>
                  <span className="text-stone-muted block">HTTP Method</span>
                  <span className="font-mono font-bold text-bone">{String(selectedNode.data.method)}</span>
                </div>
              )}
              {selectedNode.data?.auth_required !== undefined && (
                <div>
                  <span className="text-stone-muted block">Authentication</span>
                  <span className={`font-mono ${selectedNode.data.auth_required ? 'text-copper' : 'text-sage'}`}>
                    {selectedNode.data.auth_required ? 'Required (Bearer token)' : 'Public / Unauthenticated'}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
