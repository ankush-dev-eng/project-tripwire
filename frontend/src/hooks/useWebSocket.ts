import { useEffect, useRef, useState, useCallback } from 'react';
import { OrchestratorState, WebSocketEvent } from '../types';

interface UseWebSocketOptions {
  onEvent?: (event: WebSocketEvent) => void;
  onStateUpdate?: (state: OrchestratorState) => void;
}

export function useWebSocket({ onEvent, onStateUpdate }: UseWebSocketOptions = {}) {
  const [isConnected, setIsConnected] = useState(false);
  const [events, setEvents] = useState<WebSocketEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/stream`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (message) => {
        try {
          const payload = JSON.parse(message.data);

          if (payload.type === 'INITIAL_SYNC' && payload.state) {
            onStateUpdate?.(payload.state);
          } else if (payload.type === 'STATE_UPDATE' && payload.state) {
            onStateUpdate?.(payload.state);
          } else {
            const ev: WebSocketEvent = {
              type: payload.type || 'EVENT',
              timestamp: payload.timestamp || new Date().toISOString(),
              data: payload.data || payload,
            };
            setEvents((prev) => [ev, ...prev].slice(0, 200));
            onEvent?.(ev);
          }
        } catch {
          // ignore parse errors
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        // Attempt reconnect after 3 seconds
        reconnectTimeoutRef.current = window.setTimeout(() => {
          connect();
        }, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      setIsConnected(false);
    }
  }, [onEvent, onStateUpdate]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const send = (action: string, data: Record<string, unknown> = {}) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action, ...data }));
    }
  };

  return { isConnected, events, send };
}

