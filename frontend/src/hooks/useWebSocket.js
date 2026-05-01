import { useEffect, useState } from 'react';
import socket, {
  getRealtimeStatus,
  subscribeRealtimeEvent,
  subscribeRealtimeStatus,
  ensureRealtimeConnection,
} from '../socket';

export const useWebSocket = (topic, onData) => {
  const [status, setStatus] = useState(getRealtimeStatus());

  useEffect(() => subscribeRealtimeStatus(setStatus), []);

  useEffect(() => {
    if (!topic || !onData) {
      return undefined;
    }
    return subscribeRealtimeEvent(topic, onData);
  }, [topic, onData]);

  useEffect(() => {
    ensureRealtimeConnection();
  }, []);

  return { status, socket };
};
