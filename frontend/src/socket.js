import io from 'socket.io-client';
import { getSocketBaseUrl } from './config/runtime';

const socket = io(getSocketBaseUrl(), {
  autoConnect: false,
  withCredentials: true,
  reconnection: true,
  reconnectionAttempts: 10,
  reconnectionDelay: 2000,
  timeout: 5000,
  transports: ['websocket', 'polling'],
});

const statusListeners = new Set();
let connectionStatus = socket.connected ? 'connected' : 'disconnected';

const emitStatus = (nextStatus) => {
  connectionStatus = nextStatus;
  statusListeners.forEach((listener) => {
    try {
      listener(connectionStatus);
    } catch (error) {
      console.error('[WS] Status listener failed:', error);
    }
  });
};

socket.on('connect', () => {
  emitStatus('connected');
});

socket.on('disconnect', () => {
  emitStatus('disconnected');
});

socket.on('connect_error', (error) => {
  console.error('[WS] Connection error:', error);
  emitStatus('error');
});

socket.io.on('reconnect_attempt', () => {
  emitStatus('reconnecting');
});

socket.io.on('reconnect', () => {
  emitStatus('connected');
});

socket.io.on('reconnect_failed', () => {
  emitStatus('error');
});

export const ensureRealtimeConnection = () => {
  if (!socket.connected) {
    emitStatus('connecting');
    socket.connect();
  }
  return socket;
};

export const getRealtimeStatus = () => connectionStatus;

export const subscribeRealtimeStatus = (listener) => {
  if (typeof listener !== 'function') {
    return () => {};
  }

  statusListeners.add(listener);
  listener(connectionStatus);
  ensureRealtimeConnection();

  return () => {
    statusListeners.delete(listener);
  };
};

export const subscribeRealtimeEvent = (eventName, handler) => {
  if (typeof handler !== 'function') {
    return () => {};
  }

  ensureRealtimeConnection();
  socket.on(eventName, handler);
  return () => {
    socket.off(eventName, handler);
  };
};

export const disconnectRealtime = () => {
  socket.disconnect();
};

export default socket;
