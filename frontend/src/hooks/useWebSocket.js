import { useState, useEffect, useCallback, useRef } from 'react';
import io from 'socket.io-client';

const WS_URL = import.meta.env.VITE_WS_URL || '/';

export const useWebSocket = (topic, onData) => {
    const [status, setStatus] = useState('disconnected');
    const socketRef = useRef(null);

    const connect = useCallback(() => {
        if (socketRef.current) return;

        console.log(`[WS] Connecting to ${WS_URL}...`);
        const socket = io(WS_URL, {
            reconnectionAttempts: 10,
            reconnectionDelay: 2000,
            timeout: 5000,
        });

        socket.on('connect', () => {
            console.log('[WS] Connected successfully');
            setStatus('connected');
        });

        socket.on('disconnect', (reason) => {
            console.log(`[WS] Disconnected: ${reason}`);
            setStatus('disconnected');
        });

        socket.on('connect_error', (error) => {
            console.error('[WS] Connection Error:', error);
            setStatus('error');
        });

        if (topic && onData) {
            socket.on(topic, onData);
        }

        socketRef.current = socket;
    }, [topic, onData]);

    const disconnect = useCallback(() => {
        if (socketRef.current) {
            socketRef.current.close();
            socketRef.current = null;
            setStatus('disconnected');
        }
    }, []);

    useEffect(() => {
        connect();
        return () => disconnect();
    }, [connect, disconnect]);

    return { status, socket: socketRef.current };
};
