import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { subscribeRealtimeEvent } from '../../socket';

const AlertPanel = ({ isOpen, onClose }) => {
    const [alerts, setAlerts] = useState([]);
    const panelRef = useRef(null);

    useEffect(() => {
        const handleNewAlert = (alert) => {
            setAlerts(prev => [alert, ...prev].slice(0, 20));
        };

        return subscribeRealtimeEvent('alert_event', handleNewAlert);
    }, []);

    useEffect(() => {
        if (!isOpen) {
            return undefined;
        }

        const handlePointerDown = (event) => {
            if (panelRef.current && !panelRef.current.contains(event.target)) {
                onClose();
            }
        };

        const handleKeyDown = (event) => {
            if (event.key === 'Escape') {
                onClose();
            }
        };

        document.addEventListener('mousedown', handlePointerDown);
        document.addEventListener('touchstart', handlePointerDown);
        document.addEventListener('keydown', handleKeyDown);

        return () => {
            document.removeEventListener('mousedown', handlePointerDown);
            document.removeEventListener('touchstart', handlePointerDown);
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [isOpen, onClose]);

    return (
        <AnimatePresence>
            {isOpen ? (
                <>
                    <motion.button
                        type="button"
                        aria-label="Close threat feed"
                        className="fixed inset-0 z-[99] bg-black/45 backdrop-blur-[2px]"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={onClose}
                    />
                    <motion.div
                        ref={panelRef}
                        initial={{ x: '100%' }}
                        animate={{ x: 0 }}
                        exit={{ x: '100%' }}
                        transition={{ type: 'spring', damping: 25, stiffness: 200 }}
                        className="fixed top-0 right-0 z-[100] flex h-screen w-[22rem] max-w-[calc(100vw-1rem)] flex-col border-l border-white/5 bg-slate-900/98 shadow-[-20px_0px_50px_rgba(0,0,0,0.5)] backdrop-blur-xl"
                    >
                        <div className="flex items-center justify-between border-b border-white/5 bg-white/[0.02] p-6">
                            <div className="flex items-center gap-3">
                                <div className="relative flex h-3 w-3">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-20"></span>
                                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-red-500"></span>
                                </div>
                                <h2 className="text-lg font-bold tracking-tight text-white uppercase font-mono">Real-time Threats</h2>
                            </div>
                            <button onClick={onClose} className="rounded-full p-2 text-slate-400 transition-all hover:bg-white/5 hover:text-white">
                                <i className="ri-close-large-line text-xl"></i>
                            </button>
                        </div>

                        <div className="custom-scrollbar flex-1 space-y-3 overflow-y-auto p-4">
                            <AnimatePresence initial={false}>
                                {alerts.length > 0 ? (
                                    alerts.map((alert, index) => (
                                        <motion.div
                                            key={alert.id || index}
                                            initial={{ opacity: 0, x: 20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            exit={{ opacity: 0, scale: 0.95 }}
                                            className={`relative group rounded-xl border border-white/5 bg-gradient-to-br p-4 transition-colors hover:border-white/10 ${alert.severity === 'CRITICAL' ? 'from-red-900/20 to-transparent' : 'from-slate-800/40 to-transparent'}`}
                                        >
                                            <div className="flex flex-col gap-2">
                                                <div className="flex items-center justify-between">
                                                    <span className={`rounded px-2 py-0.5 text-[10px] font-black uppercase tracking-widest text-white ${alert.severity === 'CRITICAL' ? 'bg-red-600' : 'bg-slate-700'}`}>
                                                        {alert.severity}
                                                    </span>
                                                    <span className="font-mono text-[10px] text-slate-500">{new Date(alert.time).toLocaleTimeString([], { hour12: false })}</span>
                                                </div>
                                                <h3 className="text-sm font-semibold leading-snug text-slate-100">{alert.message}</h3>
                                                <div className="mt-1 grid grid-cols-2 gap-2">
                                                    <div className="flex items-center gap-1.5 text-slate-400">
                                                        <i className="ri-map-pin-range-line text-xs"></i>
                                                        <span className="font-mono text-[11px]">{alert.src_ip}</span>
                                                    </div>
                                                    <div className="flex items-center gap-1.5 truncate text-slate-400">
                                                        <i className="ri-instance-line text-xs"></i>
                                                        <span className="truncate text-[11px]">{alert.application}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        </motion.div>
                                    ))
                                ) : (
                                    <div className="flex h-full flex-col items-center justify-center p-8 text-center">
                                        <div className="relative mb-6">
                                            <motion.div
                                                animate={{ rotate: 360 }}
                                                transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
                                                className="h-24 w-24 rounded-full border-2 border-dashed border-blue-500/20"
                                            />
                                            <i className="ri-shield-flash-line absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-5xl text-blue-500/20"></i>
                                        </div>
                                        <p className="animate-pulse font-mono text-xs uppercase tracking-widest text-slate-500">Scanning Grid...</p>
                                    </div>
                                )}
                            </AnimatePresence>
                        </div>

                        <div className="border-t border-white/5 bg-white/[0.01] p-4">
                            <button
                                onClick={() => setAlerts([])}
                                className="w-full rounded-lg border border-white/5 bg-slate-800/50 py-2.5 text-xs font-bold uppercase tracking-widest text-slate-300 transition-all active:scale-95 hover:bg-slate-700/50"
                            >
                                Clear History
                            </button>
                        </div>
                    </motion.div>
                </>
            ) : null}
        </AnimatePresence>
    );
};


export default AlertPanel;
