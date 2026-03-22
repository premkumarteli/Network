import { useEffect, useRef } from 'react';

export const useVisibilityPolling = (callback, intervalMs) => {
  const callbackRef = useRef(callback);

  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  useEffect(() => {
    if (!intervalMs || intervalMs <= 0) {
      return undefined;
    }

    let cancelled = false;

    const run = () => {
      if (cancelled || document.visibilityState !== 'visible') {
        return;
      }
      callbackRef.current?.();
    };

    const intervalId = window.setInterval(run, intervalMs);
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        run();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [intervalMs]);
};

export default useVisibilityPolling;
