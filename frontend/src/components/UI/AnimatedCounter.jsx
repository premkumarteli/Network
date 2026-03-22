import { useEffect, useRef, useState } from 'react';

const AnimatedCounter = ({
  value,
  duration = 700,
  formatter = defaultFormatter,
}) => {
  const numericValue = Number(value);
  const [displayValue, setDisplayValue] = useState(Number.isFinite(numericValue) ? numericValue : value);
  const frameRef = useRef(0);
  const previousNumericRef = useRef(Number.isFinite(numericValue) ? numericValue : 0);

  useEffect(() => {
    if (!Number.isFinite(numericValue)) {
      setDisplayValue(value);
      return undefined;
    }

    const startValue = previousNumericRef.current;
    const startedAt = performance.now();

    const tick = (now) => {
      const progress = Math.min((now - startedAt) / duration, 1);
      const eased = 1 - (1 - progress) * (1 - progress);
      const nextValue = startValue + (numericValue - startValue) * eased;
      setDisplayValue(nextValue);
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(tick);
      } else {
        previousNumericRef.current = numericValue;
      }
    };

    cancelAnimationFrame(frameRef.current);
    frameRef.current = requestAnimationFrame(tick);

    return () => cancelAnimationFrame(frameRef.current);
  }, [numericValue, value, duration]);

  if (!Number.isFinite(numericValue)) {
    return <>{String(value ?? '0')}</>;
  }

  return <>{formatter(displayValue)}</>;
};

function defaultFormatter(value) {
  return Math.round(value).toLocaleString();
}

export default AnimatedCounter;
