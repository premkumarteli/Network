import { useMemo } from 'react';

const Background = () => {
  const dots = useMemo(() => Array.from({ length: 80 }).map((_, i) => ({
    id: i,
    left: `${Math.random() * 100}%`,
    duration: `${Math.random() * 12 + 4}s`,
    delay: `${Math.random() * 8}s`,
    size: `${Math.random() * 6 + 4}px`,
    opacity: Math.random() * 0.5 + 0.4,
  })), []);

  return (
    <div className="ambient-background" aria-hidden="true">
      <div className="ambient-background__glow ambient-background__glow--cyan"></div>
      <div className="ambient-background__glow ambient-background__glow--violet"></div>
      <div className="ambient-background__glow ambient-background__glow--blue"></div>
      <div className="ambient-background__dots">
        {dots.map((dot) => (
          <div
            key={dot.id}
            className="ambient-background__dot"
            style={{
              '--left': dot.left,
              '--duration': dot.duration,
              '--size': dot.size,
              '--opacity': dot.opacity,
              '--delay': dot.delay,
            }}
          />
        ))}
      </div>
    </div>
  );
};

export default Background;
