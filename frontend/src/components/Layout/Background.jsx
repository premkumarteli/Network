import { useEffect, useRef, useState } from 'react';

const Background = () => {
  const canvasRef = useRef(null);
  const [theme, setTheme] = useState(document.documentElement.getAttribute('data-theme') || 'dark');

  useEffect(() => {
    const root = document.documentElement;
    const observer = new MutationObserver(() => {
      setTheme(root.getAttribute('data-theme') || 'dark');
    });

    observer.observe(root, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    let width, height;
    let stars = [];
    let asteroids = [];
    let animationFrameId;

    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    class Star {
      constructor() {
        this.reset();
        this.y = Math.random() * height;
      }
      reset() {
        this.x = Math.random() * width;
        this.y = -10;
        this.z = Math.random() * 2 + 0.5;
        this.size = Math.random() * 1.5;
        this.opacity = Math.random() * 0.5 + 0.1;
      }
      update() {
        this.y += this.z * 0.5;
        if (this.y > height) this.reset();
      }
      draw() {
        ctx.fillStyle = theme === 'light'
          ? `rgba(81, 101, 124, ${Math.min(this.opacity, 0.28)})`
          : `rgba(255, 255, 255, ${this.opacity})`;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    class Asteroid {
      constructor() {
        this.reset();
      }
      reset() {
        this.x = Math.random() < 0.5 ? -50 : width + 50;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 2;
        this.vy = (Math.random() - 0.5) * 2;
        this.size = Math.random() * 2 + 1;
        this.color = theme === 'light'
          ? (Math.random() < 0.5 ? "rgba(15, 118, 110, " : "rgba(21, 94, 117, ")
          : (Math.random() < 0.5 ? "rgba(6, 182, 212, " : "rgba(139, 92, 246, ");
        this.opacity = 0;
        this.life = 0;
        this.maxLife = Math.random() * 200 + 100;
      }
      update() {
        this.x += this.vx;
        this.y += this.vy;
        this.life++;
        if (this.life < 50) this.opacity += 0.01;
        else if (this.life > this.maxLife - 50) this.opacity -= 0.01;
        if (this.life > this.maxLife || this.opacity < 0) this.reset();
      }
      draw() {
        ctx.shadowBlur = 15;
        ctx.shadowColor = this.color + "1)";
        ctx.fillStyle = this.color + this.opacity + ")";
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }

    const init = () => {
      stars = [];
      asteroids = [];
      for (let i = 0; i < 150; i++) stars.push(new Star());
      for (let i = 0; i < 15; i++) asteroids.push(new Asteroid());
    };

    const animate = () => {
      ctx.clearRect(0, 0, width, height);

      stars.forEach((s) => {
        s.update();
        s.draw();
      });

      ctx.strokeStyle = "rgba(6, 182, 212, 0.1)";
      ctx.lineWidth = 0.5;
      for (let i = 0; i < asteroids.length; i++) {
        asteroids[i].update();
        asteroids[i].draw();
      }
      animationFrameId = requestAnimationFrame(animate);
    };

    window.addEventListener("resize", resize);
    resize();
    init();
    animate();

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [theme]);

  return (
    <div
      className="ambient-background"
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        background: theme === 'light'
          ? 'linear-gradient(180deg, rgba(237, 243, 248, 0.92), rgba(247, 250, 252, 0.88))'
          : undefined,
      }}
    >
      {/* Background Glows kept for depth */}
      <div className="ambient-background__glow ambient-background__glow--cyan" style={{ opacity: theme === 'light' ? 0.24 : undefined }}></div>
      <div className="ambient-background__glow ambient-background__glow--violet" style={{ opacity: theme === 'light' ? 0.14 : undefined }}></div>
      <div className="ambient-background__glow ambient-background__glow--blue" style={{ opacity: theme === 'light' ? 0.18 : undefined }}></div>
      
      <canvas 
        ref={canvasRef} 
        id="particle-canvas" 
        style={{ 
          position: 'absolute', 
          top: 0, 
          left: 0, 
          width: '100%', 
          height: '100%', 
          pointerEvents: 'none' 
        }} 
      />
    </div>
  );
};

export default Background;
