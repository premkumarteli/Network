import React, { useEffect, useRef } from 'react';

const Background = () => {
  const canvasRef = useRef(null);

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
        ctx.fillStyle = `rgba(255, 255, 255, ${this.opacity})`;
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
        this.color = Math.random() < 0.5 ? "rgba(6, 182, 212, " : "rgba(139, 92, 246, ";
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
        for (let j = i + 1; j < asteroids.length; j++) {
          const dx = asteroids[i].x - asteroids[j].x;
          const dy = asteroids[i].y - asteroids[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 200) {
            ctx.beginPath();
            ctx.moveTo(asteroids[i].x, asteroids[i].y);
            ctx.lineTo(asteroids[j].x, asteroids[j].y);
            ctx.stroke();
          }
        }
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
  }, []);

  return <canvas ref={canvasRef} id="particle-canvas" style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', zIndex: 0, pointerEvents: 'none' }} />;
};

export default Background;
