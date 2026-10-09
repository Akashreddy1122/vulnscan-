"use client";

import { useEffect, useRef } from "react";

/**
 * Subtle animated 3D backdrop: a perspective grid with drifting nodes and
 * link lines, drawn on a canvas. Pure decoration — pointer-events disabled and
 * disabled entirely when the user prefers reduced motion.
 */
export default function Scene3D() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    let w = 0, h = 0, dpr = 1;
    type Node = { x: number; y: number; z: number; vx: number; vy: number; vz: number };
    let nodes: Node[] = [];

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.round(Math.min(70, Math.max(26, (w * h) / 26000)));
      nodes = Array.from({ length: count }, () => ({
        x: (Math.random() - 0.5) * 2, y: (Math.random() - 0.5) * 2, z: Math.random(),
        vx: (Math.random() - 0.5) * 0.0016, vy: (Math.random() - 0.5) * 0.0016, vz: (Math.random() - 0.5) * 0.0008,
      }));
    };

    const project = (n: Node) => {
      const depth = 1.2 + n.z * 1.6;
      const scale = 1 / depth;
      return { sx: w / 2 + n.x * w * 0.7 * scale, sy: h * 0.62 + n.y * h * 0.7 * scale, s: scale };
    };

    const frame = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      // perspective floor grid
      ctx.strokeStyle = "rgba(34,211,238,0.07)";
      ctx.lineWidth = 1;
      const horizon = h * 0.62;
      const offset = (t / 60) % 1;
      for (let i = 0; i <= 14; i++) {
        const y = horizon + Math.pow((i + offset) / 14, 2) * (h - horizon);
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }
      for (let i = -12; i <= 12; i++) {
        ctx.beginPath();
        ctx.moveTo(w / 2 + i * 22, horizon);
        ctx.lineTo(w / 2 + i * 120, h);
        ctx.stroke();
      }
      // nodes + links
      const pts = nodes.map(project);
      for (let i = 0; i < nodes.length; i++) {
        if (!reduce) {
          const n = nodes[i];
          n.x += n.vx; n.y += n.vy; n.z += n.vz;
          if (n.x < -1 || n.x > 1) n.vx *= -1;
          if (n.y < -1 || n.y > 1) n.vy *= -1;
          if (n.z < 0 || n.z > 1) n.vz *= -1;
        }
      }
      const projected = nodes.map(project);
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const a = projected[i], b = projected[j];
          const d = Math.hypot(a.sx - b.sx, a.sy - b.sy);
          if (d < 130) {
            ctx.strokeStyle = `rgba(34,211,238,${0.18 * (1 - d / 130)})`;
            ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
          }
        }
      }
      projected.forEach((p, i) => {
        const hot = i % 17 === 0;
        ctx.fillStyle = hot ? "rgba(255,77,109,0.75)" : "rgba(103,232,249,0.85)";
        ctx.beginPath();
        ctx.arc(p.sx, p.sy, Math.max(1, 2.4 * p.s), 0, Math.PI * 2);
        ctx.fill();
      });
      void pts;
      if (!reduce) raf = requestAnimationFrame(frame);
    };

    resize();
    raf = requestAnimationFrame(frame);
    window.addEventListener("resize", resize);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return <canvas ref={ref} aria-hidden className="scene3d" />;
}
