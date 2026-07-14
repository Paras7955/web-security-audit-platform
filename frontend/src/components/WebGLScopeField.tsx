"use client";

import { useEffect, useRef, useState } from "react";

const vertexShaderSource = `
attribute vec2 a_position;
void main() {
  gl_Position = vec4(a_position, 0.0, 1.0);
}`;

const fragmentShaderSource = `
precision highp float;
uniform vec2 u_resolution;
uniform float u_time;
uniform float u_light;

float ring(vec2 p, float radius, float width) {
  return smoothstep(width, 0.0, abs(length(p) - radius));
}

float node(vec2 p, vec2 center, float size) {
  return smoothstep(size, 0.0, length(p - center));
}

void main() {
  vec2 uv = (gl_FragCoord.xy * 2.0 - u_resolution.xy) / min(u_resolution.x, u_resolution.y);
  float time = u_time * 0.28;
  float depth = 1.0 + 0.12 * sin(time * 1.7);
  vec2 p = uv * depth;
  p.x += 0.13;

  float angle = time * 0.16;
  mat2 rotation = mat2(cos(angle), -sin(angle), sin(angle), cos(angle));
  vec2 rp = rotation * p;

  float outer = ring(rp, 0.76, 0.012);
  float middle = ring(rp * vec2(1.0, 1.32), 0.54, 0.009);
  float inner = ring(rp, 0.29, 0.008);
  float radar = smoothstep(0.018, 0.0, abs(rp.y - 0.14 * sin(rp.x * 7.0 + time * 2.0))) * smoothstep(0.78, 0.15, length(rp));

  float spokes = 0.0;
  for (int i = 0; i < 8; i++) {
    float a = float(i) * 0.785398 + time * 0.08;
    vec2 direction = vec2(cos(a), sin(a));
    float lineDistance = abs(rp.x * direction.y - rp.y * direction.x);
    spokes += smoothstep(0.006, 0.0, lineDistance) * smoothstep(0.73, 0.2, length(rp)) * 0.28;
  }

  float nodes = 0.0;
  for (int i = 0; i < 7; i++) {
    float fi = float(i);
    float a = fi * 0.8976 + time * (0.18 + fi * 0.012);
    float radius = 0.28 + 0.065 * mod(fi, 4.0);
    vec2 center = vec2(cos(a), sin(a)) * radius;
    nodes += node(rp, center, 0.025) + node(rp, center, 0.055) * 0.18;
  }

  float scanAngle = time * 0.85;
  vec2 scanDirection = vec2(cos(scanAngle), sin(scanAngle));
  float sweep = max(0.0, dot(normalize(rp + 0.0001), scanDirection));
  sweep = pow(sweep, 18.0) * smoothstep(0.82, 0.08, length(rp));

  vec3 cyan = vec3(0.20, 0.88, 0.82);
  vec3 blue = vec3(0.20, 0.52, 1.0);
  vec3 violet = vec3(0.54, 0.35, 1.0);
  vec3 color = cyan * (outer + nodes * 1.4 + radar * 0.5);
  color += blue * (middle + spokes + sweep * 0.75);
  color += violet * (inner + sweep * 0.4);

  float glow = exp(-2.6 * length(rp)) * 0.14;
  color += mix(vec3(0.05, 0.14, 0.22), vec3(0.35, 0.72, 0.80), u_light) * glow;
  float alpha = clamp((outer + middle + inner + spokes + nodes + radar + sweep) * 0.82 + glow, 0.0, 0.92);
  gl_FragColor = vec4(color, alpha);
}`;

export function WebGLScopeField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [available, setAvailable] = useState(true);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    const gl = canvas.getContext("webgl", {
      alpha: true,
      antialias: false,
      depth: false,
      powerPreference: "low-power",
      premultipliedAlpha: true
    });
    if (!gl) {
      setAvailable(false);
      return;
    }

    const vertexShader = compileShader(gl, gl.VERTEX_SHADER, vertexShaderSource);
    const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, fragmentShaderSource);
    if (!vertexShader || !fragmentShader) {
      if (vertexShader) {
        gl.deleteShader(vertexShader);
      }
      if (fragmentShader) {
        gl.deleteShader(fragmentShader);
      }
      setAvailable(false);
      return;
    }

    const program = gl.createProgram();
    if (!program) {
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
      setAvailable(false);
      return;
    }
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      setAvailable(false);
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
      return;
    }

    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    gl.useProgram(program);
    const position = gl.getAttribLocation(program, "a_position");
    gl.enableVertexAttribArray(position);
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);

    const resolution = gl.getUniformLocation(program, "u_resolution");
    const time = gl.getUniformLocation(program, "u_time");
    const light = gl.getUniformLocation(program, "u_light");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let animationFrame = 0;
    let start = performance.now();
    let visible = !document.hidden;

    const render = (now: number) => {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.75);
      const width = Math.max(1, Math.floor(canvas.clientWidth * ratio));
      const height = Math.max(1, Math.floor(canvas.clientHeight * ratio));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        gl.viewport(0, 0, width, height);
      }

      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform2f(resolution, width, height);
      gl.uniform1f(time, reducedMotion.matches ? 2.8 : (now - start) / 1000);
      gl.uniform1f(light, document.documentElement.dataset.theme === "light" ? 1 : 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      if (visible && !reducedMotion.matches) {
        animationFrame = window.requestAnimationFrame(render);
      }
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      start = performance.now();
      render(start);
    };
    const handleVisibility = () => {
      visible = !document.hidden;
      if (visible) {
        restart();
      } else {
        window.cancelAnimationFrame(animationFrame);
      }
    };
    const themeObserver = new MutationObserver(restart);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    reducedMotion.addEventListener("change", restart);
    document.addEventListener("visibilitychange", handleVisibility);
    render(start);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      themeObserver.disconnect();
      reducedMotion.removeEventListener("change", restart);
      document.removeEventListener("visibilitychange", handleVisibility);
      gl.deleteBuffer(buffer);
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
    };
  }, []);

  return (
    <div className={available ? "scopeField" : "scopeField scopeFieldFallback"} aria-hidden="true">
      <canvas ref={canvasRef} />
      <span className="scopeFieldCore" />
      <span className="scopeFieldLabel">AUTHORIZED SCOPE</span>
    </div>
  );
}

function compileShader(gl: WebGLRenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) {
    return null;
  }
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}
