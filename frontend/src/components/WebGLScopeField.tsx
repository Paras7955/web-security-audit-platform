"use client";

import { useEffect, useRef, useState } from "react";

type WebGLScopeFieldProps = {
  activeProfile?: string;
  currentStep?: string | null;
  status?: string;
};

type Vec3 = [number, number, number];
type SceneBox = {
  position: Vec3;
  scale: Vec3;
  color: Vec3;
  rotation?: Vec3;
  emissive?: number;
};

const vertexShaderSource = `
attribute vec3 a_position;
attribute vec3 a_normal;
uniform mat4 u_mvp;
uniform mat4 u_model;
varying vec3 v_normal;

void main() {
  gl_Position = u_mvp * vec4(a_position, 1.0);
  v_normal = mat3(u_model) * a_normal;
}`;

const fragmentShaderSource = `
precision mediump float;
uniform vec3 u_color;
uniform float u_emissive;
varying vec3 v_normal;

void main() {
  vec3 normal = normalize(v_normal);
  vec3 lightDirection = normalize(vec3(-0.35, 0.82, 0.48));
  float diffuse = max(dot(normal, lightDirection), 0.0);
  float edge = pow(1.0 - max(normal.z, 0.0), 2.0) * 0.12;
  vec3 lit = u_color * (0.28 + diffuse * 0.72 + edge + u_emissive);
  gl_FragColor = vec4(lit, 1.0);
}`;

const profileLabels: Record<string, string> = {
  "passive-web": "Passive web",
  "active-demo": "Active demo",
  "modern-web-crawl": "Modern web crawl",
  repo: "Repository"
};

const profileLanes: Record<string, number> = {
  "passive-web": -0.48,
  "active-demo": -0.15,
  "modern-web-crawl": 0.18,
  repo: 0.5
};

export function WebGLScopeField({ activeProfile = "passive-web", currentStep = null, status = "ready" }: WebGLScopeFieldProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const fieldRef = useRef<HTMLElement>(null);
  const pointerRef = useRef({ x: 0, y: 0 });
  const [available, setAvailable] = useState(true);

  useEffect(() => {
    const canvas = canvasRef.current;
    const field = fieldRef.current;
    if (!canvas || !field) {
      return;
    }

    const gl = canvas.getContext("webgl", {
      alpha: true,
      antialias: true,
      depth: true,
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
      if (vertexShader) gl.deleteShader(vertexShader);
      if (fragmentShader) gl.deleteShader(fragmentShader);
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
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
      setAvailable(false);
      return;
    }

    const vertices = createCubeVertices();
    const buffer = gl.createBuffer();
    if (!buffer) {
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
      setAvailable(false);
      return;
    }

    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
    gl.useProgram(program);

    const positionLocation = gl.getAttribLocation(program, "a_position");
    const normalLocation = gl.getAttribLocation(program, "a_normal");
    const mvpLocation = gl.getUniformLocation(program, "u_mvp");
    const modelLocation = gl.getUniformLocation(program, "u_model");
    const colorLocation = gl.getUniformLocation(program, "u_color");
    const emissiveLocation = gl.getUniformLocation(program, "u_emissive");
    const stride = 6 * Float32Array.BYTES_PER_ELEMENT;

    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 3, gl.FLOAT, false, stride, 0);
    gl.enableVertexAttribArray(normalLocation);
    gl.vertexAttribPointer(normalLocation, 3, gl.FLOAT, false, stride, 3 * Float32Array.BYTES_PER_ELEMENT);
    gl.enable(gl.DEPTH_TEST);
    gl.depthFunc(gl.LEQUAL);
    gl.enable(gl.CULL_FACE);
    gl.cullFace(gl.BACK);

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let animationFrame = 0;
    let visible = !document.hidden;
    let start = performance.now();

    const drawBox = (box: SceneBox, viewProjection: Float32Array) => {
      const model = composeMatrix(box.position, box.rotation ?? [0, 0, 0], box.scale);
      const mvp = multiplyMatrices(viewProjection, model);
      gl.uniformMatrix4fv(mvpLocation, false, mvp);
      gl.uniformMatrix4fv(modelLocation, false, model);
      gl.uniform3fv(colorLocation, box.color);
      gl.uniform1f(emissiveLocation, box.emissive ?? 0);
      gl.drawArrays(gl.TRIANGLES, 0, 36);
    };

    const render = (now: number) => {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.75);
      const width = Math.max(1, Math.floor(canvas.clientWidth * ratio));
      const height = Math.max(1, Math.floor(canvas.clientHeight * ratio));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        gl.viewport(0, 0, width, height);
      }

      const elapsed = reducedMotion.matches ? 1.25 : (now - start) / 1000;
      const pulse = 0.5 + Math.sin(elapsed * 2.15) * 0.5;
      const lane = profileLanes[activeProfile] ?? profileLanes["passive-web"];
      const stage = stageForStep(currentStep, status);
      const warning = status === "completed_with_warnings" || status === "failed";
      const completed = status === "completed";
      const routeColor: Vec3 = warning ? [0.96, 0.51, 0.13] : completed ? [0.31, 0.67, 0.47] : [0.82, 0.28, 0.08];
      const activeColor: Vec3 = warning ? [1, 0.68, 0.28] : completed ? [0.52, 0.86, 0.66] : [1, 0.49, 0.2];
      const structure: Vec3 = document.documentElement.dataset.theme === "light" ? [0.42, 0.39, 0.35] : [0.12, 0.115, 0.11];
      const structureTop: Vec3 = document.documentElement.dataset.theme === "light" ? [0.58, 0.54, 0.49] : [0.21, 0.195, 0.18];
      const pointer = pointerRef.current;
      const camera: Vec3 = [pointer.x * 0.5, 5.45 + pointer.y * 0.25, 10.7];
      const projection = perspectiveMatrix(Math.PI / 4.2, width / height, 0.1, 40);
      const view = lookAtMatrix(camera, [0, -0.05, 0], [0, 1, 0]);
      const viewProjection = multiplyMatrices(projection, view);

      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

      for (let index = -6; index <= 6; index += 1) {
        drawBox({ position: [index * 0.82, -0.56, 0], scale: [0.012, 0.012, 4.4], color: structure, emissive: 0 }, viewProjection);
      }
      for (let index = -4; index <= 4; index += 1) {
        drawBox({ position: [0, -0.56, index * 0.82], scale: [5.45, 0.012, 0.012], color: structure, emissive: 0 }, viewProjection);
      }

      const platforms: SceneBox[] = [
        { position: [-4.28, -0.34, -0.72], scale: [0.72, 0.16, 0.66], color: structure },
        { position: [-4.28, -0.34, 0.72], scale: [0.72, 0.16, 0.66], color: structure },
        { position: [-2.45, -0.28, 0], scale: [0.72, 0.22, 0.92], color: structure },
        { position: [-0.48, -0.3, lane], scale: [0.92, 0.18, 0.8], color: structure },
        { position: [1.56, -0.28, 0], scale: [0.76, 0.2, 0.82], color: structure },
        { position: [3.72, -0.26, 0], scale: [1.02, 0.22, 1.02], color: structure }
      ];
      platforms.forEach((box) => drawBox(box, viewProjection));

      const route: SceneBox[] = [
        { position: [-3.68, -0.02, -0.56], scale: [0.72, 0.045, 0.06], color: routeColor, rotation: [0, -0.23, 0] },
        { position: [-3.68, -0.02, 0.56], scale: [0.72, 0.045, 0.06], color: routeColor, rotation: [0, 0.23, 0] },
        { position: [-1.47, 0.01, lane * 0.55], scale: [1.12, 0.055, 0.07], color: routeColor, rotation: [0, lane * -0.18, 0] },
        { position: [0.54, 0.01, lane * 0.48], scale: [1.08, 0.055, 0.07], color: routeColor, rotation: [0, lane * 0.18, 0] },
        { position: [2.62, 0.01, 0], scale: [1.14, 0.055, 0.07], color: routeColor }
      ];
      route.forEach((box, index) => drawBox({ ...box, color: index <= stage ? activeColor : box.color, emissive: index === stage ? 0.22 + pulse * 0.2 : 0.02 }, viewProjection));

      const blocks: SceneBox[] = [
        { position: [-4.28, 0.02, -0.72], scale: [0.27, 0.34, 0.27], color: structureTop },
        { position: [-4.28, 0.02, 0.72], scale: [0.27, 0.34, 0.27], color: structureTop },
        { position: [-2.45, 0.14, 0], scale: [0.38, 0.54, 0.52], color: stage === 1 ? activeColor : structureTop, emissive: stage === 1 ? pulse * 0.12 : 0 },
        { position: [-0.48, 0.12, lane], scale: [0.48, 0.44, 0.42], color: stage === 2 ? activeColor : structureTop, emissive: stage === 2 ? pulse * 0.15 : 0 },
        { position: [1.56, 0.11, 0], scale: [0.42, 0.4, 0.44], color: stage === 3 ? activeColor : structureTop, emissive: stage === 3 ? pulse * 0.15 : 0 },
        { position: [3.72, 0.15, 0], scale: [0.62, 0.54, 0.64], color: structureTop },
        { position: [3.72, 0.25, 0], scale: [0.31, 0.62, 0.32], color: stage >= 4 ? activeColor : routeColor, emissive: stage >= 4 ? 0.18 + pulse * 0.16 : 0.04 }
      ];
      blocks.forEach((box) => drawBox(box, viewProjection));

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
      if (visible) restart();
      else window.cancelAnimationFrame(animationFrame);
    };
    const handlePointerMove = (event: PointerEvent) => {
      const rect = field.getBoundingClientRect();
      pointerRef.current = {
        x: ((event.clientX - rect.left) / rect.width - 0.5) * 2,
        y: ((event.clientY - rect.top) / rect.height - 0.5) * 2
      };
    };
    const handlePointerLeave = () => {
      pointerRef.current = { x: 0, y: 0 };
    };
    const themeObserver = new MutationObserver(restart);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    reducedMotion.addEventListener("change", restart);
    window.addEventListener("resize", restart);
    document.addEventListener("visibilitychange", handleVisibility);
    field.addEventListener("pointermove", handlePointerMove);
    field.addEventListener("pointerleave", handlePointerLeave);
    render(start);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      themeObserver.disconnect();
      reducedMotion.removeEventListener("change", restart);
      window.removeEventListener("resize", restart);
      document.removeEventListener("visibilitychange", handleVisibility);
      field.removeEventListener("pointermove", handlePointerMove);
      field.removeEventListener("pointerleave", handlePointerLeave);
      gl.deleteBuffer(buffer);
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
    };
  }, [activeProfile, currentStep, status]);

  const fieldClass = available ? "scopeField" : "scopeField scopeFieldFallback";
  return (
    <figure ref={fieldRef} className={fieldClass} aria-label="Authorized audit route from local scope through policy checks and normalized findings">
      <canvas ref={canvasRef} aria-hidden="true" />
      <div className="scopeFieldLabels" aria-hidden="true">
        <span className="scopeNode scopeNodeSource">Web target<br /><small>Local repository</small></span>
        <span className="scopeNode scopeNodePolicy">Policy gate</span>
        <span className="scopeNode scopeNodeProfile">{profileLabels[activeProfile] ?? "Audit profile"}</span>
        <span className="scopeNode scopeNodeNormalize">Normalize + redact</span>
        <span className="scopeNode scopeNodeHarbor">Protected harbor</span>
      </div>
      <figcaption><span className="scopeFieldSignal" /> Scope stays explicit at every step</figcaption>
    </figure>
  );
}

function stageForStep(step: string | null, status: string) {
  if (status === "completed" || status === "completed_with_warnings") return 4;
  if (status === "ready") return 2;
  if (!step) return 0;
  if (step.includes("validation")) return 1;
  if (step.includes("normaliz")) return 3;
  if (step.includes("report") || step.includes("explanation")) return 4;
  return 2;
}

function compileShader(gl: WebGLRenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

function createCubeVertices() {
  const data: number[] = [];
  const faces: Array<{ normal: Vec3; corners: Vec3[] }> = [
    { normal: [0, 0, 1], corners: [[-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]] },
    { normal: [0, 0, -1], corners: [[1, -1, -1], [-1, -1, -1], [-1, 1, -1], [1, 1, -1]] },
    { normal: [1, 0, 0], corners: [[1, -1, 1], [1, -1, -1], [1, 1, -1], [1, 1, 1]] },
    { normal: [-1, 0, 0], corners: [[-1, -1, -1], [-1, -1, 1], [-1, 1, 1], [-1, 1, -1]] },
    { normal: [0, 1, 0], corners: [[-1, 1, 1], [1, 1, 1], [1, 1, -1], [-1, 1, -1]] },
    { normal: [0, -1, 0], corners: [[-1, -1, -1], [1, -1, -1], [1, -1, 1], [-1, -1, 1]] }
  ];
  for (const face of faces) {
    for (const index of [0, 1, 2, 0, 2, 3]) {
      data.push(...face.corners[index], ...face.normal);
    }
  }
  return new Float32Array(data);
}

function composeMatrix(position: Vec3, rotation: Vec3, scale: Vec3) {
  return multiplyMatrices(
    translationMatrix(...position),
    multiplyMatrices(rotationYMatrix(rotation[1]), multiplyMatrices(rotationXMatrix(rotation[0]), scalingMatrix(...scale)))
  );
}

function multiplyMatrices(left: Float32Array, right: Float32Array) {
  const result = new Float32Array(16);
  for (let column = 0; column < 4; column += 1) {
    for (let row = 0; row < 4; row += 1) {
      let value = 0;
      for (let index = 0; index < 4; index += 1) {
        value += left[index * 4 + row] * right[column * 4 + index];
      }
      result[column * 4 + row] = value;
    }
  }
  return result;
}

function perspectiveMatrix(fieldOfView: number, aspect: number, near: number, far: number) {
  const f = 1 / Math.tan(fieldOfView / 2);
  const nf = 1 / (near - far);
  return new Float32Array([
    f / aspect, 0, 0, 0,
    0, f, 0, 0,
    0, 0, (far + near) * nf, -1,
    0, 0, 2 * far * near * nf, 0
  ]);
}

function lookAtMatrix(eye: Vec3, center: Vec3, up: Vec3) {
  const z = normalize([eye[0] - center[0], eye[1] - center[1], eye[2] - center[2]]);
  const x = normalize(cross(up, z));
  const y = cross(z, x);
  return new Float32Array([
    x[0], y[0], z[0], 0,
    x[1], y[1], z[1], 0,
    x[2], y[2], z[2], 0,
    -dot(x, eye), -dot(y, eye), -dot(z, eye), 1
  ]);
}

function translationMatrix(x: number, y: number, z: number) {
  return new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, x, y, z, 1]);
}

function scalingMatrix(x: number, y: number, z: number) {
  return new Float32Array([x, 0, 0, 0, 0, y, 0, 0, 0, 0, z, 0, 0, 0, 0, 1]);
}

function rotationXMatrix(angle: number) {
  const cosine = Math.cos(angle);
  const sine = Math.sin(angle);
  return new Float32Array([1, 0, 0, 0, 0, cosine, sine, 0, 0, -sine, cosine, 0, 0, 0, 0, 1]);
}

function rotationYMatrix(angle: number) {
  const cosine = Math.cos(angle);
  const sine = Math.sin(angle);
  return new Float32Array([cosine, 0, -sine, 0, 0, 1, 0, 0, sine, 0, cosine, 0, 0, 0, 0, 1]);
}

function normalize(vector: Vec3): Vec3 {
  const length = Math.hypot(...vector) || 1;
  return [vector[0] / length, vector[1] / length, vector[2] / length];
}

function cross(left: Vec3, right: Vec3): Vec3 {
  return [left[1] * right[2] - left[2] * right[1], left[2] * right[0] - left[0] * right[2], left[0] * right[1] - left[1] * right[0]];
}

function dot(left: Vec3, right: Vec3) {
  return left[0] * right[0] + left[1] * right[1] + left[2] * right[2];
}
