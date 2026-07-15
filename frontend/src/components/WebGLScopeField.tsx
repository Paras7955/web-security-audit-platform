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
  geometry?: "cube" | "cylinder";
};

type PulseBinding = {
  box: SceneBox;
  base: number;
  amount: number;
};

type WebGLScene = {
  boxes: SceneBox[];
  pulseBindings: PulseBinding[];
};

const vertexShaderSource = `
attribute vec3 a_position;
attribute vec3 a_normal;
uniform mat4 u_mvp;
uniform mat4 u_model;
varying vec3 v_normal;
varying vec3 v_position;

void main() {
  gl_Position = u_mvp * vec4(a_position, 1.0);
  v_normal = mat3(u_model) * a_normal;
  v_position = (u_model * vec4(a_position, 1.0)).xyz;
}`;

const fragmentShaderSource = `
precision highp float;
uniform vec3 u_color;
uniform float u_emissive;
varying vec3 v_normal;
varying vec3 v_position;

void main() {
  vec3 normal = normalize(v_normal);
  vec3 keyLight = normalize(vec3(-0.48, 0.86, 0.38));
  vec3 fillLight = normalize(vec3(0.72, 0.38, 0.58));
  float key = max(dot(normal, keyLight), 0.0);
  float fill = max(dot(normal, fillLight), 0.0);
  float rim = pow(1.0 - max(dot(normal, normalize(vec3(0.0, 0.35, 1.0))), 0.0), 2.4);
  float topLift = max(normal.y, 0.0) * 0.16;
  float distanceFade = clamp(1.04 - length(v_position.xz) * 0.014, 0.82, 1.0);
  vec3 lit = u_color * (0.2 + key * 0.72 + fill * 0.18 + rim * 0.18 + topLift + u_emissive);
  lit *= distanceFade;
  gl_FragColor = vec4(pow(lit, vec3(0.92)), 1.0);
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
      powerPreference: "high-performance",
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

    const cubeVertices = createCubeVertices();
    const cylinderVertices = createCylinderVertices(40);
    const cubeBuffer = gl.createBuffer();
    const cylinderBuffer = gl.createBuffer();
    if (!cubeBuffer || !cylinderBuffer) {
      gl.deleteProgram(program);
      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);
      setAvailable(false);
      return;
    }

    gl.bindBuffer(gl.ARRAY_BUFFER, cubeBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, cubeVertices, gl.STATIC_DRAW);
    gl.bindBuffer(gl.ARRAY_BUFFER, cylinderBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, cylinderVertices, gl.STATIC_DRAW);
    gl.useProgram(program);

    const positionLocation = gl.getAttribLocation(program, "a_position");
    const normalLocation = gl.getAttribLocation(program, "a_normal");
    const mvpLocation = gl.getUniformLocation(program, "u_mvp");
    const modelLocation = gl.getUniformLocation(program, "u_model");
    const colorLocation = gl.getUniformLocation(program, "u_color");
    const emissiveLocation = gl.getUniformLocation(program, "u_emissive");
    const stride = 6 * Float32Array.BYTES_PER_ELEMENT;

    gl.enableVertexAttribArray(positionLocation);
    gl.enableVertexAttribArray(normalLocation);
    gl.enable(gl.DEPTH_TEST);
    gl.depthFunc(gl.LEQUAL);
    gl.enable(gl.CULL_FACE);
    gl.cullFace(gl.BACK);

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let animationFrame = 0;
    let visible = !document.hidden;
    let intersecting = true;
    let start = performance.now();
    let sceneKey = "";
    let scene: WebGLScene | null = null;
    const modelMatrices = new WeakMap<SceneBox, Float32Array>();
    const mvpScratch = new Float32Array(16);
    const lane = profileLanes[activeProfile] ?? profileLanes["passive-web"];

    const drawBox = (box: SceneBox, viewProjection: Float32Array) => {
      const isCylinder = box.geometry === "cylinder";
      gl.bindBuffer(gl.ARRAY_BUFFER, isCylinder ? cylinderBuffer : cubeBuffer);
      gl.vertexAttribPointer(positionLocation, 3, gl.FLOAT, false, stride, 0);
      gl.vertexAttribPointer(normalLocation, 3, gl.FLOAT, false, stride, 3 * Float32Array.BYTES_PER_ELEMENT);
      let model = modelMatrices.get(box);
      if (!model) {
        model = composeMatrix(box.position, box.rotation ?? [0, 0, 0], box.scale);
        modelMatrices.set(box, model);
      }
      multiplyMatricesInto(viewProjection, model, mvpScratch);
      gl.uniformMatrix4fv(mvpLocation, false, mvpScratch);
      gl.uniformMatrix4fv(modelLocation, false, model);
      gl.uniform3fv(colorLocation, box.color);
      gl.uniform1f(emissiveLocation, box.emissive ?? 0);
      gl.drawArrays(gl.TRIANGLES, 0, isCylinder ? cylinderVertices.length / 6 : cubeVertices.length / 6);
    };

    const render = (now: number) => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2.5);
      const width = Math.max(1, Math.floor(canvas.clientWidth * ratio));
      const height = Math.max(1, Math.floor(canvas.clientHeight * ratio));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        gl.viewport(0, 0, width, height);
      }

      const elapsed = reducedMotion.matches ? 1.25 : (now - start) / 1000;
      const pulse = 0.5 + Math.sin(elapsed * 2.15) * 0.5;
      const lightTheme = document.documentElement.dataset.theme === "light";
      const nextSceneKey = lightTheme ? "light" : "dark";
      if (!scene || sceneKey !== nextSceneKey) {
        scene = createWebGLScene(lane, currentStep, status, lightTheme);
        sceneKey = nextSceneKey;
      }
      const pointer = pointerRef.current;
      const aspect = width / height;
      const compactScene = aspect < 2;
      const camera: Vec3 = compactScene
        ? [pointer.x * 0.16, 5 + pointer.y * 0.12, 10.8]
        : [0.35 + pointer.x * 0.2, 4.25 + pointer.y * 0.14, 7.6];
      const projection = perspectiveMatrix(compactScene ? Math.PI / 4.2 : Math.PI / 7.2, aspect, 0.1, 40);
      const view = lookAtMatrix(camera, [0.45, -0.1, 0], [0, 1, 0]);
      const viewProjection = multiplyMatrices(projection, view);

      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
      for (const binding of scene.pulseBindings) {
        binding.box.emissive = binding.base + pulse * binding.amount;
      }
      for (const box of scene.boxes) drawBox(box, viewProjection);

      if (visible && intersecting && !reducedMotion.matches) {
        animationFrame = window.requestAnimationFrame(render);
      }
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      if (!visible || !intersecting) return;
      start = performance.now();
      render(start);
    };
    const handleVisibility = () => {
      visible = !document.hidden;
      if (visible && intersecting) restart();
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
    const intersectionObserver = "IntersectionObserver" in window
      ? new IntersectionObserver(([entry]) => {
          const nextIntersecting = entry.isIntersecting;
          if (nextIntersecting === intersecting) return;
          intersecting = nextIntersecting;
          if (intersecting && visible) restart();
          else window.cancelAnimationFrame(animationFrame);
        })
      : null;
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    intersectionObserver?.observe(field);
    reducedMotion.addEventListener("change", restart);
    window.addEventListener("resize", restart);
    document.addEventListener("visibilitychange", handleVisibility);
    field.addEventListener("pointermove", handlePointerMove);
    field.addEventListener("pointerleave", handlePointerLeave);
    render(start);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      themeObserver.disconnect();
      intersectionObserver?.disconnect();
      reducedMotion.removeEventListener("change", restart);
      window.removeEventListener("resize", restart);
      document.removeEventListener("visibilitychange", handleVisibility);
      field.removeEventListener("pointermove", handlePointerMove);
      field.removeEventListener("pointerleave", handlePointerLeave);
      gl.deleteBuffer(cubeBuffer);
      gl.deleteBuffer(cylinderBuffer);
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
        <span className="scopeNode scopeNodeWeb">Web target<small>Exact allowlist</small></span>
        <span className="scopeNode scopeNodeRepo">Local repository<small>Your code</small></span>
        <span className="scopeNode scopeNodePolicy">Policy gate<small>Rules enforced</small></span>
        <span className="scopeNode scopeNodeProfile">{profileLabels[activeProfile] ?? "Audit profile"}<small>{profileRouteLabel(activeProfile)}</small></span>
        <span className="scopeNode scopeNodeNormalize">Normalize + redact<small>Protect sensitive</small></span>
        <span className="scopeNode scopeNodeHarbor">Protected harbor<small>Your data. Your control.</small></span>
      </div>
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

function createCylinderVertices(segments: number) {
  const data: number[] = [];
  for (let index = 0; index < segments; index += 1) {
    const firstAngle = (index / segments) * Math.PI * 2;
    const secondAngle = ((index + 1) / segments) * Math.PI * 2;
    const firstX = Math.cos(firstAngle);
    const firstZ = Math.sin(firstAngle);
    const secondX = Math.cos(secondAngle);
    const secondZ = Math.sin(secondAngle);

    data.push(0, 1, 0, 0, 1, 0, firstX, 1, firstZ, 0, 1, 0, secondX, 1, secondZ, 0, 1, 0);
    data.push(0, -1, 0, 0, -1, 0, secondX, -1, secondZ, 0, -1, 0, firstX, -1, firstZ, 0, -1, 0);
    data.push(
      firstX, -1, firstZ, firstX, 0, firstZ,
      secondX, -1, secondZ, secondX, 0, secondZ,
      secondX, 1, secondZ, secondX, 0, secondZ,
      firstX, -1, firstZ, firstX, 0, firstZ,
      secondX, 1, secondZ, secondX, 0, secondZ,
      firstX, 1, firstZ, firstX, 0, firstZ
    );
  }
  return new Float32Array(data);
}

function profileRouteLabel(profileId: string) {
  if (profileId === "active-demo") return "Bounded active checks";
  if (profileId === "modern-web-crawl") return "Rendered route crawl";
  if (profileId === "repo") return "Offline repository scan";
  return "Observe only";
}

function createRouteArchitecture(points: Vec3[], edgeColor: Vec3, topColor: Vec3): SceneBox[] {
  const boxes: SceneBox[] = [];
  for (let segmentIndex = 0; segmentIndex < points.length - 1; segmentIndex += 1) {
    const start = points[segmentIndex];
    const end = points[segmentIndex + 1];
    const deltaX = end[0] - start[0];
    const deltaZ = end[2] - start[2];
    const distance = Math.hypot(deltaX, deltaZ);
    const tileCount = Math.max(3, Math.ceil(distance / 0.42));
    const angle = -Math.atan2(deltaZ, deltaX);
    const normalX = -deltaZ / distance;
    const normalZ = deltaX / distance;

    for (let tileIndex = 0; tileIndex < tileCount; tileIndex += 1) {
      const progress = (tileIndex + 0.5) / tileCount;
      const x = start[0] + deltaX * progress;
      const y = start[1] + (end[1] - start[1]) * progress;
      const z = start[2] + deltaZ * progress;
      const tileHalfLength = distance / tileCount / 2;
      boxes.push({
        position: [x, y, z],
        scale: [tileHalfLength * 0.96, 0.11, 0.29],
        rotation: [0, angle, 0],
        color: edgeColor
      });
      for (const side of [-1, 1]) {
        boxes.push({
          position: [x + normalX * 0.39 * side, y + 0.09, z + normalZ * 0.39 * side],
          scale: [Math.min(0.14, tileHalfLength * 0.74), 0.15, 0.11],
          rotation: [0, angle, 0],
          color: topColor
        });
      }
    }
  }
  return boxes;
}

function createWebGLScene(lane: number, currentStep: string | null, status: string, lightTheme: boolean): WebGLScene {
  const stage = stageForStep(currentStep, status);
  const warning = status === "completed_with_warnings" || status === "failed";
  const completed = status === "completed";
  const routeColor: Vec3 = warning ? [0.98, 0.29, 0.055] : [0.94, 0.19, 0.035];
  const activeColor: Vec3 = warning ? [1, 0.56, 0.14] : [1, 0.39, 0.08];
  const outcomeColor: Vec3 = completed ? [0.38, 0.78, 0.52] : warning ? [1, 0.56, 0.14] : activeColor;
  const structure: Vec3 = lightTheme ? [0.36, 0.4, 0.48] : [0.035, 0.052, 0.082];
  const structureTop: Vec3 = lightTheme ? [0.52, 0.56, 0.64] : [0.105, 0.135, 0.19];
  const structureEdge: Vec3 = lightTheme ? [0.26, 0.3, 0.38] : [0.065, 0.085, 0.125];
  const boxes: SceneBox[] = [
    { position: [-4.82, -0.42, -0.72], scale: [0.66, 0.13, 0.68], color: structureEdge },
    { position: [-3.45, -0.42, 0.58], scale: [0.66, 0.13, 0.68], color: structureEdge },
    { position: [-2.15, -0.39, -0.08], scale: [0.68, 0.17, 0.8], color: structureEdge },
    { position: [-0.35, -0.4, lane], scale: [0.76, 0.16, 0.74], color: structureEdge },
    { position: [1.5, -0.39, 0.03], scale: [0.72, 0.17, 0.76], color: structureEdge },
    { position: [4.18, -0.42, 0], scale: [1.68, 0.14, 1.68], color: structureEdge, geometry: "cylinder" },
    { position: [4.18, -0.22, 0], scale: [1.4, 0.055, 1.4], color: routeColor, emissive: 0.2, geometry: "cylinder" },
    { position: [4.18, -0.12, 0], scale: [1.08, 0.11, 1.08], color: structure, geometry: "cylinder" }
  ];
  const pulseBindings: PulseBinding[] = [];
  const routePoints: Vec3[] = [
    [-4.82, -0.34, -0.72],
    [-3.45, -0.34, 0.58],
    [-2.15, -0.31, -0.08],
    [-0.35, -0.32, lane],
    [1.5, -0.31, 0.03],
    [3.28, -0.34, 0]
  ];
  boxes.push(...createRouteArchitecture(routePoints, structureEdge, structureTop));

  const route: SceneBox[] = [
    { position: [-4.12, -0.12, -0.18], scale: [0.82, 0.035, 0.075], color: routeColor, rotation: [0, -0.5, 0] },
    { position: [-2.79, -0.11, 0.24], scale: [0.78, 0.04, 0.075], color: routeColor, rotation: [0, 0.35, 0] },
    { position: [-1.25, -0.1, lane * 0.5], scale: [0.95, 0.045, 0.075], color: routeColor, rotation: [0, lane * -0.22, 0] },
    { position: [0.58, -0.1, lane * 0.48], scale: [0.98, 0.045, 0.075], color: routeColor, rotation: [0, lane * 0.2, 0] },
    { position: [2.58, -0.1, 0], scale: [1.16, 0.045, 0.075], color: routeColor }
  ];
  route.forEach((box, index) => {
    const routeBed: SceneBox = {
      ...box,
      position: [box.position[0], box.position[1] - 0.07, box.position[2]],
      scale: [box.scale[0] * 1.02, box.scale[1] * 2.2, box.scale[2] * 2.3],
      color: structureTop
    };
    const routeSignal: SceneBox = {
      ...box,
      position: [box.position[0], box.position[1] + 0.055, box.position[2]],
      color: index <= stage ? activeColor : routeColor,
      emissive: index === stage ? 0.28 : 0.12
    };
    boxes.push(routeBed, routeSignal);
    if (index === stage) pulseBindings.push({ box: routeSignal, base: 0.28, amount: 0.22 });
  });

  const blocks: SceneBox[] = [
    { position: [-4.82, 0.02, -0.72], scale: [0.36, 0.4, 0.36], color: structureTop },
    { position: [-4.82, 0.48, -0.72], scale: [0.25, 0.055, 0.25], color: activeColor, emissive: 0.08 },
    { position: [-3.45, -0.02, 0.58], scale: [0.34, 0.31, 0.34], color: structureTop, geometry: "cylinder" },
    { position: [-3.45, 0.34, 0.58], scale: [0.37, 0.055, 0.37], color: structureEdge, geometry: "cylinder" },
    { position: [-2.42, 0.2, -0.08], scale: [0.16, 0.62, 0.5], color: stage === 1 ? activeColor : structureTop, emissive: 0 },
    { position: [-1.88, 0.2, -0.08], scale: [0.16, 0.62, 0.5], color: stage === 1 ? activeColor : structureTop, emissive: 0 },
    { position: [-2.15, 0.2, -0.08], scale: [0.16, 0.38, 0.28], color: activeColor, emissive: 0.09 },
    { position: [-0.35, 0.11, lane], scale: [0.42, 0.48, 0.42], color: stage === 2 ? activeColor : structureTop, emissive: 0 },
    { position: [1.5, 0.08, 0.03], scale: [0.38, 0.47, 0.4], color: stage === 3 ? activeColor : structureTop, emissive: 0 },
    { position: [4.18, 0.49, 0], scale: [0.88, 0.68, 0.88], color: structureTop, geometry: "cylinder" },
    { position: [4.18, 1.18, 0], scale: [0.94, 0.11, 0.94], color: structureEdge, geometry: "cylinder" },
    { position: [4.18, 1.27, 0], scale: [0.52, 0.085, 0.52], color: stage >= 4 ? outcomeColor : routeColor, emissive: 0.15, geometry: "cylinder" },
    { position: [4.18, 0.52, -0.86], scale: [0.2, 0.31, 0.065], color: stage >= 4 ? outcomeColor : routeColor, emissive: 0.12 },
    { position: [3.42, 0.28, 0.54], scale: [0.16, 0.5, 0.16], color: structureTop, geometry: "cylinder" },
    { position: [4.92, 0.28, 0.54], scale: [0.16, 0.5, 0.16], color: structureTop, geometry: "cylinder" }
  ];
  boxes.push(...blocks);
  if (stage === 1) {
    pulseBindings.push({ box: blocks[4], base: 0, amount: 0.16 }, { box: blocks[5], base: 0, amount: 0.16 });
  }
  if (stage === 2) pulseBindings.push({ box: blocks[7], base: 0, amount: 0.18 });
  if (stage === 3) pulseBindings.push({ box: blocks[8], base: 0, amount: 0.18 });
  pulseBindings.push({ box: blocks[11], base: 0.15, amount: 0.12 });

  const terrainPositions: Array<[number, number]> = [
    [-3.9, -1.45], [-2.82, -1.02], [-1.35, -1.5], [0.65, -1.28], [2.32, -1.08], [4.98, -1.42], [2.9, 1.18], [-1.0, 1.32]
  ];
  boxes.push(...terrainPositions.map(([x, z], index) => ({
    position: [x, -0.48, z] as Vec3,
    scale: [0.09 + (index % 3) * 0.035, 0.07 + (index % 2) * 0.025, 0.08 + (index % 4) * 0.02] as Vec3,
    rotation: [0, index * 0.53, 0] as Vec3,
    color: structureEdge
  })));

  return { boxes, pulseBindings };
}

function composeMatrix(position: Vec3, rotation: Vec3, scale: Vec3) {
  return multiplyMatrices(
    translationMatrix(...position),
    multiplyMatrices(rotationYMatrix(rotation[1]), multiplyMatrices(rotationXMatrix(rotation[0]), scalingMatrix(...scale)))
  );
}

function multiplyMatrices(left: Float32Array, right: Float32Array) {
  const result = new Float32Array(16);
  return multiplyMatricesInto(left, right, result);
}

function multiplyMatricesInto(left: Float32Array, right: Float32Array, result: Float32Array) {
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
