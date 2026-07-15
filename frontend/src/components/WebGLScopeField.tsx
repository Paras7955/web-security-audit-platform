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
  geometry?: "cube" | "cylinder" | "octahedron";
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
  vec3 viewDirection = normalize(vec3(0.0, 0.34, 1.0));
  vec3 halfDirection = normalize(keyLight + viewDirection);
  float key = max(dot(normal, keyLight), 0.0);
  float fill = max(dot(normal, fillLight), 0.0);
  float specular = pow(max(dot(normal, halfDirection), 0.0), 30.0);
  float rim = pow(1.0 - max(dot(normal, viewDirection), 0.0), 2.4);
  float topLift = max(normal.y, 0.0) * 0.16;
  float distanceFade = clamp(1.04 - length(v_position.xz) * 0.014, 0.82, 1.0);
  vec3 lit = u_color * (0.18 + key * 0.7 + fill * 0.2 + rim * 0.2 + topLift + u_emissive);
  lit += vec3(1.0, 0.82, 0.68) * specular * 0.2;
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
    const cylinderVertices = createCylinderVertices(48);
    const octahedronVertices = createOctahedronVertices();
    const cubeBuffer = gl.createBuffer();
    const cylinderBuffer = gl.createBuffer();
    const octahedronBuffer = gl.createBuffer();
    if (!cubeBuffer || !cylinderBuffer || !octahedronBuffer) {
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
    gl.bindBuffer(gl.ARRAY_BUFFER, octahedronBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, octahedronVertices, gl.STATIC_DRAW);
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
      const isOctahedron = box.geometry === "octahedron";
      gl.bindBuffer(gl.ARRAY_BUFFER, isCylinder ? cylinderBuffer : isOctahedron ? octahedronBuffer : cubeBuffer);
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
      const vertexCount = isCylinder ? cylinderVertices.length / 6 : isOctahedron ? octahedronVertices.length / 6 : cubeVertices.length / 6;
      gl.drawArrays(gl.TRIANGLES, 0, vertexCount);
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
        ? [pointer.x * 0.14, 3.8 + pointer.y * 0.1, 10.6]
        : [0.18 + pointer.x * 0.18, 3.15 + pointer.y * 0.12, 8.2];
      const projection = perspectiveMatrix(compactScene ? Math.PI / 4.4 : Math.PI / 8.5, aspect, 0.1, 40);
      const view = lookAtMatrix(camera, [0.1, 0.26, 0], [0, 1, 0]);
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
      gl.deleteBuffer(octahedronBuffer);
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

function createOctahedronVertices() {
  const data: number[] = [];
  const vertices: Vec3[] = [
    [0, 1, 0],
    [1, 0, 0],
    [0, 0, 1],
    [-1, 0, 0],
    [0, 0, -1],
    [0, -1, 0]
  ];
  const faces: Array<[number, number, number]> = [
    [0, 2, 1], [0, 3, 2], [0, 4, 3], [0, 1, 4],
    [5, 1, 2], [5, 2, 3], [5, 3, 4], [5, 4, 1]
  ];
  for (const [firstIndex, secondIndex, thirdIndex] of faces) {
    const first = vertices[firstIndex];
    const second = vertices[secondIndex];
    const third = vertices[thirdIndex];
    const normal = normalize(cross(
      [second[0] - first[0], second[1] - first[1], second[2] - first[2]],
      [third[0] - first[0], third[1] - first[1], third[2] - first[2]]
    ));
    data.push(...first, ...normal, ...second, ...normal, ...third, ...normal);
  }
  return new Float32Array(data);
}

function profileRouteLabel(profileId: string) {
  if (profileId === "active-demo") return "Bounded active checks";
  if (profileId === "modern-web-crawl") return "Rendered route crawl";
  if (profileId === "repo") return "Offline repository scan";
  return "Observe only";
}

function createRouteTube(start: Vec3, end: Vec3, radius: number, color: Vec3, emissive = 0): SceneBox {
  const deltaX = end[0] - start[0];
  const deltaZ = end[2] - start[2];
  const distance = Math.hypot(deltaX, deltaZ);
  return {
    position: [(start[0] + end[0]) / 2, (start[1] + end[1]) / 2, (start[2] + end[2]) / 2],
    scale: [radius, distance / 2, radius],
    rotation: [0, -Math.atan2(deltaZ, deltaX), -Math.PI / 2],
    color,
    emissive,
    geometry: "cylinder"
  };
}

function createRoute(points: Vec3[], radius: number, color: Vec3, emissive = 0): SceneBox[] {
  return points.slice(0, -1).map((point, index) => createRouteTube(point, points[index + 1], radius, color, emissive));
}

function createShieldBeam(start: [number, number], end: [number, number], z: number, thickness: number, color: Vec3, emissive = 0): SceneBox {
  const deltaX = end[0] - start[0];
  const deltaY = end[1] - start[1];
  return {
    position: [(start[0] + end[0]) / 2, (start[1] + end[1]) / 2, z],
    scale: [Math.hypot(deltaX, deltaY) / 2, thickness, thickness],
    rotation: [0, 0, Math.atan2(deltaY, deltaX)],
    color,
    emissive
  };
}

function createWebGLScene(lane: number, currentStep: string | null, status: string, lightTheme: boolean): WebGLScene {
  const stage = stageForStep(currentStep, status);
  const warning = status === "completed_with_warnings" || status === "failed";
  const completed = status === "completed";
  const orange: Vec3 = warning ? [1, 0.48, 0.08] : [1, 0.28, 0.035];
  const orangeBright: Vec3 = warning ? [1, 0.66, 0.16] : [1, 0.48, 0.09];
  const blue: Vec3 = lightTheme ? [0.08, 0.42, 0.9] : [0.11, 0.54, 1];
  const yellow: Vec3 = lightTheme ? [0.85, 0.52, 0.04] : [1, 0.72, 0.12];
  const outcomeColor: Vec3 = completed ? [0.28, 0.78, 0.5] : warning ? yellow : orangeBright;
  const structure: Vec3 = lightTheme ? [0.33, 0.38, 0.48] : [0.035, 0.055, 0.09];
  const structureTop: Vec3 = lightTheme ? [0.55, 0.6, 0.69] : [0.12, 0.16, 0.23];
  const boxes: SceneBox[] = [];
  const pulseBindings: PulseBinding[] = [];
  const routePoints: Vec3[] = [
    [-4.45, -0.04, -0.72],
    [-3.25, 0.02, 0.5],
    [-2.03, 0.05, -0.08],
    [-0.55, 0.08, lane],
    [0.92, 0.11, 0.18],
    [2.52, 0.14, 0]
  ];

  boxes.push(...createRoute(routePoints, 0.13, structure));
  const orangeRoute = createRoute(routePoints, 0.052, orange, 0.16);
  boxes.push(...orangeRoute);
  const bluePoints = routePoints.map((point, index) => [point[0], point[1] + 0.11, point[2] + 0.42 * (1 - index / (routePoints.length - 1))] as Vec3);
  const yellowPoints = routePoints.map((point, index) => [point[0], point[1] + 0.06, point[2] - 0.42 * (1 - index / (routePoints.length - 1))] as Vec3);
  boxes.push(...createRoute(bluePoints, 0.026, blue, 0.12));
  boxes.push(...createRoute(yellowPoints, 0.022, yellow, 0.12));

  routePoints.slice(0, -1).forEach((point, index) => {
    const active = index <= stage;
    const node: SceneBox = {
      position: [point[0], point[1] + 0.16, point[2]],
      scale: index === 2 ? [0.3, 0.42, 0.3] : [0.23, 0.31, 0.23],
      rotation: [0, index * 0.58, 0],
      color: active ? orangeBright : structureTop,
      emissive: index === stage ? 0.28 : active ? 0.1 : 0,
      geometry: "octahedron"
    };
    boxes.push(node);
    if (index === stage) pulseBindings.push({ box: node, base: 0.28, amount: 0.22 });

    const blueSatellite: Vec3 = [bluePoints[index][0], bluePoints[index][1] + 0.13, bluePoints[index][2]];
    const yellowSatellite: Vec3 = [yellowPoints[index][0], yellowPoints[index][1] + 0.11, yellowPoints[index][2]];
    boxes.push(
      { position: blueSatellite, scale: [0.095, 0.13, 0.095], color: blue, emissive: 0.12, geometry: "octahedron" },
      { position: yellowSatellite, scale: [0.075, 0.1, 0.075], color: yellow, emissive: 0.1, geometry: "octahedron" },
      createRouteTube([point[0], point[1] + 0.08, point[2]], blueSatellite, 0.012, blue, 0.08),
      createRouteTube([point[0], point[1] + 0.07, point[2]], yellowSatellite, 0.01, yellow, 0.08)
    );
  });

  const shieldPoints: Array<[number, number]> = [
    [3.82, 1.7],
    [4.55, 1.34],
    [4.43, 0.36],
    [3.82, -0.28],
    [3.21, 0.36],
    [3.09, 1.34]
  ];
  for (let index = 0; index < shieldPoints.length; index += 1) {
    const next = shieldPoints[(index + 1) % shieldPoints.length];
    boxes.push(
      createShieldBeam(shieldPoints[index], next, 0.08, 0.12, structure),
      createShieldBeam(shieldPoints[index], next, -0.02, 0.047, stage >= 4 ? outcomeColor : orange, stage >= 4 ? 0.2 : 0.12)
    );
  }
  boxes.push(
    createShieldBeam([2.52, 0.14], [3.82, 0.71], -0.01, 0.055, orangeBright, 0.18),
    createShieldBeam([3.82, 0.1], [3.82, 1.27], 0, 0.038, blue, 0.12),
    createShieldBeam([3.48, 0.7], [4.16, 0.7], -0.025, 0.034, yellow, 0.12)
  );
  const shieldCore: SceneBox = {
    position: [3.82, 0.7, -0.08],
    scale: [0.31, 0.43, 0.22],
    rotation: [0, Math.PI / 4, 0],
    color: stage >= 4 ? outcomeColor : orangeBright,
    emissive: 0.26,
    geometry: "octahedron"
  };
  boxes.push(shieldCore);
  pulseBindings.push({ box: shieldCore, base: 0.26, amount: 0.18 });

  const constellation: Array<[Vec3, Vec3]> = [
    [[-3.8, -0.28, -1.45], blue],
    [[-2.55, -0.34, 1.32], yellow],
    [[-1.08, -0.3, -1.27], structureTop],
    [[0.42, -0.31, 1.18], blue],
    [[1.76, -0.3, -1.05], yellow],
    [[2.72, -0.2, 0.94], structureTop]
  ];
  boxes.push(...constellation.map(([position, color], index) => ({
    position,
    scale: [0.055 + (index % 2) * 0.025, 0.08 + (index % 3) * 0.018, 0.055 + (index % 2) * 0.025] as Vec3,
    rotation: [0, index * 0.73, 0] as Vec3,
    color,
    emissive: color === structureTop ? 0 : 0.08,
    geometry: "octahedron" as const
  })));

  return { boxes, pulseBindings };
}

function composeMatrix(position: Vec3, rotation: Vec3, scale: Vec3) {
  return multiplyMatrices(
    translationMatrix(...position),
    multiplyMatrices(
      rotationYMatrix(rotation[1]),
      multiplyMatrices(rotationZMatrix(rotation[2]), multiplyMatrices(rotationXMatrix(rotation[0]), scalingMatrix(...scale)))
    )
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

function rotationZMatrix(angle: number) {
  const cosine = Math.cos(angle);
  const sine = Math.sin(angle);
  return new Float32Array([cosine, sine, 0, 0, -sine, cosine, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]);
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
