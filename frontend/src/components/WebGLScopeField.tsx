"use client";

import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { RoomEnvironment } from "three/addons/environments/RoomEnvironment.js";

import { AppIcon } from "@/components/AppIcon";

type WebGLScopeFieldProps = {
  activeProfile?: string;
  currentStep?: string | null;
  status?: string;
};

const profileTilt: Record<string, number> = {
  "passive-web": -0.035,
  "active-demo": 0.025,
  "modern-web-crawl": 0.045,
  repository: -0.015
};

export function WebGLScopeField({
  activeProfile = "passive-web",
  currentStep = null,
  status = "ready"
}: WebGLScopeFieldProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const fieldRef = useRef<HTMLElement>(null);
  const pointerRef = useRef({ x: 0, y: 0 });
  const stateRef = useRef({ activeProfile, currentStep, status });
  const [available, setAvailable] = useState(true);

  useEffect(() => {
    stateRef.current = { activeProfile, currentStep, status };
  }, [activeProfile, currentStep, status]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const field = fieldRef.current;
    if (!canvas || !field) return;

    const contextAttributes: WebGLContextAttributes = {
      alpha: true,
      antialias: true,
      powerPreference: "high-performance",
      premultipliedAlpha: true
    };
    const context = canvas.getContext("webgl2", contextAttributes) ?? canvas.getContext("webgl", contextAttributes);
    if (!context) {
      window.setTimeout(() => setAvailable(false), 0);
      return;
    }

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        canvas,
        context,
        alpha: true,
        antialias: true,
        powerPreference: "high-performance",
        premultipliedAlpha: true
      });
    } catch {
      window.setTimeout(() => setAvailable(false), 0);
      return;
    }

    renderer.setClearColor(0x000000, 0);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.06;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 30);
    camera.position.set(0.15, 0.12, 7.4);

    const environmentScene = new RoomEnvironment();
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    const environmentTarget = pmremGenerator.fromScene(environmentScene, 0.04);
    scene.environment = environmentTarget.texture;
    environmentScene.dispose();
    pmremGenerator.dispose();

    const composition = createShieldComposition();
    scene.add(composition.root);

    const ambient = new THREE.HemisphereLight(0xdde8ff, 0x080711, 1.35);
    const key = new THREE.DirectionalLight(0xf4f6ff, 3.5);
    key.position.set(-3.2, 4.8, 5.5);
    const rim = new THREE.PointLight(0xff6a2b, 22, 8, 1.8);
    rim.position.set(2.6, 0.3, 2.7);
    const edge = new THREE.PointLight(0xffa24c, 12, 6, 2);
    edge.position.set(0.4, -1.6, 1.2);
    scene.add(ambient, key, rim, edge);

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0;
    let visible = !document.hidden;
    let intersecting = true;
    let width = 1;
    let height = 1;
    let start = performance.now();

    const resize = () => {
      const nextWidth = Math.max(1, Math.floor(field.clientWidth));
      const nextHeight = Math.max(1, Math.floor(field.clientHeight));
      if (nextWidth === width && nextHeight === height) return;
      width = nextWidth;
      height = nextHeight;
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      composition.root.scale.setScalar(camera.aspect < 2 ? 0.82 : 1);
      composition.root.position.x = camera.aspect < 2 ? 0.36 : 0.18;
    };

    const updateTheme = () => {
      const lightTheme = document.documentElement.dataset.theme === "light";
      composition.outerMaterial.color.set(lightTheme ? 0x596173 : 0x252936);
      composition.innerMaterial.color.set(lightTheme ? 0x3a251f : 0x171313);
      composition.networkMaterial.color.set(lightTheme ? 0xb24d23 : 0xdf642d);
      composition.pointMaterial.color.set(lightTheme ? 0xb65b32 : 0xffb16f);
      renderer.toneMappingExposure = lightTheme ? 0.96 : 1.06;
    };

    const render = (now: number) => {
      const elapsed = reducedMotion.matches ? 1.4 : (now - start) / 1000;
      const pointer = pointerRef.current;
      const heroState = stateRef.current;
      const idleYaw = profileTilt[heroState.activeProfile] ?? 0;

      composition.shield.rotation.y = idleYaw + pointer.x * 0.085 + Math.sin(elapsed * 0.42) * 0.018;
      composition.shield.rotation.x = -0.025 - pointer.y * 0.045 + Math.sin(elapsed * 0.35) * 0.008;
      composition.shield.position.y = Math.sin(elapsed * 0.72) * 0.025;
      composition.emblem.rotation.z = Math.sin(elapsed * 0.3) * 0.025;
      composition.network.rotation.y = pointer.x * 0.018;
      composition.network.position.y = pointer.y * -0.025;
      composition.glowMaterial.opacity = 0.08 + Math.sin(elapsed * 0.9) * 0.018;
      composition.emblemMaterial.emissiveIntensity =
        heroState.status === "running" || heroState.currentStep ? 2.25 + Math.sin(elapsed * 1.3) * 0.18 : 2.05;

      renderer.render(scene, camera);
      if (visible && intersecting && !reducedMotion.matches) {
        frame = window.requestAnimationFrame(render);
      }
    };

    const restart = () => {
      window.cancelAnimationFrame(frame);
      if (!visible || !intersecting) return;
      start = performance.now();
      render(start);
    };
    const handleResize = () => {
      resize();
      restart();
    };
    const handleThemeChange = () => {
      updateTheme();
      restart();
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
    const handleVisibility = () => {
      visible = !document.hidden;
      if (visible && intersecting) restart();
      else window.cancelAnimationFrame(frame);
    };
    const handleContextLost = (event: Event) => {
      event.preventDefault();
      setAvailable(false);
    };

    const resizeObserver = new ResizeObserver(handleResize);
    const themeObserver = new MutationObserver(handleThemeChange);
    const intersectionObserver = new IntersectionObserver(([entry]) => {
      intersecting = entry.isIntersecting;
      if (intersecting && visible) restart();
      else window.cancelAnimationFrame(frame);
    });

    resizeObserver.observe(field);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    intersectionObserver.observe(field);
    reducedMotion.addEventListener("change", restart);
    document.addEventListener("visibilitychange", handleVisibility);
    field.addEventListener("pointermove", handlePointerMove);
    field.addEventListener("pointerleave", handlePointerLeave);
    canvas.addEventListener("webglcontextlost", handleContextLost);
    resize();
    updateTheme();
    render(start);

    return () => {
      window.cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      themeObserver.disconnect();
      intersectionObserver.disconnect();
      reducedMotion.removeEventListener("change", restart);
      document.removeEventListener("visibilitychange", handleVisibility);
      field.removeEventListener("pointermove", handlePointerMove);
      field.removeEventListener("pointerleave", handlePointerLeave);
      canvas.removeEventListener("webglcontextlost", handleContextLost);
      composition.root.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.LineSegments || object instanceof THREE.Points) {
          object.geometry.dispose();
          const materials = Array.isArray(object.material) ? object.material : [object.material];
          materials.forEach((material) => material.dispose());
        }
      });
      environmentTarget.dispose();
      renderer.dispose();
      renderer.forceContextLoss();
    };
  }, []);

  return (
    <figure
      ref={fieldRef}
      className={available ? "scopeField" : "scopeField scopeFieldFallback"}
      aria-label="Faceted shield protecting a local application security network"
    >
      <canvas ref={canvasRef} aria-hidden="true" />
      {!available ? (
        <div className="scopeShieldFallback" aria-hidden="true">
          <AppIcon name="shield" size={92} />
        </div>
      ) : null}
    </figure>
  );
}

function createShieldComposition() {
  const root = new THREE.Group();
  root.position.set(0.18, 0, 0);

  const network = createNetworkMesh();
  network.position.set(-0.75, 0.02, -0.7);
  root.add(network);

  const shield = new THREE.Group();
  shield.position.set(2.05, 0, 0);
  shield.rotation.set(-0.025, profileTilt["passive-web"], -0.025);
  root.add(shield);

  const outerMaterial = new THREE.MeshPhysicalMaterial({
    color: 0x252936,
    metalness: 0.92,
    roughness: 0.2,
    clearcoat: 0.48,
    clearcoatRoughness: 0.16,
    envMapIntensity: 1.35
  });
  const innerMaterial = new THREE.MeshPhysicalMaterial({
    color: 0x12131f,
    emissive: 0x57200f,
    emissiveIntensity: 0.7,
    metalness: 0.78,
    roughness: 0.18,
    clearcoat: 0.62,
    clearcoatRoughness: 0.14,
    envMapIntensity: 1.2
  });
  const edgeMaterial = new THREE.LineBasicMaterial({
    color: 0x7f899e,
    transparent: true,
    opacity: 0.38
  });
  const glowMaterial = new THREE.MeshBasicMaterial({
    color: 0xff6a2b,
    transparent: true,
    opacity: 0.08,
    depthWrite: false,
    side: THREE.DoubleSide
  });

  const outerGeometry = new THREE.ExtrudeGeometry(createShieldShape(1.28, 1.54), {
    depth: 0.34,
    steps: 1,
    bevelEnabled: true,
    bevelSegments: 5,
    bevelSize: 0.11,
    bevelThickness: 0.11
  });
  outerGeometry.center();
  const outerShield = new THREE.Mesh(outerGeometry, outerMaterial);
  shield.add(outerShield);

  const outerEdges = new THREE.LineSegments(new THREE.EdgesGeometry(outerGeometry, 24), edgeMaterial);
  outerEdges.position.z = 0.01;
  shield.add(outerEdges);

  const innerGeometry = new THREE.ExtrudeGeometry(createShieldShape(0.88, 1.06), {
    depth: 0.19,
    steps: 1,
    bevelEnabled: true,
    bevelSegments: 4,
    bevelSize: 0.07,
    bevelThickness: 0.07
  });
  innerGeometry.center();
  const innerShield = new THREE.Mesh(innerGeometry, innerMaterial);
  innerShield.position.z = 0.31;
  shield.add(innerShield);

  const innerEdges = new THREE.LineSegments(new THREE.EdgesGeometry(innerGeometry, 22), edgeMaterial.clone());
  innerEdges.position.z = 0.325;
  shield.add(innerEdges);

  const glowGeometry = new THREE.ShapeGeometry(createShieldShape(1.48, 1.78));
  glowGeometry.center();
  const glow = new THREE.Mesh(glowGeometry, glowMaterial);
  glow.position.z = -0.24;
  shield.add(glow);

  const emblem = new THREE.Group();
  emblem.position.z = 0.54;
  shield.add(emblem);

  const emblemMaterial = new THREE.MeshPhysicalMaterial({
    color: 0xffa455,
    emissive: 0xff5b21,
    emissiveIntensity: 2.05,
    metalness: 0.18,
    roughness: 0.14,
    clearcoat: 0.72,
    clearcoatRoughness: 0.12,
    envMapIntensity: 1.1
  });
  const emblemGeometry = new THREE.CylinderGeometry(0.205, 0.205, 0.12, 6, 1, false);
  const emblemPoints: Array<[number, number, number]> = [
    [0, 0.28, 0],
    [-0.24, -0.02, 0],
    [0.24, -0.02, 0],
    [0, -0.32, 0]
  ];
  for (const [x, y, z] of emblemPoints) {
    const cell = new THREE.Mesh(emblemGeometry, emblemMaterial);
    cell.rotation.x = Math.PI / 2;
    cell.position.set(x, y, z);
    emblem.add(cell);
  }

  const coreLight = new THREE.PointLight(0xff6a2b, 18, 4.5, 2);
  coreLight.position.set(0, 0, 1.05);
  shield.add(coreLight);

  return {
    root,
    shield,
    network,
    emblem,
    outerMaterial,
    innerMaterial,
    edgeMaterial,
    glowMaterial,
    emblemMaterial,
    networkMaterial: network.userData.lineMaterial as THREE.LineBasicMaterial,
    pointMaterial: network.userData.pointMaterial as THREE.MeshStandardMaterial
  };
}

function createShieldShape(width: number, height: number) {
  const shape = new THREE.Shape();
  shape.moveTo(0, height);
  shape.lineTo(width, height * 0.67);
  shape.lineTo(width * 0.9, -height * 0.26);
  shape.lineTo(width * 0.48, -height * 0.76);
  shape.lineTo(0, -height);
  shape.lineTo(-width * 0.48, -height * 0.76);
  shape.lineTo(-width * 0.9, -height * 0.26);
  shape.lineTo(-width, height * 0.67);
  shape.closePath();
  return shape;
}

function createNetworkMesh() {
  const group = new THREE.Group();
  const points = [
    [-3.65, 0.64, -0.1], [-3.2, 0.98, 0.06], [-2.75, 0.55, -0.02], [-2.2, 0.92, 0.08],
    [-1.65, 0.5, -0.06], [-1.1, 0.82, 0.03], [-0.55, 0.46, -0.08], [0, 0.72, 0.02],
    [0.55, 0.38, -0.04], [1.05, 0.62, 0.04], [-3.48, 0.02, 0.05], [-2.94, 0.18, -0.08],
    [-2.42, -0.14, 0.04], [-1.9, 0.12, -0.05], [-1.36, -0.18, 0.05], [-0.82, 0.08, -0.07],
    [-0.28, -0.22, 0.04], [0.28, 0.04, -0.06], [0.78, -0.16, 0.04], [1.22, 0.04, -0.02],
    [-3.18, -0.55, -0.04], [-2.62, -0.42, 0.04], [-2.08, -0.65, -0.05], [-1.5, -0.46, 0.04],
    [-0.92, -0.72, -0.04], [-0.36, -0.5, 0.04], [0.2, -0.7, -0.04], [0.74, -0.48, 0.04],
    [1.18, -0.58, -0.02]
  ].map(([x, y, z]) => new THREE.Vector3(x, y, z));
  const connections: Array<[number, number]> = [
    [0, 1], [0, 10], [0, 11], [1, 2], [1, 11], [2, 3], [2, 11], [2, 12],
    [3, 4], [3, 13], [4, 5], [4, 13], [4, 14], [5, 6], [5, 15], [6, 7],
    [6, 15], [6, 16], [7, 8], [7, 17], [8, 9], [8, 17], [8, 18], [9, 19],
    [10, 11], [10, 20], [11, 12], [11, 20], [11, 21], [12, 13], [12, 21], [12, 22],
    [13, 14], [13, 22], [13, 23], [14, 15], [14, 23], [14, 24], [15, 16],
    [15, 24], [15, 25], [16, 17], [16, 25], [16, 26], [17, 18], [17, 26],
    [17, 27], [18, 19], [18, 27], [18, 28], [19, 28], [20, 21], [21, 22],
    [22, 23], [23, 24], [24, 25], [25, 26], [26, 27], [27, 28]
  ];
  const linePositions: number[] = [];
  for (const [start, end] of connections) {
    linePositions.push(...points[start].toArray(), ...points[end].toArray());
  }
  const lineGeometry = new THREE.BufferGeometry();
  lineGeometry.setAttribute("position", new THREE.Float32BufferAttribute(linePositions, 3));
  const lineMaterial = new THREE.LineBasicMaterial({
    color: 0xdf642d,
    transparent: true,
    opacity: 0.34,
    depthWrite: false
  });
  group.add(new THREE.LineSegments(lineGeometry, lineMaterial));

  const pointGeometry = new THREE.SphereGeometry(0.055, 12, 8);
  const pointMaterial = new THREE.MeshStandardMaterial({
    color: 0xffb16f,
    emissive: 0x8c3518,
    emissiveIntensity: 0.32,
    metalness: 0.72,
    roughness: 0.28,
    envMapIntensity: 0.85
  });
  const nodes = new THREE.InstancedMesh(pointGeometry, pointMaterial, points.length);
  const transform = new THREE.Object3D();
  points.forEach((point, index) => {
    transform.position.copy(point);
    transform.updateMatrix();
    nodes.setMatrixAt(index, transform.matrix);
  });
  nodes.instanceMatrix.needsUpdate = true;
  group.add(nodes);
  group.userData.lineMaterial = lineMaterial;
  group.userData.pointMaterial = pointMaterial;
  return group;
}
