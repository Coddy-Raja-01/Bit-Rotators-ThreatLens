// 3D Redirect Path Visualizer (Three.js Bundled Locally)
// Design Rules: Flat-colored materials only, no gradients, no glows.
// Visualizes hop-by-hop spatial navigation with status and domain transitions.

export function renderRedirectPath3D(containerEl, redirectData) {
  if (!containerEl) return;
  containerEl.innerHTML = "";

  const hops = redirectData.hops || [];
  if (hops.length === 0) {
    containerEl.innerHTML = "<p style='color:#666; font-size:13px;'>No redirects recorded. Direct connection established.</p>";
    return;
  }

  // Check WebGL availability
  const hasWebGL = (() => {
    try {
      const canvas = document.createElement("canvas");
      return !!(window.WebGLRenderingContext && (canvas.getContext("webgl") || canvas.getContext("experimental-webgl")));
    } catch (e) {
      return false;
    }
  })();

  if (!hasWebGL || !window.THREE) {
    render2DFallback(containerEl, hops, "WebGL unavailable in browser; showing accessible 2D redirect table.");
    return;
  }

  const wrapper = document.createElement("div");
  wrapper.className = "viewport-3d-wrapper";

  const controlsBar = document.createElement("div");
  controlsBar.className = "viewport-overlay-controls";

  const toggleBtn = document.createElement("button");
  toggleBtn.className = "btn-secondary";
  toggleBtn.style.padding = "4px 8px";
  toggleBtn.style.fontSize = "11px";
  toggleBtn.textContent = "Switch to 2D Table View";

  const resetViewBtn = document.createElement("button");
  resetViewBtn.className = "btn-secondary";
  resetViewBtn.style.padding = "4px 8px";
  resetViewBtn.style.fontSize = "11px";
  resetViewBtn.textContent = "Reset View";

  controlsBar.appendChild(resetViewBtn);
  controlsBar.appendChild(toggleBtn);
  wrapper.appendChild(controlsBar);

  const legend = document.createElement("div");
  legend.className = "viewport-legend";
  legend.innerHTML = `
    <span class="legend-chip"><span class="chip-color" style="background:#2a5d91"></span> Initial Hop</span>
    <span class="legend-chip"><span class="chip-color" style="background:#475569"></span> Intermediate / Final</span>
    <span class="legend-chip"><span class="chip-color" style="background:#c27803"></span> Cross-Domain</span>
    <span class="legend-chip"><span class="chip-color" style="background:#b02a2a"></span> Downgrade / Error</span>
  `;
  wrapper.appendChild(legend);

  const canvasContainer = document.createElement("div");
  canvasContainer.style.width = "100%";
  canvasContainer.style.height = "100%";
  wrapper.appendChild(canvasContainer);

  const fallbackContainer = document.createElement("div");
  fallbackContainer.style.display = "none";
  render2DFallback(fallbackContainer, hops);

  containerEl.appendChild(wrapper);
  containerEl.appendChild(fallbackContainer);

  let is2D = false;
  toggleBtn.addEventListener("click", () => {
    is2D = !is2D;
    if (is2D) {
      wrapper.style.display = "none";
      fallbackContainer.style.display = "block";
      toggleBtn.textContent = "Switch to 3D View";
    } else {
      wrapper.style.display = "block";
      fallbackContainer.style.display = "none";
      toggleBtn.textContent = "Switch to 2D Table View";
    }
  });

  const width = containerEl.clientWidth || 800;
  const height = 380;

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0xf6f6f4);

  const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
  camera.position.set(0, 6, 16);

  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setSize(width, height);
  renderer.setPixelRatio(window.devicePixelRatio || 1);
  canvasContainer.appendChild(renderer.domElement);

  const ambientLight = new THREE.AmbientLight(0xffffff, 0.85);
  scene.add(ambientLight);

  const dirLight = new THREE.DirectionalLight(0xffffff, 0.4);
  dirLight.position.set(5, 12, 8);
  scene.add(dirLight);

  const pathGroup = new THREE.Group();
  scene.add(pathGroup);

  const spacing = 4.5;
  const startX = -((hops.length - 1) * spacing) / 2;

  const points = [];

  hops.forEach((hop, idx) => {
    const xPos = startX + idx * spacing;
    const yPos = (idx % 2 === 1) ? 1.0 : -0.5;
    const zPos = 0;
    points.push(new THREE.Vector3(xPos, yPos, zPos));

    let colorHex = 0x475569; // Normal Slate
    if (idx === 0) colorHex = 0x2a5d91; // Initial hop
    if (hop.flag === "cross_domain") colorHex = 0xc27803; // Amber
    if (hop.flag === "ssl_downgrade" || hop.flag === "ssl_error" || hop.flag === "blocked" || hop.flag === "error") {
      colorHex = 0xb02a2a; // Red
    }

    // Node Sphere / Box
    const nodeGeo = new THREE.CylinderGeometry(0.8, 0.8, 0.5, 16);
    const nodeMat = new THREE.MeshLambertMaterial({ color: colorHex });
    const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
    nodeMesh.position.set(xPos, yPos, zPos);
    pathGroup.add(nodeMesh);

    // Outline
    const edgeGeo = new THREE.EdgesGeometry(nodeGeo);
    const edgeMat = new THREE.LineBasicMaterial({ color: 0x111111 });
    const edgeMesh = new THREE.LineSegments(edgeGeo, edgeMat);
    edgeMesh.position.set(xPos, yPos, zPos);
    pathGroup.add(edgeMesh);
  });

  // Connect points with line segments
  if (points.length > 1) {
    const curve = new THREE.CatmullRomCurve3(points);
    const tubeGeo = new THREE.TubeGeometry(curve, 32, 0.08, 8, false);
    const tubeMat = new THREE.MeshLambertMaterial({ color: 0x888880 });
    const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
    pathGroup.add(tubeMesh);
  }

  // Interactive mouse rotation
  let isDragging = false;
  let prevMousePos = { x: 0, y: 0 };

  renderer.domElement.addEventListener("mousedown", (e) => {
    isDragging = true;
    prevMousePos = { x: e.clientX, y: e.clientY };
  });

  window.addEventListener("mouseup", () => {
    isDragging = false;
  });

  renderer.domElement.addEventListener("mousemove", (e) => {
    if (!isDragging) return;
    const deltaX = e.clientX - prevMousePos.x;
    const deltaY = e.clientY - prevMousePos.y;

    pathGroup.rotation.y += deltaX * 0.01;
    pathGroup.rotation.x += deltaY * 0.01;
    pathGroup.rotation.x = Math.max(-0.6, Math.min(0.6, pathGroup.rotation.x));

    prevMousePos = { x: e.clientX, y: e.clientY };
  });

  renderer.domElement.addEventListener("wheel", (e) => {
    e.preventDefault();
    camera.position.z += e.deltaY * 0.01;
    camera.position.z = Math.max(6, Math.min(26, camera.position.z));
  }, { passive: false });

  resetViewBtn.addEventListener("click", () => {
    pathGroup.rotation.set(0, 0, 0);
    camera.position.set(0, 6, 16);
  });

  function animate() {
    requestAnimationFrame(animate);
    renderer.render(scene, camera);
  }
  animate();

  window.addEventListener("resize", () => {
    const newWidth = containerEl.clientWidth || 800;
    camera.aspect = newWidth / height;
    camera.updateProjectionMatrix();
    renderer.setSize(newWidth, height);
  });
}

function render2DFallback(container, hops, noticeText = "") {
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>Hop</th>
        <th>URL</th>
        <th>Domain</th>
        <th>Status</th>
        <th>Latency</th>
        <th>IP Address</th>
        <th>Flag</th>
      </tr>
    </thead>
    <tbody>
      ${hops.map(h => {
        let badgeClass = "badge-neutral";
        if (h.flag === "cross_domain") badgeClass = "badge-amber";
        if (h.flag === "ssl_downgrade" || h.flag === "error" || h.flag === "blocked") badgeClass = "badge-red";
        if (h.flag === "normal") badgeClass = "badge-green";

        return `
          <tr>
            <td><strong>#${h.hop_index + 1}</strong></td>
            <td class="font-mono" style="max-width:240px; word-break:break-all;">${escapeHtml(h.url)}</td>
            <td class="font-mono">${escapeHtml(h.domain)}</td>
            <td><strong>${h.status_code}</strong> <font color="#666">${escapeHtml(h.status_text)}</font></td>
            <td>${h.latency_ms} ms</td>
            <td class="font-mono">${h.ip || 'N/A'}</td>
            <td><span class="badge ${badgeClass}">${(h.flag || 'NORMAL').toUpperCase()}</span></td>
          </tr>
        `;
      }).join("")}
    </tbody>
  `;

  if (noticeText) {
    const p = document.createElement("p");
    p.style.fontSize = "12px";
    p.style.color = "#666";
    p.style.marginBottom = "8px";
    p.textContent = noticeText;
    container.appendChild(p);
  }
  container.appendChild(table);
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
