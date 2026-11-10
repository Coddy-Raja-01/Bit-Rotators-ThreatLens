// 3D Trust Chain Explorer (Three.js Bundled Locally)
// Design Rules: Flat-colored materials only, no gradients, no glows. 
// Provides full 2D accessible table toggle and WebGL fallback.

export function renderTrustChain3D(containerEl, chainData) {
  if (!containerEl) return;
  containerEl.innerHTML = "";

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
    render2DFallback(containerEl, chainData, "WebGL unavailable in browser; showing accessible 2D trust chain table.");
    return;
  }

  // Wrapper with control buttons
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

  // Legend overlay
  const legend = document.createElement("div");
  legend.className = "viewport-legend";
  legend.innerHTML = `
    <span class="legend-chip"><span class="chip-color" style="background:#2a5d91"></span> Leaf Cert</span>
    <span class="legend-chip"><span class="chip-color" style="background:#475569"></span> Intermediate / Root CA</span>
    <span class="legend-chip"><span class="chip-color" style="background:#b02a2a"></span> Weak / Expired / Untrusted</span>
    <span style="color:#666; font-size:10px;">Drag to rotate • Scroll to zoom</span>
  `;
  wrapper.appendChild(legend);

  const canvasContainer = document.createElement("div");
  canvasContainer.style.width = "100%";
  canvasContainer.style.height = "100%";
  wrapper.appendChild(canvasContainer);

  const fallbackContainer = document.createElement("div");
  fallbackContainer.style.display = "none";
  render2DFallback(fallbackContainer, chainData);

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

  // Three.js Setup
  const width = containerEl.clientWidth || 800;
  const height = 380;

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0xf6f6f4); // Same off-white as page

  const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
  camera.position.set(0, 5, 14);

  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setSize(width, height);
  renderer.setPixelRatio(window.devicePixelRatio || 1);
  canvasContainer.appendChild(renderer.domElement);

  // Flat utilitarian lighting (No neon / no dramatic shadows)
  const ambientLight = new THREE.AmbientLight(0xffffff, 0.85);
  scene.add(ambientLight);

  const dirLight = new THREE.DirectionalLight(0xffffff, 0.4);
  dirLight.position.set(5, 10, 7);
  scene.add(dirLight);

  // Group for rotation
  const chainGroup = new THREE.Group();
  scene.add(chainGroup);

  // Build 3D chain blocks
  const nodeCount = chainData.length || 1;
  const spacing = 5.0;
  const startX = -((nodeCount - 1) * spacing) / 2;

  chainData.forEach((node, idx) => {
    const xPos = startX + idx * spacing;
    
    // Determine color based on health
    let colorHex = 0x2a5d91; // Normal Leaf Blue
    if (node.node_type === "root") colorHex = 0x334155; // Root Slate
    if (node.node_type === "intermediate") colorHex = 0x475569; // Intermediate Slate
    if (node.status === "EXPIRED" || node.status === "SELF_SIGNED" || node.status === "WEAK_KEY" || node.is_weak_key) {
      colorHex = 0xb02a2a; // Danger Red
    }

    // Node Box Mesh (Flat Lambert Material - No gradients, no gloss)
    const boxGeo = new THREE.BoxGeometry(2.8, 1.6, 1.2);
    const boxMat = new THREE.MeshLambertMaterial({ color: colorHex });
    const boxMesh = new THREE.Mesh(boxGeo, boxMat);
    boxMesh.position.set(xPos, 0, 0);
    chainGroup.add(boxMesh);

    // Subtle edge outline for crisp utilitarian architectural look
    const edgeGeo = new THREE.EdgesGeometry(boxGeo);
    const edgeMat = new THREE.LineBasicMaterial({ color: 0x111111, linewidth: 1 });
    const edgeMesh = new THREE.LineSegments(edgeGeo, edgeMat);
    edgeMesh.position.set(xPos, 0, 0);
    chainGroup.add(edgeMesh);

    // Connect to next node in chain with link bar
    if (idx < nodeCount - 1) {
      const linkGeo = new THREE.CylinderGeometry(0.12, 0.12, spacing - 2.8, 8);
      const linkMat = new THREE.MeshLambertMaterial({ color: 0x888880 });
      const linkMesh = new THREE.Mesh(linkGeo, linkMat);
      linkMesh.rotation.z = Math.PI / 2;
      linkMesh.position.set(xPos + spacing / 2, 0, 0);
      chainGroup.add(linkMesh);
    }
  });

  // Orbit controls or clean mouse drag implementation
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

    chainGroup.rotation.y += deltaX * 0.01;
    chainGroup.rotation.x += deltaY * 0.01;
    chainGroup.rotation.x = Math.max(-0.6, Math.min(0.6, chainGroup.rotation.x));

    prevMousePos = { x: e.clientX, y: e.clientY };
  });

  renderer.domElement.addEventListener("wheel", (e) => {
    e.preventDefault();
    camera.position.z += e.deltaY * 0.01;
    camera.position.z = Math.max(6, Math.min(24, camera.position.z));
  }, { passive: false });

  resetViewBtn.addEventListener("click", () => {
    chainGroup.rotation.set(0, 0, 0);
    camera.position.set(0, 5, 14);
  });

  let animId;
  function animate() {
    animId = requestAnimationFrame(animate);
    renderer.render(scene, camera);
  }
  animate();

  // Resize handler
  window.addEventListener("resize", () => {
    const newWidth = containerEl.clientWidth || 800;
    camera.aspect = newWidth / height;
    camera.updateProjectionMatrix();
    renderer.setSize(newWidth, height);
  });
}

function render2DFallback(container, chainData, noticeText = "") {
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>Tier</th>
        <th>Common Name (Subject)</th>
        <th>Issuer</th>
        <th>Key Type & Size</th>
        <th>Valid To</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      ${chainData.map(node => {
        const cn = node.subject?.common_name || node.subject?.CN || "Unknown";
        const issuerCn = node.issuer?.common_name || node.issuer?.CN || "Root Trust Anchor";
        const isProblem = node.status !== "VALID";
        const badgeClass = isProblem ? "badge-red" : "badge-green";
        return `
          <tr>
            <td><strong>${(node.node_type || 'certificate').toUpperCase()}</strong></td>
            <td class="font-mono">${escapeHtml(cn)}</td>
            <td>${escapeHtml(issuerCn)}</td>
            <td class="font-mono">${node.key_type || 'RSA'} ${node.key_size || 2048}-bit</td>
            <td>${node.valid_to || 'N/A'}</td>
            <td><span class="badge ${badgeClass}">${node.status || 'VALID'}</span></td>
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
