"use strict";

class EvidenceBoard {
  constructor() {
    this.viewport = document.getElementById("board-viewport");
    this.world = document.getElementById("board-world");
    this.layer = document.getElementById("board-nodes");
    this.lines = document.getElementById("board-lines");
    this.scaleLabel = document.getElementById("board-zoom");
    this.nodes = new Map();
    this.edges = [];
    this.zoom = 1;
    this.pan = {x: 0, y: 0};
    this.fitted = true;
    this.key = null;
    this.drag = null;

    const zoomIn = document.getElementById("board-zoom-in");
    const zoomOut = document.getElementById("board-zoom-out");
    const fit = document.getElementById("board-fit");
    zoomIn.onclick = () => this.zoomBy(1.2);
    zoomOut.onclick = () => this.zoomBy(1 / 1.2);
    fit.onclick = () => this.fit();
    this.controls = [zoomIn, zoomOut, fit];
    this.updateControls(false);
    this.viewport.addEventListener("pointerdown", event => this.startDrag(event));
    this.viewport.addEventListener("pointermove", event => this.moveDrag(event));
    this.viewport.addEventListener("pointerup", event => this.endDrag(event));
    this.viewport.addEventListener("pointercancel", event => this.endDrag(event));
    this.viewport.addEventListener("lostpointercapture", event => this.endDrag(event));
    this.viewport.addEventListener("wheel", event => {
      if (!this.nodes.size) return;
      event.preventDefault();
      const rect = this.viewport.getBoundingClientRect();
      this.zoomBy(Math.exp(-Math.max(-100, Math.min(100, event.deltaY)) * .005),
                  event.clientX - rect.left, event.clientY - rect.top);
    }, {passive: false});
    this.viewport.addEventListener("keydown", event => this.navigate(event));
    new ResizeObserver(() => {
      if (this.fitted) this.fit();
    }).observe(this.viewport);
  }

  updateControls(hasNodes) {
    for (const control of this.controls) control.disabled = !hasNodes;
    this.viewport.classList.toggle("has-nodes", hasNodes);
  }

  loadLayout(key) {
    if (!key) return {};
    try {
      return JSON.parse(localStorage.getItem("mitre-rag.board.v1") || "{}")[key] || {};
    } catch {
      return {};
    }
  }

  bind(key) {
    this.key = key;
    if (this.dirty) this.saveLayout();
  }

  saveLayout() {
    if (!this.key) return;
    try {
      const data = JSON.parse(localStorage.getItem("mitre-rag.board.v1") || "{}");
      delete data[this.key];
      data[this.key] = Object.fromEntries([...this.nodes].map(([id, node]) => [id, [node.x, node.y]]));
      localStorage.setItem("mitre-rag.board.v1", JSON.stringify(Object.fromEntries(Object.entries(data).slice(-50))));
      this.dirty = false;
    } catch {
      // Layout preferences are optional when browser storage is unavailable.
    }
  }

  render(cards, links, key) {
    this.nodes.clear();
    this.layer.replaceChildren();
    this.lines.replaceChildren();
    this.edges = [];
    this.drag = null;
    this.viewport.classList.remove("board-dragging");
    this.key = key;
    this.dirty = false;
    const saved = this.loadLayout(key);
    const controls = new Map();
    for (const card of cards) {
      const node = document.createElement("article");
      node.className = "board-node board-node-" + card.type;
      const handle = document.createElement("h3");
      handle.className = "board-node-head";
      handle.textContent = card.label;
      handle.dataset.dragNode = card.id;
      handle.tabIndex = 0;
      handle.setAttribute("aria-label", card.label + " · Ok tuşlarıyla taşı");
      const content = document.createElement(card.action ? "button" : "p");
      content.className = "board-node-content";
      if (card.action) {
        content.type = "button";
        content.addEventListener("click", card.action);
        controls.set(card.id, content);
      }
      if (card.code) {
        const code = document.createElement("code");
        code.textContent = card.code;
        content.append(code);
      }
      const text = document.createElement("span");
      text.textContent = card.text;
      content.append(text);
      if (card.meta) {
        const metadata = document.createElement("small");
        metadata.textContent = card.meta;
        content.append(metadata);
      }
      node.append(handle, content);
      this.layer.append(node);
      const position = saved[card.id];
      const [x, y] = Array.isArray(position) && position.length === 2 && position.every(Number.isFinite)
        ? position : [card.x, card.y];
      this.nodes.set(card.id, {node, x, y});
      this.position(card.id, x, y);
    }
    for (const [from, to] of links) {
      if (!this.nodes.has(from) || !this.nodes.has(to)) continue;
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      this.lines.append(path);
      this.edges.push({from, to, path});
    }
    this.updateControls(this.nodes.size > 0);
    this.fitted = true;
    this.fit();
    return controls;
  }

  position(id, x, y) {
    const entry = this.nodes.get(id);
    entry.x = Math.max(-6000, Math.min(x, 6000));
    entry.y = Math.max(-6000, Math.min(y, 6000));
    entry.node.style.transform = `translate(${entry.x}px, ${entry.y}px)`;
  }

  updateVisibility(changes) {
    for (const [id, visible] of changes) this.nodes.get(id).node.hidden = !visible;
    for (const [id, entry] of this.nodes) {
      if (!entry.node.classList.contains("board-node-reference")) continue;
      entry.node.hidden = !this.edges.some(({from, to}) => to === id && !this.nodes.get(from).node.hidden);
    }
    this.drawEdges();
  }

  drawEdges() {
    for (const {from, to, path} of this.edges) {
      const a = this.nodes.get(from);
      const b = this.nodes.get(to);
      path.style.display = a.node.hidden || b.node.hidden ? "none" : "";
      if (path.style.display) continue;
      const aCenter = a.x + a.node.offsetWidth / 2;
      const bCenter = b.x + b.node.offsetWidth / 2;
      const direction = bCenter >= aCenter ? 1 : -1;
      const ax = a.x + (direction > 0 ? a.node.offsetWidth : 0);
      const bx = b.x + (direction < 0 ? b.node.offsetWidth : 0);
      const ay = a.y + a.node.offsetHeight / 2;
      const by = b.y + b.node.offsetHeight / 2;
      const curve = Math.max(24, Math.abs(bx - ax) * .44) * direction;
      path.setAttribute("d", `M ${ax} ${ay} C ${ax + curve} ${ay}, ${bx - curve} ${by}, ${bx} ${by}`);
    }
  }

  bounds() {
    const nodes = [...this.nodes.values()].filter(({node}) => !node.hidden);
    if (!nodes.length) return null;
    const left = Math.min(...nodes.map(node => node.x));
    const top = Math.min(...nodes.map(node => node.y));
    const right = Math.max(...nodes.map(({node, x}) => x + node.offsetWidth));
    const bottom = Math.max(...nodes.map(({node, y}) => y + node.offsetHeight));
    return {left, top, right, bottom};
  }

  fit() {
    const width = this.viewport.clientWidth;
    const height = this.viewport.clientHeight;
    if (!width || !height) return;
    this.fitted = true;
    const bounds = this.bounds();
    if (bounds) {
      const {left, top, right, bottom} = bounds;
      this.zoom = Math.max(.15, Math.min(1, (width - 48) / (right - left), (height - 80) / (bottom - top)));
      this.pan = {x: (width - (left + right) * this.zoom) / 2,
                  y: 19 + (height - (top + bottom) * this.zoom) / 2};
    } else {
      this.zoom = 1;
      this.pan = {x: 0, y: 0};
    }
    this.drawEdges();
    this.paint();
  }

  paint() {
    this.world.style.transform = `translate(${this.pan.x}px, ${this.pan.y}px) scale(${this.zoom})`;
    this.scaleLabel.textContent = `${Math.round(this.zoom * 100)}%`;
  }

  zoomBy(factor, x = this.viewport.clientWidth / 2, y = this.viewport.clientHeight / 2) {
    if (!this.nodes.size) return;
    const next = Math.min(2.5, Math.max(.15, this.zoom * factor));
    const ratio = next / this.zoom;
    this.pan = {x: x - (x - this.pan.x) * ratio, y: y - (y - this.pan.y) * ratio};
    this.zoom = next;
    this.fitted = false;
    this.paint();
  }

  startDrag(event) {
    if (!this.nodes.size || event.button !== 0 || this.drag || event.target.closest("button")) return;
    const handle = event.target.closest("[data-drag-node]");
    const id = handle?.dataset.dragNode;
    if (!id && event.target.closest(".board-node")) return;
    const start = id ? this.nodes.get(id) : this.pan;
    this.drag = {id, pointer: event.pointerId, startX: event.clientX, startY: event.clientY,
                 x: start.x, y: start.y, moved: false};
    this.viewport.setPointerCapture(event.pointerId);
    this.viewport.classList.add("board-dragging");
  }

  moveDrag(event) {
    const drag = this.drag;
    if (!drag || event.pointerId !== drag.pointer) return;
    const dx = event.clientX - drag.startX;
    const dy = event.clientY - drag.startY;
    if (!dx && !dy && !drag.moved) return;
    drag.moved = true;
    this.fitted = false;
    if (drag.id) {
      this.position(drag.id, drag.x + dx / this.zoom, drag.y + dy / this.zoom);
      this.drawEdges();
    } else {
      this.pan = {x: drag.x + dx, y: drag.y + dy};
      this.paint();
    }
  }

  endDrag(event) {
    const drag = this.drag;
    if (!drag || event.pointerId !== drag.pointer) return;
    this.drag = null;
    this.viewport.classList.remove("board-dragging");
    if (drag.id && drag.moved) {
      this.dirty = true;
      this.saveLayout();
    }
  }

  navigate(event) {
    if (!this.nodes.size || event.target.closest("button")) return;
    const directions = {ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1]};
    const direction = directions[event.key];
    if (!direction && !["+", "=", "-", "0"].includes(event.key)) return;
    event.preventDefault();
    if (!direction) {
      if (event.key === "0") this.fit();
      else this.zoomBy(event.key === "-" ? 1 / 1.2 : 1.2);
      return;
    }
    this.fitted = false;
    const [dx, dy] = direction;
    const id = event.target.dataset.dragNode;
    if (id) {
      const node = this.nodes.get(id);
      this.position(id, node.x + 14 * dx, node.y + 14 * dy);
      this.drawEdges();
      this.dirty = true;
      this.saveLayout();
    } else {
      this.pan = {x: this.pan.x + 36 * dx, y: this.pan.y + 36 * dy};
      this.paint();
    }
  }
}
