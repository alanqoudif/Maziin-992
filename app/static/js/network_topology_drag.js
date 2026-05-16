/**
 * Draggable logical topology nodes: updates link paths and laser motion paths to follow devices.
 */
(function () {
  function $(sel, root) {
    return (root || document).querySelector(sel);
  }
  function $$(sel, root) {
    return Array.from((root || document).querySelectorAll(sel));
  }

  function localToGlobal(svg, group, lx, ly) {
    if (!group) return null;
    const pt = svg.createSVGPoint();
    pt.x = lx;
    pt.y = ly;
    const m = group.getCTM();
    if (!m) return null;
    return pt.matrixTransform(m);
  }

  function buildPolylineD(points) {
    const ok = points.filter(Boolean);
    if (ok.length === 0) return '';
    let d = 'M ' + ok[0].x + ' ' + ok[0].y;
    for (let i = 1; i < ok.length; i++) {
      d += ' L ' + ok[i].x + ' ' + ok[i].y;
    }
    return d;
  }

  function quadEW(from, to) {
    const cx = (from.x + to.x) / 2;
    const cy = (from.y + to.y) / 2 - 45;
    return 'M ' + from.x + ' ' + from.y + ' Q ' + cx + ' ' + cy + ' ' + to.x + ' ' + to.y;
  }

  const EW_META = [
    { key: 'it', el: 'it' },
    { key: 'fin', el: 'finance' },
    { key: 'hr', el: 'hr' },
    { key: 'adm', el: 'admin' },
    { key: 'smart', el: 'smart' },
  ];

  function refreshTopology(svg) {
    const internet = $('[data-node="internet"]', svg);
    const edge = $('[data-node="edge"]', svg);
    const fw = $('[data-node="firewall"]', svg);
    const core = $('[data-node="core"]', svg);

    const I = localToGlobal(svg, internet, 60, 36);
    const Et = localToGlobal(svg, edge, 120, 0);
    const Eb = localToGlobal(svg, edge, 120, 46);
    const Ft = localToGlobal(svg, fw, 95, 0);
    const Fb = localToGlobal(svg, fw, 95, 48);
    const Ct = localToGlobal(svg, core, 140, 0);
    const Cb = localToGlobal(svg, core, 140, 116);

    const spine = [I, Et, Eb, Ft, Fb, Ct, Cb];
    const dNS = buildPolylineD(spine);
    const dNSrev = buildPolylineD(spine.slice().reverse());

    $$('.topo-link-ns', svg).forEach(function (p) {
      p.setAttribute('d', dNS);
    });
    const pDown = $('#path-ns-down', svg);
    const pUp = $('#path-ns-up', svg);
    if (pDown) pDown.setAttribute('d', dNS);
    if (pUp) pUp.setAttribute('d', dNSrev);

    EW_META.forEach(function (row) {
      const dept = $('[data-node="' + row.el + '"]', svg);
      const top = localToGlobal(svg, dept, 80, 0);
      if (!top || !Cb) return;
      const d = quadEW(Cb, top);
      $$('.topo-link-ew.topo-ew-' + row.key, svg).forEach(function (p) {
        p.setAttribute('d', d);
      });
      const mp = $('#path-ew-' + row.key, svg);
      if (mp) mp.setAttribute('d', d);
    });

    const it = $('[data-node="it"]', svg);
    const smart = $('[data-node="smart"]', svg);
    const itB = localToGlobal(svg, it, 80, 100);
    const smB = localToGlobal(svg, smart, 80, 100);
    if (itB && smB) {
      const c1x = (itB.x + smB.x) / 2;
      const c1y = Math.min(itB.y, smB.y) - 35;
      const dX =
        'M ' + itB.x + ' ' + itB.y + ' Q ' + c1x + ' ' + c1y + ' ' + smB.x + ' ' + smB.y;
      $$('.topo-link-cross', svg).forEach(function (p) {
        p.setAttribute('d', dX);
      });
      const pex = $('#path-ew-x', svg);
      if (pex) pex.setAttribute('d', dX);
    }
  }

  function parseTranslate(g) {
    const t = g.getAttribute('transform') || '';
    const m = t.match(/translate\(\s*([\d.-]+)[\s,]+([\d.-]+)\s*\)/);
    if (m) return { x: parseFloat(m[1]), y: parseFloat(m[2]) };
    return { x: 0, y: 0 };
  }

  function clientToSvg(svg, cx, cy) {
    const pt = svg.createSVGPoint();
    pt.x = cx;
    pt.y = cy;
    const ctm = svg.getScreenCTM();
    if (!ctm) return pt;
    return pt.matrixTransform(ctm.inverse());
  }

  var dragging = null;

  function onPointerDown(e) {
    if (e.button !== undefined && e.button !== 0) return;
    const g = e.target.closest('.topo-draggable');
    const svg = $('#topo-lan-svg');
    if (!g || !svg || !svg.contains(g)) return;
    dragging = {
      g: g,
      svg: svg,
      start: clientToSvg(svg, e.clientX, e.clientY),
      initial: parseTranslate(g),
    };
    g.classList.add('dragging');
    try {
      g.setPointerCapture(e.pointerId);
    } catch (_) {}
    e.preventDefault();
  }

  function onPointerMove(e) {
    if (!dragging) return;
    const cur = clientToSvg(dragging.svg, e.clientX, e.clientY);
    var dx = cur.x - dragging.start.x;
    var dy = cur.y - dragging.start.y;
    var nx = dragging.initial.x + dx;
    var ny = dragging.initial.y + dy;
    dragging.g.setAttribute('transform', 'translate(' + nx + ' ' + ny + ')');
    refreshTopology(dragging.svg);
  }

  function onPointerUp(e) {
    if (!dragging) return;
    try {
      if (typeof e.pointerId === 'number') dragging.g.releasePointerCapture(e.pointerId);
    } catch (_) {}
    dragging.g.classList.remove('dragging');
    dragging = null;
  }

  var DEFAULT_POS = {
    internet: [400, 18],
    edge: [340, 68],
    firewall: [365, 128],
    core: [320, 198],
    it: [40, 448],
    finance: [200, 488],
    hr: [380, 518],
    admin: [560, 488],
    smart: [720, 448],
  };

  function resetLayout(svg) {
    $$('.topo-draggable', svg).forEach(function (g) {
      var id = g.getAttribute('data-node');
      if (DEFAULT_POS[id]) {
        var xy = DEFAULT_POS[id];
        g.setAttribute('transform', 'translate(' + xy[0] + ' ' + xy[1] + ')');
      }
    });
    refreshTopology(svg);
  }

  function init() {
    var svg = $('#topo-lan-svg');
    if (!svg) return;
    requestAnimationFrame(function () {
      refreshTopology(svg);
    });
    svg.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
    window.addEventListener('pointercancel', onPointerUp);
    var resetBtn = $('#topo-reset-layout');
    if (resetBtn) {
      resetBtn.addEventListener('click', function () {
        resetLayout(svg);
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
