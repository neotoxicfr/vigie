// vigie : améliorations progressives. Tout fonctionne sans ce script.
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  // Thème : sombre par défaut, choix gardé dans le navigateur.
  const root = document.documentElement;
  try { const t = localStorage.getItem('vigie-theme'); if (t) root.dataset.theme = t; } catch (_) {}
  document.addEventListener('click', (e) => {
    if (!e.target.closest('[data-theme-toggle]')) return;
    root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
    try { localStorage.setItem('vigie-theme', root.dataset.theme); } catch (_) {}
  });

  document.addEventListener('DOMContentLoaded', () => {
    // Filtres : appliqués dès qu'une case change, recherche après une courte pause.
    $$('form[data-autosubmit]').forEach((f) => {
      f.addEventListener('change', () => f.requestSubmit());
      const q = $('input[type=search]', f);
      let t;
      if (q) q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => f.requestSubmit(), 350); });
    });

    // Lignes cliquables : le lien de la ligne, ouvert dans le tiroir.
    document.addEventListener('click', (e) => {
      const tr = e.target.closest('tr[data-href]');
      if (tr && !e.target.closest('a, button, input, form')) {
        const a = $('a.row-link', tr);
        if (a) a.click();
      }
    });

    // Tiroir de détail.
    const drawer = $('[data-drawer]');
    const body = drawer && $('[data-drawer-body]', drawer);
    let lastFocus = null;
    const open = async (href) => {
      if (!drawer) { location.href = href; return; }
      const u = new URL(href, location.href);
      u.searchParams.set('panel', '1');
      u.searchParams.set('back', location.pathname + location.search);
      try {
        const r = await fetch(u, { credentials: 'same-origin' });
        if (!r.ok) throw new Error(r.status);
        body.innerHTML = await r.text();
      } catch (_) { location.href = href; return; }
      // Les formulaires du tiroir reviennent sur la page courante.
      $$('input[name=back]', body).forEach((i) => { if (i.value === '/issues') i.value = location.pathname + location.search; });
      lastFocus = document.activeElement;
      drawer.hidden = false;
      document.body.style.overflow = 'hidden';
      setupTabs(body); setupCopy(body);
      $('.drawer-x', drawer).focus();
      history.replaceState(null, '', location.pathname + location.search);
    };
    const close = () => {
      if (!drawer || drawer.hidden) return;
      drawer.hidden = true;
      document.body.style.overflow = '';
      body.innerHTML = '';
      if (lastFocus) lastFocus.focus();
    };
    document.addEventListener('click', (e) => {
      const a = e.target.closest('a.row-link[href^="/issue/"], a[data-drawer-link]');
      if (a && !e.metaKey && !e.ctrlKey && !e.shiftKey) { e.preventDefault(); open(a.href); return; }
      if (e.target.closest('[data-drawer-close]')) close();
    });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });

    setupTabs(document); setupCopy(document);

    // Avancement du passage en direct ; rechargement à la fin.
    const live = $('[data-progress][data-running]');
    if (live) {
      const bar = $('[data-bar]', live), pct = $('[data-pct]', live), phase = $('[data-phase]', live);
      if (bar) bar.style.transform = 'scaleX(' + (bar.dataset.val || 0) / 100 + ')';
      const tick = async () => {
        try {
          const r = await fetch('/api/progress', { credentials: 'same-origin' });
          const p = await r.json();
          if (!p.running) { location.reload(); return; }
          if (bar) bar.style.transform = 'scaleX(' + p.percent / 100 + ')';
          if (pct) pct.textContent = p.percent + ' %';
          if (phase) phase.textContent = p.phase;
        } catch (_) {}
        setTimeout(tick, 2000);
      };
      setTimeout(tick, 2000);
    }
  });

  function setupTabs(scope) {
    $$('[data-tabs]', scope).forEach((box) => {
      const tabs = $$('[data-tab]', box), panels = $$('[data-panel]', box);
      const show = (i) => {
        tabs.forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === i)));
        panels.forEach((p) => { p.hidden = p.dataset.panel !== i; });
      };
      tabs.forEach((t) => t.addEventListener('click', () => show(t.dataset.tab)));
      const def = tabs.find((t) => t.hasAttribute('data-default')) || tabs[0];
      if (def) show(def.dataset.tab);
    });
  }

  function setupCopy(scope) {
    $$('[data-copy]', scope).forEach((b) => b.addEventListener('click', async () => {
      const code = b.parentElement.querySelector('code');
      try { await navigator.clipboard.writeText(code.textContent); b.classList.add('done'); setTimeout(() => b.classList.remove('done'), 1200); } catch (_) {}
    }));
  }
})();
