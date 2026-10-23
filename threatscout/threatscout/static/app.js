// ThreatScout ortak betik: giriş animasyonu, arka plan noktaları, canlı tarama ve htmx hata gösterimi.
(function () {
  'use strict';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  // Sunucudaki DISABLED_ERROR ile birebir aynı olmalı
  var DISABLED_ERROR = 'API anahtarı eklenmemiş';

  // htmx hata cevaplarını (400, 429 vb.) da sonuç alanına yazdır
  document.body.addEventListener('htmx:beforeSwap', function (evt) {
    if (evt.detail.xhr.status >= 400) {
      evt.detail.shouldSwap = true;
      evt.detail.isError = false;
    }
  });

  // ---- Canlı tarama: her kaynak bitince kendi kartı görünür ----

  // Sunucudan gelen HTML içindeki betikleri (harita kurulumu gibi) yeniden çalıştırır
  function runScripts(root) {
    root.querySelectorAll('script').forEach(function (old) {
      var fresh = document.createElement('script');
      fresh.textContent = old.textContent;
      old.parentNode.replaceChild(fresh, old);
    });
  }

  function addLiveCard(live, data, startedAt) {
    var off = !data.ok && data.error === DISABLED_ERROR;
    var card = document.createElement('div');
    card.className = 'live-card ' + (data.ok ? 'is-ok' : (off ? 'is-off' : 'is-fail')) + (data.cached ? ' is-cached' : '');

    var head = document.createElement('div');
    head.className = 'live-head';
    var name = document.createElement('span');
    name.className = 'live-name';
    name.textContent = data.title;
    var state = document.createElement('span');
    state.className = 'live-state';
    state.textContent = data.ok ? 'Veri alındı' : (off ? 'Anahtar yok' : 'Hata');
    head.appendChild(name);
    head.appendChild(state);
    card.appendChild(head);

    var detail = document.createElement('div');
    detail.className = 'live-detail';
    detail.textContent = data.detail;
    card.appendChild(detail);

    if (!data.ok && !off) {
      var error = document.createElement('div');
      error.className = 'live-error';
      error.textContent = data.error;
      card.appendChild(error);
    }

    var foot = document.createElement('div');
    foot.className = 'live-foot';
    foot.textContent = (data.cached ? 'Önbellekten' : 'Canlı sorgu') + ' · ' + (Date.now() - startedAt) + ' ms';
    card.appendChild(foot);

    live.appendChild(card);
  }

  // Sunucu-gönderimli olay akışını ("event:" ve "data:" satırları) okur
  function readEvents(body, onEvent) {
    var reader = body.getReader();
    var decoder = new TextDecoder();
    var buffer = '';

    function pump() {
      return reader.read().then(function (chunk) {
        if (chunk.done) return;
        buffer += decoder.decode(chunk.value, { stream: true });
        var parts = buffer.split('\n\n');
        buffer = parts.pop();
        parts.forEach(function (part) {
          var name = 'message';
          var data = '';
          part.split('\n').forEach(function (line) {
            if (line.indexOf('event: ') === 0) name = line.slice(7);
            else if (line.indexOf('data: ') === 0) data += line.slice(6);
          });
          if (data) onEvent(name, JSON.parse(data));
        });
        return pump();
      });
    }
    return pump();
  }

  function runStreamingScan(form) {
    var result = document.getElementById('result');
    var busy = document.getElementById('busy');
    var button = form.querySelector('button[type="submit"]');
    var startedAt = Date.now();

    if (busy) busy.classList.add('is-busy');
    if (button) button.disabled = true;
    result.innerHTML = '<div class="live-grid" id="live"></div>';
    var live = document.getElementById('live');

    fetch('/scan/stream', {
      method: 'POST',
      body: new FormData(form),
      headers: { 'Accept': 'text/event-stream' }
    }).then(function (response) {
      if (!response.ok) {
        return response.text().then(function (html) { result.innerHTML = html; });
      }
      return readEvents(response.body, function (name, data) {
        if (name === 'provider') {
          addLiveCard(live, data, startedAt);
        } else if (name === 'report') {
          result.innerHTML = data.html;
          runScripts(result);
        }
      });
    }).catch(function () {
      result.innerHTML = '<div class="error"><i class="fa-solid fa-triangle-exclamation"></i><div>Tarama sırasında bağlantı kesildi. Lütfen tekrar deneyin.</div></div>';
    }).finally(function () {
      if (busy) busy.classList.remove('is-busy');
      if (button) button.disabled = false;
    });
  }

  function setupScanForm() {
    var form = document.getElementById('scan-form');
    if (!form) return;
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      runStreamingScan(form);
    });
  }

  // ---- Giriş animasyonu: bir tarayıcı sekmesinde bir kez oynar, Atla ya da Esc ile geçilir ----
  function startIntro() {
    var intro = document.getElementById('intro');
    if (!intro) return;
    if (reduceMotion || document.documentElement.classList.contains('intro-seen')) {
      intro.remove();
      return;
    }
    try { sessionStorage.setItem('ts-intro-seen', '1'); } catch (e) { /* depolama kapalıysa sorun yok */ }

    var app = document.getElementById('app');
    var skipBtn = document.getElementById('intro-skip');
    if (app) app.inert = true;

    function onKey(e) {
      if (e.key === 'Escape') skip();
    }

    function finish() {
      document.removeEventListener('keydown', onKey);
      intro.remove();
      if (app) app.inert = false;
      var first = document.querySelector('[autofocus]');
      if (first) first.focus();
    }

    function skip() {
      intro.style.animation = 'intro-out 0.35s ease forwards';
      window.setTimeout(finish, 380);
    }

    if (skipBtn) skipBtn.addEventListener('click', skip);
    document.addEventListener('keydown', onKey);
    window.setTimeout(finish, 4900);
  }

  // ---- Arka plan noktaları (hareket azaltma açıksa çizilmez) ----
  function startDots() {
    var canvas = document.getElementById('cyber-canvas');
    if (!canvas) return;
    if (reduceMotion) {
      canvas.remove();
      return;
    }
    var ctx = canvas.getContext('2d');
    var w = 0;
    var h = 0;
    var dots = [];

    function resize() {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    var count = Math.min(Math.floor(window.innerWidth / 38), 30);
    for (var i = 0; i < count; i++) {
      dots.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: Math.random() * 1.4 + 0.6,
        rgb: Math.random() > 0.3 ? '34,211,238' : '52,211,153'
      });
    }

    (function frame() {
      ctx.clearRect(0, 0, w, h);
      for (var a = 0; a < dots.length; a++) {
        var p = dots[a];
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = w;
        if (p.x > w) p.x = 0;
        if (p.y < 0) p.y = h;
        if (p.y > h) p.y = 0;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(' + p.rgb + ',0.75)';
        ctx.fill();
        for (var b = a + 1; b < dots.length; b++) {
          var q = dots[b];
          var d = Math.hypot(p.x - q.x, p.y - q.y);
          if (d < 140) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = 'rgba(34,211,238,' + (0.2 * (1 - d / 140)).toFixed(3) + ')';
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(frame);
    })();
  }

  document.addEventListener('DOMContentLoaded', function () {
    startIntro();
    startDots();
    setupScanForm();
  });
})();

// Sayfadaki küçük yardımcı işlevler
function toggleGuide() {
  var body = document.getElementById('guide-body');
  var arrow = document.getElementById('guide-arrow');
  if (!body) return;
  var hidden = body.style.display === 'none';
  body.style.display = hidden ? 'grid' : 'none';
  if (arrow) arrow.style.transform = hidden ? 'rotate(0deg)' : 'rotate(-90deg)';
}

function fillExample(value) {
  var input = document.getElementById('ioc-input');
  if (!input) return;
  input.value = value;
  input.focus();
}
