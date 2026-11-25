// ============================================================
//  SentinelAI – Main JS
// ============================================================

// ---- Clock ----
function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ---- Sidebar (responsive) ----
function toggleSidebar() {
  const sidebar  = document.getElementById('sidebar');
  const overlay  = document.getElementById('sidebar-overlay');
  const isOpen   = sidebar.classList.contains('open');
  if (isOpen) {
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
  } else {
    sidebar.classList.add('open');
    overlay.classList.add('open');
  }
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('open');
}

// Close sidebar when a nav link is clicked on mobile
document.querySelectorAll('.nav-item').forEach(link => {
  link.addEventListener('click', () => {
    if (window.innerWidth <= 1024) closeSidebar();
  });
});

// ---- Toast notifications ----
function showToast(message, type = 'info') {
  const icons = {
    success: 'fa-check-circle',
    error:   'fa-circle-xmark',
    warning: 'fa-triangle-exclamation',
    info:    'fa-circle-info'
  };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i><span>${message}</span>`;
  document.getElementById('toast-container').appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s'; }, 3200);
  setTimeout(() => toast.remove(), 3500);
}

// ---- Header stats (runs on every page) ----
async function updateHeaderStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();
    const sc   = data.severity_counts || {};

    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val ?? 0; };
    set('hdr-critical', sc.critical);
    set('hdr-high',     sc.high);
    set('hdr-medium',   sc.medium);
    set('hdr-low',      sc.low);

    const navBadge = document.getElementById('nav-alert-count');
    if (navBadge) navBadge.textContent = data.active_alerts || '';

    // Danger level badge
    const badge = document.getElementById('threat-level-badge');
    if (badge) {
      if (sc.critical > 0) {
        badge.textContent = 'CRITICAL';
        badge.style.cssText = 'background:rgba(255,0,110,0.2);color:#ff006e;border:1px solid rgba(255,0,110,0.4);font-size:10px;font-weight:700;padding:3px 9px;border-radius:4px;font-family:monospace;';
      } else if (sc.high > 0) {
        badge.textContent = 'HIGH'; badge.className = 'tl-badge high';
      } else if (sc.medium > 0) {
        badge.textContent = 'MEDIUM'; badge.className = 'tl-badge medium';
      } else {
        badge.textContent = 'LOW'; badge.className = 'tl-badge low';
      }
    }

    // Dashboard-specific counters
    set('stat-total',   data.total_events);
    set('stat-alerts',  data.active_alerts);
    set('stat-alerts2', data.active_alerts);
    set('stat-brute',   data.brute_force);
    set('stat-anomaly', data.anomalies);
    set('stat-today',   data.today_events);
  } catch (e) { /* silent fail */ }
}

setInterval(updateHeaderStats, 15000);
updateHeaderStats();

// ---- Dashboard charts ----
function initDashboardCharts(trendData, severityData, eventTypes) {

  // Trend line chart
  const trendCtx = document.getElementById('trendChart');
  if (trendCtx) {
    new Chart(trendCtx, {
      type: 'line',
      data: {
        labels: trendData.map(d => d.day || ''),
        datasets: [{
          label: 'Events',
          data: trendData.map(d => d.count || 0),
          fill: true,
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.08)',
          tension: 0.4,
          pointBackgroundColor: '#3b82f6',
          pointRadius: 4,
          pointHoverRadius: 6,
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#64748b', font: { size: 11 } }, grid: { color: 'rgba(99,179,237,0.06)' } },
          y: { ticks: { color: '#64748b', font: { size: 11 } }, grid: { color: 'rgba(99,179,237,0.06)' }, beginAtZero: true }
        }
      }
    });
  }

  // Severity donut
  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [
            severityData.critical || 0,
            severityData.high     || 0,
            severityData.medium   || 0,
            severityData.low      || 0
          ],
          backgroundColor: [
            'rgba(255,0,110,0.75)',
            'rgba(249,115,22,0.75)',
            'rgba(234,179,8,0.75)',
            'rgba(16,185,129,0.75)'
          ],
          borderColor: ['#ff006e','#f97316','#eab308','#10b981'],
          borderWidth: 1,
          hoverOffset: 6,
        }]
      },
      options: {
        cutout: '70%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#64748b', padding: 10, font: { size: 11 } }
          }
        }
      }
    });
  }

  // Event type bar chart
  const typeCtx = document.getElementById('typeChart');
  if (typeCtx && eventTypes.length) {
    // Rename technical labels to plain English
    const labelMap = {
      SSH_AUTH:        'Login Attempt',
      INVALID_USER:    'Unknown User',
      SUDO:            'Admin Command',
      SUSPICIOUS_LOGIN:'Suspicious Login',
      SYSTEM:          'System',
      DISCONNECT:      'Disconnect'
    };
    new Chart(typeCtx, {
      type: 'bar',
      data: {
        labels: eventTypes.map(e => labelMap[e.type] || e.type),
        datasets: [{
          data: eventTypes.map(e => e.count),
          backgroundColor: [
            'rgba(59,130,246,0.6)','rgba(6,182,212,0.6)','rgba(168,85,247,0.6)',
            'rgba(249,115,22,0.6)','rgba(239,68,68,0.6)','rgba(16,185,129,0.6)'
          ],
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { display: false } },
          y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(99,179,237,0.06)' }, beginAtZero: true }
        }
      }
    });
  }
}

// ---- Simulate brute-force attack ----
async function simulateAttack() {
  try {
    const res  = await fetch('/api/simulate/attack', { method: 'POST' });
    const data = await res.json();
    showToast(`Test attack from ${data.ip} targeting "${data.user}"`, 'warning');
    setTimeout(updateHeaderStats, 1000);
  } catch (e) { showToast('Simulation failed', 'error'); }
}

// ---- Simulate anomaly ----
async function simulateAnomaly() {
  try {
    const res  = await fetch('/api/simulate/anomaly', { method: 'POST' });
    const data = await res.json();
    showToast(`Test unusual login from ${data.ip}`, 'info');
    setTimeout(updateHeaderStats, 1000);
  } catch (e) { showToast('Simulation failed', 'error'); }
}

// ---- Chart.js global defaults ----
Chart.defaults.color       = '#94a3b8';
Chart.defaults.borderColor = 'rgba(99,179,237,0.08)';
