'use strict';
// ============================================================
// ROMI NEXUS — OPS COMMAND CENTER v6.2
// ============================================================
// v6.2 changes (on top of v6.1-sec FIXED v3.7):
//
// BUG-11 FIX: opsDD() now reads decision_token / decision_token_reject
//   from _opsData.ddQueue row and sends it as 'token' field.
//   Previously sent _opsToken (session token) as 'token' which
//   never matched the Python HMAC in dd_queue.decision_token,
//   causing approveDDReview/rejectDDReview to always return
//   "INVALID DECISION TOKEN".
//
// BUG-12 FIX: openDDModal() pillar labels corrected to match
//   Python worker v4.4.0 output:
//     ENTITY VERIFICATION, BENEFICIAL OWNERSHIP,
//     SANCTIONS SCREENING, NEGATIVE NEWS,
//     FINANCIAL HEALTH, LEGAL & REGULATORY
//   Old labels (LEGAL & REGULATORY, FINANCIAL HEALTH,
//   OPERATIONAL INTEGRITY, PRODUCT/TECHNICAL MOAT,
//   MARKET POSITION, CULTURAL/STRATEGIC FIT) were wrong —
//   they never matched the actual pillar keys from the DD engine.
//
// BUG-13 FIX: loadOpsChatMessages() now appends opsToken to
//   getMessages request URL. Required by worker M-06 patch —
//   without it the request fell through to email-based access
//   control, blocking ops from reading/sending helpdesk messages.
// ============================================================

const API_URL = 'https://rominexus-gateway-v6.vacorp-inquiries.workers.dev';

// ── DOMPurify safeHTML helpers ──
const PURIFY_CONFIG = {
  ALLOWED_TAGS: ['b','strong','br','div','span','table','thead','tbody','tr','th','td','button','a','select','option'],
  ALLOWED_ATTR: ['style','class','id','colspan','data-id','data-email','data-decision','data-roomid','data-action','data-path','data-active','data-label','href','target','rel'],
  FORCE_BODY: true,
};
function safeHTML(html) {
  if (typeof DOMPurify !== 'undefined') {
    return DOMPurify.sanitize(html, PURIFY_CONFIG);
  }
  return String(html).replace(/<script[\s\S]*?<\/script>/gi,'').replace(/on\w+="[^"]*"/gi,'');
}
function setHTML(el, html) {
  if (!el) return;
  el.innerHTML = safeHTML(html);
}

// ── State ──
let _opsToken       = '';
let _opsData        = null;
let _pollInterval   = null;
let _chatInterval   = null;
let _idleTimer      = null;
let _activeChatId   = null;
let _activeChatType = null;
let _chatView       = 'tickets';
let _lastMsgTs      = null;
let _allLeads       = [];
let _allDD          = [];
let _loadFailCount  = 0;

// OWASP A07: idle timeout
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
function resetIdleTimer() {
  clearTimeout(_idleTimer);
  _idleTimer = setTimeout(() => {
    if (_opsToken) forceLogout('SESSION TIMED OUT — PLEASE LOG IN AGAIN');
  }, IDLE_TIMEOUT_MS);
}
['click','keydown','mousemove','touchstart'].forEach(evt =>
  document.addEventListener(evt, resetIdleTimer, { passive: true })
);

// ── Helpers ──
function sanitize(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function timeAgo(ts) {
  if (!ts) return '—';
  const past = new Date(ts);
  if (isNaN(past.getTime())) return sanitize(String(ts).substring(0,16));
  const diff = Math.floor((Date.now()-past.getTime())/1000);
  if (diff < 60)    return 'JUST NOW';
  if (diff < 3600)  return Math.floor(diff/60)+'m ago';
  if (diff < 86400) return Math.floor(diff/3600)+'h ago';
  return Math.floor(diff/86400)+'d ago';
}
function scoreColor(n) {
  const v = parseFloat(n);
  if (isNaN(v)) return 'var(--text-muted)';
  if (v <= 3) return 'var(--success)';
  if (v <= 6) return 'var(--warning)';
  return 'var(--danger)';
}

// ── Clock ──
function updateClock() {
  const gst = new Date(Date.now() + 4 * 60 * 60 * 1000);
  const el  = document.getElementById('opsClock');
  if (el) el.textContent =
    String(gst.getUTCHours()).padStart(2,'0')+':'+
    String(gst.getUTCMinutes()).padStart(2,'0')+':'+
    String(gst.getUTCSeconds()).padStart(2,'0')+' GST';
}
setInterval(updateClock, 1000); updateClock();

// ── Session restore ──
function initializeAuth() {
  try {
    const saved = sessionStorage.getItem('romi-ops-v6-session');
    if (saved) {
      const s   = JSON.parse(saved);
      const age = Date.now() - (s.loginTime || 0);
      if (age < 8 * 60 * 60 * 1000 && s.token && /^[0-9a-f]{64}$/.test(s.token)) {
        _opsToken = s.token;
        verifySessionThenShow();
        return;
      }
    }
  } catch(_) {}
  try { sessionStorage.removeItem('romi-ops-v6-session'); } catch(_) {}
  const authOverlay = document.getElementById('authOverlay');
  if (authOverlay) authOverlay.style.display = 'flex';
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeAuth);
} else {
  initializeAuth();
}
window.addEventListener('load', initializeAuth);

async function verifySessionThenShow() {
  try {
    const res  = await fetch(`${API_URL}?action=getOpsData&opsToken=${encodeURIComponent(_opsToken)}`);
    const data = await res.json();
    if (data.error) {
      try { sessionStorage.removeItem('romi-ops-v6-session'); } catch(_) {}
      _opsToken = '';
      const authOverlay = document.getElementById('authOverlay');
      if (authOverlay) authOverlay.style.display = 'flex';
      return;
    }
    _opsData = data;
    showOpsView();
    renderAll(data);
  } catch(e) {
    try { sessionStorage.removeItem('romi-ops-v6-session'); } catch(_) {}
    _opsToken = '';
    const authOverlay = document.getElementById('authOverlay');
    if (authOverlay) authOverlay.style.display = 'flex';
  }
}

// ============================================================
// AUTH
// ============================================================
async function requestOTP() {
  const pp  = document.getElementById('passphraseInput');
  if(!pp) return;
  const val = (pp.value || '').trim();
  const btn = document.getElementById('passphraseBtn');
  const err = document.getElementById('authError1');

  if (!val || val.length < 8 || val.length > 128) {
    showAuthError(err, 'ENTER VALID PASSPHRASE'); return;
  }

  if(btn) btn.disabled = true;
  if(btn) btn.textContent = 'SENDING CODE...';
  if(err) err.style.display = 'none';

  try {
    const res  = await fetch(API_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'opsRequestOTP', passphrase: val })
    });
    const data = await res.json();
    if (data.success) {
      _opsToken = '';
      document.getElementById('_pp').value = val;
      document.getElementById('authStep1').style.display = 'none';
      document.getElementById('authStep2').style.display = 'block';
      setTimeout(() => document.getElementById('otpInput').focus(), 100);
    } else {
      showAuthError(err, data.error || 'INVALID PASSPHRASE');
      if(btn) btn.disabled = false;
      if(btn) btn.textContent = 'REQUEST ACCESS CODE →';
    }
  } catch(e) {
    showAuthError(err, 'NETWORK ERROR — RETRY');
    if(btn) btn.disabled = false;
    if(btn) btn.textContent = 'REQUEST ACCESS CODE →';
  }
}

async function verifyOpsOTP() {
  const otpInput = document.getElementById('otpInput');
  if(!otpInput) return;

  const otp = (otpInput.value || '').trim();
  const pp  = document.getElementById('_pp').value;
  const btn = document.getElementById('otpBtn');
  const err = document.getElementById('authError2');

  if (!otp || !/^\d{6}$/.test(otp)) {
    showAuthError(err, 'ENTER 6-DIGIT CODE'); return;
  }
  if (!pp) {
    showAuthError(err, 'SESSION LOST — START AGAIN'); backToPassphrase(); return;
  }

  if(btn) btn.disabled = true;
  if(btn) btn.textContent = 'VERIFYING...';
  if(err) err.style.display = 'none';

  try {
    const res  = await fetch(API_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'opsVerifyOTP', passphrase: pp, otp })
    });
    const data = await res.json();
    if (data.success && data.opsToken && /^[0-9a-f]{64}$/.test(data.opsToken)) {
      _opsToken = data.opsToken;
      try {
        sessionStorage.setItem('romi-ops-v6-session', JSON.stringify({
          token: _opsToken, loginTime: Date.now()
        }));
      } catch(_) {}
      document.getElementById('_pp').value = '';
      document.getElementById('passphraseInput').value = '';
      _loadFailCount = 0;
      showOpsView();
    } else {
      showAuthError(err, data.error || 'INVALID CODE');
      if(btn) btn.disabled = false;
      if(btn) btn.textContent = 'AUTHENTICATE →';
    }
  } catch(e) {
    showAuthError(err, 'NETWORK ERROR — RETRY');
    if(btn) btn.disabled = false;
    if(btn) btn.textContent = 'AUTHENTICATE →';
  }
}

function backToPassphrase() {
  document.getElementById('authStep2').style.display = 'none';
  document.getElementById('authStep1').style.display = 'block';
  const btn = document.getElementById('passphraseBtn');
  if(btn) btn.disabled  = false;
  if(btn) btn.textContent = 'REQUEST ACCESS CODE →';
  const otpInput = document.getElementById('otpInput');
  if(otpInput) otpInput.value = '';
  const ppInput = document.getElementById('_pp');
  if(ppInput) ppInput.value = '';
}

function showAuthError(el, msg) {
  if(!el) return;
  el.textContent   = String(msg).substring(0, 120);
  el.style.display = 'block';
}

function showOpsView() {
  const authOverlay = document.getElementById('authOverlay');
  const appView = document.getElementById('opsView');
  if(authOverlay) authOverlay.style.display = 'none';
  if(appView) appView.style.display  = 'block';
  loadOpsData();
  _pollInterval = setInterval(loadOpsData, 20000);
  resetIdleTimer();
}

function forceLogout(reason) {
  clearInterval(_pollInterval);
  clearInterval(_chatInterval);
  clearTimeout(_idleTimer);
  _opsToken = ''; _opsData = null; _loadFailCount = 0;
  try { sessionStorage.removeItem('romi-ops-v6-session'); } catch(_) {}

  const opsView = document.getElementById('opsView');
  const authOverlay = document.getElementById('authOverlay');
  if(opsView) opsView.style.display   = 'none';
  if(authOverlay) authOverlay.style.display  = 'flex';

  const step1 = document.getElementById('authStep1');
  const step2 = document.getElementById('authStep2');
  if(step1) step1.style.display = 'block';
  if(step2) step2.style.display = 'none';

  const passphraseInput = document.getElementById('passphraseInput');
  const otpInput = document.getElementById('otpInput');
  const ppInput = document.getElementById('_pp');
  if(passphraseInput) passphraseInput.value   = '';
  if(otpInput) otpInput.value          = '';
  if(ppInput) ppInput.value               = '';

  const passphraseBtn = document.getElementById('passphraseBtn');
  if(passphraseBtn) passphraseBtn.disabled  = false;
  if(passphraseBtn) passphraseBtn.textContent = 'REQUEST ACCESS CODE →';

  if (reason) {
    const err = document.getElementById('authError1');
    if(err) err.textContent    = reason;
    if(err) err.style.display  = 'block';
  }
}

function opsLogout() {
  if (!confirm('Log out of Ops Command Center?')) return;
  forceLogout(null);
}

// ============================================================
// DATA LOADING
// ============================================================
async function loadOpsData() {
  if (!_opsToken) return;
  try {
    const res  = await fetch(`${API_URL}?action=getOpsData&opsToken=${encodeURIComponent(_opsToken)}`);
    const data = await res.json();
    if (data.error === 'OPS SESSION INVALID OR EXPIRED') {
      forceLogout('SESSION EXPIRED — PLEASE LOG IN AGAIN'); return;
    }
    if (data.error) {
      _loadFailCount++;
      if (_loadFailCount >= 3) forceLogout('CONNECTION LOST — PLEASE LOG IN AGAIN');
      return;
    }
    _loadFailCount = 0;
    _opsData = data;
    renderAll(data);
  } catch(e) {
    _loadFailCount++;
    if (_loadFailCount >= 3) forceLogout('CONNECTION LOST — PLEASE LOG IN AGAIN');
  }
}

function renderAll(d) {
  renderStats(d.stats       || {});
  renderFeed(d);
  renderLeads(d.leads       || []);
  renderDD(d.ddQueue        || []);
  renderMandates(d.mandates || []);
  renderRoomsTable(d.rooms  || []);
  renderDeals(d.deals       || []);
  renderChatList(d.tickets  || [], d.rooms || []);
}

// ── Stats ──
function renderStats(s) {
  document.getElementById('statLeads').textContent     = s.totalLeads     || 0;
  document.getElementById('statApproved').textContent  = s.approved       || 0;
  document.getElementById('statDD').textContent        = s.pendingDD      || 0;
  document.getElementById('statMandates').textContent  = s.activeMandates || 0;
  document.getElementById('statRooms').textContent     = s.pendingRooms   || 0;
  document.getElementById('statTickets').textContent   = s.openTickets    || 0;
  const comm = parseFloat(s.totalCommission || 0);
  document.getElementById('statCommission').textContent = '$' + comm.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  document.getElementById('totalCommMeta').textContent  = 'TOTAL: $' + comm.toLocaleString();
  const ddBadge    = document.getElementById('ddBadge');
  const roomsBadge = document.getElementById('roomsBadge');
  if ((s.pendingDD||0) > 0)    { if(ddBadge) { ddBadge.style.display='inline-block';    ddBadge.textContent=s.pendingDD; } }    else if(ddBadge) ddBadge.style.display='none';
  if ((s.pendingRooms||0) > 0) { if(roomsBadge) { roomsBadge.style.display='inline-block'; roomsBadge.textContent=s.pendingRooms; } } else if(roomsBadge) roomsBadge.style.display='none';
}

// ── Live Feed ──
function renderFeed(d) {
  const feed  = document.getElementById('liveFeed');
  const items = [];
  (d.ddQueue||[]).filter(x => x.status==='PENDING'||x.status==='PROCESSING').forEach(x =>
    items.push({ type:'new-dd', text:`DD PENDING: ${x.company_name||x.applicant_email} — ${x.role||''} / ${x.commodity||''}`, time: x.created_at })
  );
  (d.rooms||[]).filter(r=>r.status==='PENDING_APPROVAL').forEach(r =>
    items.push({ type:'new-room', text:`ROOM REQUEST: ${r.room_name||r.commodity||r.id}`, time: r.created_at })
  );
  (d.tickets||[]).filter(t=>t.status==='OPEN').forEach(t =>
    items.push({ type:'new-msg', text:`SUPPORT: ${t.subject||'New ticket'}`, time: t.created_at })
  );
  (d.leads||[]).slice(0,5).forEach(l =>
    items.push({ type:'new-lead', text:`LEAD: ${l.full_name||l.email} — ${l.is_approved?'APPROVED':'PENDING'}`, time: l.created_at })
  );
  if (!items.length) { if(feed) feed.textContent = ''; const e=document.createElement('div'); e.className='empty-state'; e.textContent='NO RECENT ACTIVITY'; if(feed) feed.appendChild(e); return; }
  setHTML(feed, items.slice(0,20).map(item =>
    `<div class="feed-item">
      <div class="feed-dot ${sanitize(item.type)}"></div>
      <div class="feed-text">${sanitize(item.text)}</div>
      <div class="feed-time">${timeAgo(item.time)}</div>
    </div>`
  ).join(''));
}

// ── Leads ──
function renderLeads(leads) {
  _allLeads = leads;
  filterLeads(document.getElementById('leadSearch')?.value || '');
}

function filterLeads(q) {
  const q2   = (q || '').toLowerCase();
  const rows = _allLeads.filter(l =>
    !q2 || (l.email||'').includes(q2) || (l.full_name||'').toLowerCase().includes(q2) || (l.jurisdiction||'').toLowerCase().includes(q2)
  );
  const tbody = document.getElementById('leadsTbody');
  if (!rows.length) { setHTML(tbody, '<tr><td colspan="5" class="empty-state">NO LEADS FOUND</td></tr>'); return; }
  setHTML(tbody, rows.map(l => {
    const statusClass = l.is_approved ? 'status-approved' : l.is_suspended ? 'status-denied' : 'status-pending';
    const statusText  = l.is_approved ? 'APPROVED' : l.is_suspended ? 'SUSPENDED' : 'PENDING';
    return `<tr>
      <td><div style="font-size:10px;color:var(--gold);">${sanitize(l.full_name||'')}</div>
          <div style="font-size:8px;color:var(--text-muted);">${sanitize(l.email)}</div>
          <div style="font-size:8px;color:var(--text-dim);">${sanitize(l.company_name||'')}</div></td>
      <td><span class="pill pill-${sanitize((l.role||'buyer').toLowerCase())}">${sanitize(l.role||'—')}</span></td>
      <td><span class="${statusClass}">${statusText}</span></td>
      <td style="font-size:9px;color:var(--text-muted);">${sanitize(l.jurisdiction||'—')}</td>
      <td style="font-size:8px;color:var(--text-dim);">${timeAgo(l.created_at)}</td>
    </tr>`;
  }).join(''));
}

// ── DD Queue ──
function renderDD(queue) {
  _allDD = queue;
  const tbody = document.getElementById('ddTbody');
  if (!queue.length) { setHTML(tbody, '<tr><td colspan="7" class="empty-state">NO DD APPLICATIONS</td></tr>'); return; }

  setHTML(tbody, queue.map(item => {
    const statusClass = item.status === 'COMPLETED' ? 'status-approved' :
                        item.status === 'PROCESSING' ? 'status-review'  :
                        item.status === 'FAILED'     ? 'status-denied'  : 'status-pending';

    const verdictHtml = item.verdict
      ? `<span class="${item.verdict === 'GO' ? 'verdict-go' : item.verdict === 'NO-GO' ? 'verdict-nogo' : 'verdict-conditional'}">${sanitize(item.verdict)}</span>`
      : '<span style="color:var(--text-dim)">—</span>';

    const roleClass = (item.role||'').toLowerCase().replace('_','-');

    return `<tr>
      <td><div style="color:var(--gold);font-size:10px;">${sanitize(item.company_name||'')}</div>
          <div style="font-size:8px;color:var(--text-muted);">${sanitize(item.applicant_email||'')}</div></td>
      <td><span class="pill pill-${sanitize(roleClass)}">${sanitize(item.role||'—')}</span></td>
      <td style="font-size:9px;">${sanitize(item.commodity||'—')}</td>
      <td><span class="${statusClass}">${sanitize(item.status||'—')}</span></td>
      <td>${verdictHtml}</td>
      <td style="font-size:8px;color:var(--text-dim);">${timeAgo(item.created_at)}</td>
      <td><div style="display:flex;gap:4px;flex-wrap:wrap;">
        <button class="action-btn" data-id="${sanitize(item.id)}" data-action="review">REVIEW</button>
        ${item.status === 'COMPLETED' && !item.human_reviewed ? `
        <button class="action-btn approve" data-email="${sanitize(item.applicant_email)}" data-decision="APPROVED" data-action="ddbtn">✓ APPROVE</button>
        <button class="action-btn deny"    data-email="${sanitize(item.applicant_email)}" data-decision="REJECTED" data-action="ddbtn">✗ REJECT</button>` : ''}
        ${item.report_pdf_path ? `<button class="action-btn" data-path="${sanitize(item.report_pdf_path)}" data-action="dlpdf" style="font-size:8px;">PDF</button>` : ''}
      </div></td>
    </tr>`;
  }).join(''));
}

// ── Mandates ──
function renderMandates(mandates) {
  const tbody = document.getElementById('mandatesTbody');
  if (!mandates.length) { setHTML(tbody, '<tr><td colspan="6" class="empty-state">NO ACTIVE MANDATES</td></tr>'); return; }
  setHTML(tbody, mandates.map(m =>
    `<tr>
      <td><span class="pill pill-${sanitize((m.mandate_type||'buy').toLowerCase())}">${sanitize(m.mandate_type||'')}</span></td>
      <td style="color:var(--gold);font-size:10px;">${sanitize(m.commodity||'')}</td>
      <td style="font-size:9px;">${sanitize(String(m.quantity_mt||''))} MT</td>
      <td style="font-size:9px;">${m.price_usd_per_mt ? '$'+sanitize(String(m.price_usd_per_mt)) : 'NEGOTIABLE'}</td>
      <td style="font-size:9px;">${sanitize(m.incoterms||'—')}</td>
      <td style="font-size:8px;color:var(--text-dim);">${timeAgo(m.created_at)}</td>
    </tr>`
  ).join(''));
}

// ── Trade Rooms table ──
function renderRoomsTable(rooms) {
  const tbody = document.getElementById('roomsTbody');
  if (!rooms.length) { setHTML(tbody, '<tr><td colspan="5" class="empty-state">NO TRADE ROOMS</td></tr>'); return; }
  setHTML(tbody, rooms.map(r => {
    const isPending = r.status === 'PENDING_APPROVAL';
    const sc        = isPending ? 'status-review' : r.status === 'ACTIVE' ? 'status-approved' : 'status-denied';
    const safeId    = sanitize(r.id||'');
    return `<tr>
      <td style="font-size:9px;color:var(--gold);">${sanitize(r.room_name||safeId)}</td>
      <td style="font-size:9px;">${sanitize(r.commodity||'—')}</td>
      <td><span class="${sc}">${sanitize(r.status||'')}</span></td>
      <td style="font-size:8px;color:var(--text-dim);">${timeAgo(r.created_at)}</td>
      <td><div style="display:flex;gap:3px;flex-wrap:wrap;">
        ${isPending
          ? `<button class="action-btn approve" data-roomid="${safeId}" data-decision="APPROVE" data-action="roomapprove">✓ APPROVE</button>
             <button class="action-btn deny"    data-roomid="${safeId}" data-decision="DENY"    data-action="roomapprove">✗ DENY</button>`
          : ''}
        ${r.status === 'ACTIVE'
          ? `<button class="action-btn close-room" data-roomid="${safeId}" data-action="roomclose">CLOSE</button>`
          : ''}
      </div></td>
    </tr>`;
  }).join(''));
}

// ── Deals ──
function renderDeals(deals) {
  const tbody = document.getElementById('dealsTbody');
  if (!deals.length) { setHTML(tbody, '<tr><td colspan="5" class="empty-state">NO DEALS REPORTED</td></tr>'); return; }
  setHTML(tbody, deals.map(d => {
    const comm = d.value_usd ? (parseFloat(d.value_usd) * 0.02).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2}) : '—';
    return `<tr>
      <td style="font-size:9px;color:var(--gold);">${sanitize(d.commodity||'')}</td>
      <td style="font-size:9px;">${sanitize(String(d.quantity_mt||''))} MT</td>
      <td style="font-size:9px;">$${sanitize(String(d.value_usd||'0'))}</td>
      <td style="font-size:9px;color:var(--success);">$${comm}</td>
      <td style="font-size:8px;color:var(--text-dim);">${timeAgo(d.closed_at)}</td>
    </tr>`;
  }).join(''));
}

// ── Chat list ──
function renderChatList(tickets, rooms) {
  const panel = document.getElementById('chatListPanel');
  if (_chatView === 'tickets') {
    const tb = document.getElementById('ticketsBadge');
    if (tickets.length > 0) { if(tb) { tb.style.display='inline-block'; tb.textContent=tickets.length; } } else if(tb) tb.style.display='none';
    if (!tickets.length) { setHTML(panel, '<div class="empty-state" style="padding:16px;">NO OPEN TICKETS</div>'); return; }
    setHTML(panel, tickets.map(t =>
      `<div class="chat-list-item${_activeChatId===t.id?' active':''}"
        data-id="${sanitize(t.id)}" data-type="support" data-label="${sanitize(t.subject||'Support')}"
        data-action="chatclick">
        <div class="cli-name">${sanitize(t.subject||'Support Ticket')}</div>
        <div class="cli-sub">${sanitize(t.status||'')} · ${timeAgo(t.updated_at)}</div>
      </div>`
    ).join(''));
  } else {
    const rb = document.getElementById('tradeRoomsBadge');
    const activeRooms = rooms.filter(r => r.status === 'ACTIVE' || r.status === 'PENDING_APPROVAL');
    if (activeRooms.length > 0) { if(rb) { rb.style.display='inline-block'; rb.textContent=activeRooms.length; } } else if(rb) rb.style.display='none';
    if (!activeRooms.length) { setHTML(panel, '<div class="empty-state" style="padding:16px;">NO ACTIVE TRADE ROOMS</div>'); return; }
    setHTML(panel, activeRooms.map(r =>
      `<div class="chat-list-item${_activeChatId===r.id?' active':''}"
        data-id="${sanitize(r.id)}" data-type="trade" data-label="${sanitize(r.room_name||r.commodity||r.id)}"
        data-action="chatclick">
        <div class="cli-name">${sanitize(r.room_name||r.commodity||'Trade Room')}</div>
        <div class="cli-sub">${sanitize(r.status||'')} · ${timeAgo(r.updated_at)}</div>
      </div>`
    ).join(''));
  }
}

// ============================================================
// OPS ACTIONS
// ============================================================

// BUG-11 FIX: opsDD() now reads decision_token from _opsData.ddQueue.
// Worker validates 'token' against dd_queue.decision_token (Python HMAC).
// Previously sent _opsToken (session token) which never matched.
async function opsDD(email, decision) {
  if (!confirm(`${decision === 'APPROVED' ? 'APPROVE' : 'REJECT'} DD application for ${email}?`)) return;

  // Read the correct decision token from the already-loaded ddQueue data
  const ddRow = (_opsData?.ddQueue || []).find(d =>
    (d.applicant_email || '').toLowerCase() === email.toLowerCase()
  );
  const decisionToken = decision === 'APPROVED'
    ? ddRow?.decision_token
    : ddRow?.decision_token_reject;

  if (!decisionToken) {
    alert('DECISION TOKEN NOT FOUND — DD report may not be complete yet.\nRefresh the dashboard and retry.');
    return;
  }

  let reason = '';
  if (decision === 'REJECTED') {
    reason = prompt('Rejection reason (shown to applicant):') || 'Rejected by ops.';
  }
  try {
    const action = decision === 'APPROVED' ? 'approveDDReview' : 'rejectDDReview';
    const body = {
      action,
      opsToken: _opsToken,     // session auth — required by Worker schema
      email,
      token:    decisionToken, // BUG-11 FIX: Python HMAC from dd_queue row
    };
    if (reason) body.reason = reason;
    const res = await fetch(API_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    alert(`✓ DD ${decision} recorded for ${email}`);
    setTimeout(loadOpsData, 1000);
  } catch(e) { alert('NETWORK ERROR — RETRY'); }
}

async function opsApproveRoom(roomId, decision) {
  if (!confirm(`${decision} trade room?`)) return;
  try {
    const res  = await fetch(API_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'approveRoom', opsToken: _opsToken, roomId, decision })
    });
    const data = await res.json();
    if (data.success) loadOpsData();
    else alert(data.error || 'ACTION FAILED');
  } catch(e) { alert('NETWORK ERROR'); }
}

async function opsApproveCloseRoom(roomId) {
  const id = roomId || _activeChatId;
  if (!id) return;
  if (!confirm('Close this trade room? All messages are retained for compliance.')) return;
  try {
    const res  = await fetch(API_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'closeRoom', opsToken: _opsToken, roomId: id })
    });
    const data = await res.json();
    if (data.success) {
      _activeChatId = null; _lastMsgTs = null;
      if (_chatInterval) clearInterval(_chatInterval);
      const msgContainer = document.getElementById('opsChatMessages');
      if(msgContainer) msgContainer.textContent  = '';
      const e = document.createElement('div'); e.className='empty-state'; e.textContent='Room closed — messages retained for compliance';
      if(msgContainer) msgContainer.appendChild(e);
      const inputRow = document.getElementById('opsInputRow');
      if(inputRow) inputRow.style.display  = 'none';
      const closeBtn = document.getElementById('closeRoomBtn');
      if(closeBtn) closeBtn.style.display = 'none';
      const roomInfoBar = document.getElementById('roomInfoBar');
      if(roomInfoBar) roomInfoBar.style.display  = 'none';
      const title = document.getElementById('chatAreaTitle');
      if(title) title.textContent  = 'SELECT A CONVERSATION';
      loadOpsData();
    } else alert(data.error||'FAILED');
  } catch(e) { alert('NETWORK ERROR'); }
}

async function opsCloseTicket() {
  if (!_activeChatId) return;
  if (!confirm('Close this support ticket? All messages are retained.')) return;
  try {
    const res  = await fetch(API_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'closeTicket', opsToken: _opsToken, ticketId: _activeChatId })
    });
    const data = await res.json();
    if (data.success) {
      _activeChatId = null; _lastMsgTs = null;
      if (_chatInterval) clearInterval(_chatInterval);
      const msgContainer = document.getElementById('opsChatMessages');
      if(msgContainer) msgContainer.textContent    = '';
      const e = document.createElement('div'); e.className='empty-state'; e.textContent='Ticket closed — messages retained for compliance';
      if(msgContainer) msgContainer.appendChild(e);
      const inputRow = document.getElementById('opsInputRow');
      if(inputRow) inputRow.style.display    = 'none';
      const closeBtn = document.getElementById('closeTicketBtn');
      if(closeBtn) closeBtn.style.display = 'none';
      const roomInfoBar = document.getElementById('roomInfoBar');
      if(roomInfoBar) roomInfoBar.style.display    = 'none';
      const title = document.getElementById('chatAreaTitle');
      if(title) title.textContent    = 'SELECT A CONVERSATION';
      loadOpsData();
    } else alert(data.error || 'FAILED TO CLOSE TICKET');
  } catch(e) { alert('NETWORK ERROR'); }
}

// ── Tab switches ──
function switchOpsTab(tab, btn) {
  if(btn) {
    const siblings = btn.closest('.ops-tab-bar').querySelectorAll('.ops-tab');
    siblings.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }
  ['dd','mandates','rooms'].forEach(t => {
    const el = document.getElementById('opsTab-'+t);
    if (el) el.style.display = 'none';
  });
  const pane = document.getElementById('opsTab-'+tab);
  if (pane) pane.style.display = 'block';
}

function switchChatView(view, btn) {
  _chatView = view;
  if(btn) {
    const siblings = btn.closest('.ops-tab-bar').querySelectorAll('.ops-tab');
    siblings.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }
  if (_opsData) renderChatList(_opsData.tickets||[], _opsData.rooms||[]);
}

// ── Chat ──
async function openOpsChat(roomId, type, label) {
  _activeChatId   = roomId;
  _activeChatType = type;
  _lastMsgTs      = null;

  const labelEl = document.getElementById('activeChatLabel');
  const titleEl = document.getElementById('chatAreaTitle');
  if(labelEl) labelEl.textContent = sanitize(label);
  if(titleEl) titleEl.textContent   = sanitize(label);

  const inputRow = document.getElementById('opsInputRow');
  const closeRoomBtn = document.getElementById('closeRoomBtn');
  const closeTicketBtn = document.getElementById('closeTicketBtn');

  if(inputRow) inputRow.style.display    = 'flex';
  if(closeRoomBtn) closeRoomBtn.style.display   = type === 'trade'   ? 'inline-block' : 'none';
  if(closeTicketBtn) closeTicketBtn.style.display = type === 'support' ? 'inline-block' : 'none';

  const msgContainer = document.getElementById('opsChatMessages');
  if(msgContainer) msgContainer.innerHTML = '';
  const emptyDiv = document.createElement('div');
  emptyDiv.className = 'empty-state';
  emptyDiv.textContent = 'LOADING...';
  if(msgContainer) msgContainer.appendChild(emptyDiv);

  // Room info bar
  const infoBar = document.getElementById('roomInfoBar');
  if (type === 'trade' && _opsData) {
    const room = (_opsData.rooms||[]).find(r => r.id === roomId);
    if (room && infoBar) {
      infoBar.style.display = 'block';
      const nameEl = document.getElementById('roomInfoName');
      const statusEl = document.getElementById('roomInfoStatus');
      const pendingBtns = document.getElementById('roomInfoPending');
      if(nameEl) nameEl.textContent   = sanitize(room.room_name || roomId);
      if(statusEl) statusEl.textContent = sanitize(room.status || '');
      const isPending = room.status === 'PENDING_APPROVAL';
      if(pendingBtns) pendingBtns.style.display = isPending ? 'flex' : 'none';
      if(inputRow) inputRow.style.display     = room.status === 'ACTIVE' ? 'flex' : 'none';
    }
  } else {
    if(infoBar) infoBar.style.display = 'none';
  }

  await loadOpsChatMessages();
  try {
    await fetch(API_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'opsMarkRead', opsToken: _opsToken, roomId })
    });
  } catch(_) {}
  if (_chatInterval) clearInterval(_chatInterval);
  _chatInterval = setInterval(loadOpsChatMessages, 10000);
  if (_opsData) renderChatList(_opsData.tickets||[], _opsData.rooms||[]);
}

async function opsApproveCurrent(decision) {
  if (!_activeChatId) return;
  await opsApproveRoom(_activeChatId, decision);
  const pendingBtns = document.getElementById('roomInfoPending');
  const inputRow = document.getElementById('opsInputRow');
  if(pendingBtns) pendingBtns.style.display = 'none';
  if(inputRow) inputRow.style.display     = decision === 'APPROVE' ? 'flex' : 'none';
}

// BUG-13 FIX: opsToken now appended to getMessages URL.
// Worker M-06 patch requires valid opsToken in KV ops_session
// to grant isOps access. Without it, request fell through to
// email-based access control, blocking helpdesk messaging.
async function loadOpsChatMessages() {
  if (!_activeChatId || !_opsToken) return;
  try {
    let url = `${API_URL}?action=getMessages&email=ops@rominexus.com&roomId=${encodeURIComponent(_activeChatId)}&opsToken=${encodeURIComponent(_opsToken)}`;
    if (_lastMsgTs) url += `&since=${encodeURIComponent(_lastMsgTs)}`;

    const res  = await fetch(url);
    const data = await res.json();
    const container = document.getElementById('opsChatMessages');

    if (!data.messages || !data.messages.length) {
      if (!_lastMsgTs && container) { container.textContent=''; const e=document.createElement('div'); e.className='empty-state'; e.textContent='NO MESSAGES YET'; container.appendChild(e); }
      return;
    }
    if (!_lastMsgTs && container) container.textContent = '';

    data.messages.forEach(m => {
      const isOps       = m.message_type === 'SYSTEM';
      const div     = document.createElement('div');
      div.className = 'ops-msg-row ' + (isOps ? 'mine' : 'theirs');

      const ts    = m.created_at ? new Date(m.created_at) : new Date();
      const gst   = new Date(ts.getTime() + 4*60*60*1000);
      const tStr  = String(gst.getUTCHours()).padStart(2,'0')+':'+String(gst.getUTCMinutes()).padStart(2,'0')+' GST';

      const senderEl = document.createElement('div');
      const bubbleEl = document.createElement('div');
      const metaEl   = document.createElement('div');

      senderEl.className = 'ops-msg-sender';
      bubbleEl.className = 'ops-bubble';
      metaEl.className   = 'ops-msg-meta';

      senderEl.textContent = isOps ? '[ROMI DESK]' : '[CLIENT]';

      try {
        bubbleEl.textContent = decodeURIComponent(escape(atob(m.message_ciphertext || '')));
      } catch(_) {
        bubbleEl.textContent = m.message_ciphertext || '';
      }

      metaEl.textContent = tStr;
      div.appendChild(senderEl);
      div.appendChild(bubbleEl);
      div.appendChild(metaEl);
      if(container) container.appendChild(div);
      _lastMsgTs = m.created_at;
    });
    if(container) container.scrollTop = container.scrollHeight;
  } catch(e) {
    const container = document.getElementById('opsChatMessages');
    if (!_lastMsgTs && container) { container.textContent=''; const e2=document.createElement('div'); e2.className='empty-state'; e2.textContent='ERROR LOADING — RETRY'; container.appendChild(e2); }
  }
}

async function opsSendMessage() {
  if (!_activeChatId || !_opsToken) return;
  const input = document.getElementById('opsMessageInput');
  const msg   = (input?.value || '').trim();
  if (!msg) return;
  if (msg.length > 2000) { alert('MESSAGE TOO LONG — MAX 2000 CHARACTERS'); return; }
  if(input) input.value = '';
  try {
    const res  = await fetch(API_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action:   'opsReply',
        opsToken: _opsToken,
        roomId:   _activeChatId,
        message:  msg,
        roomType: _activeChatType || 'support'
      })
    });
    const data = await res.json();
    if (data.success) {
      _lastMsgTs = null;
      await loadOpsChatMessages();
    } else if (data.error === 'OPS SESSION INVALID OR EXPIRED') {
      forceLogout('SESSION EXPIRED — PLEASE LOG IN AGAIN');
    }
  } catch(e) {
    console.error('opsSendMessage error:', e);
    const container = document.getElementById('opsChatMessages');
    const errDiv = document.createElement('div');
    errDiv.className = 'empty-state';
    errDiv.style.color = 'var(--danger)';
    errDiv.textContent = 'SEND FAILED — RETRY';
    if(container) container.appendChild(errDiv);
  }
}

// ============================================================
// DD MODAL
// ============================================================
function openDDModal(btn) {
  const id   = btn.getAttribute('data-id');
  const item = (_opsData?.ddQueue || []).find(d => d.id === id);
  if (!item) return;

  const modalTitle = document.getElementById('modalTitle');
  if(modalTitle) modalTitle.textContent = `DD REVIEW — ${item.company_name || item.applicant_email}`;

  const pillarScores = item.pillar_scores || {};
  const missingDocs  = item.missing_docs  || [];

  let html = `<div class="modal-section">
    <div class="modal-section-title">APPLICANT DETAILS</div>
    <div class="modal-row"><div class="modal-key">COMPANY</div><div class="modal-val">${sanitize(item.company_name||'')}</div></div>
    <div class="modal-row"><div class="modal-key">EMAIL</div><div class="modal-val">${sanitize(item.applicant_email||'')}</div></div>
    <div class="modal-row"><div class="modal-key">JURISDICTION</div><div class="modal-val">${sanitize(item.jurisdiction||'')}</div></div>
    <div class="modal-row"><div class="modal-key">ROLE</div><div class="modal-val">${sanitize(item.role||'')}</div></div>
    <div class="modal-row"><div class="modal-key">COMMODITY</div><div class="modal-val">${sanitize(item.commodity||'')}</div></div>
    <div class="modal-row"><div class="modal-key">STATUS</div><div class="modal-val">${sanitize(item.status||'')}</div></div>
    <div class="modal-row"><div class="modal-key">CERTIFIED</div><div class="modal-val" style="color:${item.certified?'var(--success)':'var(--danger)'}">${item.certified ? '✓ LEGAL DECLARATION SIGNED' : '✗ NOT CERTIFIED'}</div></div>
    <div class="modal-row"><div class="modal-key">SUBMITTED</div><div class="modal-val">${item.created_at ? new Date(item.created_at).toLocaleString('en-GB') : '—'}</div></div>
  </div>`;

  if (item.target_volume || item.target_price || item.incoterms || item.banking) {
    html += `<div class="modal-section">
      <div class="modal-section-title">BUYER TRADE DETAILS</div>
      ${item.target_volume ? `<div class="modal-row"><div class="modal-key">TARGET VOLUME</div><div class="modal-val">${sanitize(item.target_volume)}</div></div>` : ''}
      ${item.target_price  ? `<div class="modal-row"><div class="modal-key">TARGET PRICE</div><div class="modal-val">${sanitize(item.target_price)}</div></div>` : ''}
      ${item.incoterms     ? `<div class="modal-row"><div class="modal-key">INCOTERMS</div><div class="modal-val">${sanitize(item.incoterms)}</div></div>` : ''}
      ${item.banking       ? `<div class="modal-row"><div class="modal-key">BANKING</div><div class="modal-val">${sanitize(item.banking)}</div></div>` : ''}
    </div>`;
  }

  if (missingDocs.length) {
    html += `<div class="modal-section">
      <div class="modal-section-title" style="color:var(--warning);">⚠ MISSING DOCUMENTS (${missingDocs.length})</div>
      <div style="padding:8px 0;">${missingDocs.map(d => `<span class="missing-doc-tag">${sanitize(d)}</span>`).join('')}</div>
    </div>`;
  }

  if (item.verdict) {
    const vc = item.verdict === 'GO' ? 'var(--success)' : item.verdict === 'NO-GO' ? 'var(--danger)' : 'var(--warning)';
    html += `<div class="modal-section">
      <div class="modal-section-title">AI VERDICT</div>
      <div style="font-size:20px;font-weight:700;color:${vc};letter-spacing:4px;margin-bottom:8px;">${sanitize(item.verdict)}</div>
      ${pillarScores.risk_score !== undefined ? `<div class="modal-row"><div class="modal-key">RISK SCORE</div><div class="modal-val" style="color:${scoreColor(pillarScores.risk_score)}">${pillarScores.risk_score}/10</div></div>` : ''}
      ${pillarScores.confidence !== undefined ? `<div class="modal-row"><div class="modal-key">CONFIDENCE</div><div class="modal-val">${pillarScores.confidence}%</div></div>` : ''}
      ${pillarScores.enhanced !== undefined   ? `<div class="modal-row"><div class="modal-key">ENHANCED REVIEW</div><div class="modal-val" style="color:${pillarScores.enhanced?'var(--warning)':'var(--success)'}">${pillarScores.enhanced ? '⚠ YES — HUMAN SIGN-OFF REQUIRED' : '✓ NO'}</div></div>` : ''}
      ${item.executive_summary ? `<div style="margin-top:8px;font-size:9px;color:var(--text-muted);line-height:1.7;padding:8px;background:var(--bg-card);border:1px solid var(--border);">${sanitize(item.executive_summary)}</div>` : ''}
    </div>`;
  }

  // BUG-12 FIX: pillar labels now match Python worker v4.4.0 output exactly
  const pillars = [
    ['PILLAR 1 — ENTITY VERIFICATION',  'pillar1'],
    ['PILLAR 2 — BENEFICIAL OWNERSHIP', 'pillar2'],
    ['PILLAR 3 — SANCTIONS SCREENING',  'pillar3'],
    ['PILLAR 4 — NEGATIVE NEWS',        'pillar4'],
    ['PILLAR 5 — FINANCIAL HEALTH',     'pillar5'],
    ['PILLAR 6 — LEGAL & REGULATORY',   'pillar6'],
  ];
  const hasPillars = pillars.some(([,k]) => pillarScores[k]);
  if (hasPillars) {
    html += `<div class="modal-section"><div class="modal-section-title">6-PILLAR ASSESSMENT</div>`;
    pillars.forEach(([label, key]) => {
      if (pillarScores[key]) {
        const isFlag = pillarScores[key].includes('⚠') || pillarScores[key].toUpperCase().includes('HIT') || pillarScores[key].toUpperCase().includes('CRITICAL');
        html += `<div class="pillar-block">
          <div class="pillar-label">${label}</div>
          <div class="pillar-text" style="${isFlag ? 'color:var(--warning)' : ''}">${sanitize(pillarScores[key])}</div>
        </div>`;
      }
    });
    html += `</div>`;
  }

  setHTML(document.getElementById('modalBody'), html);

  let actHtml = '';
  if (item.status === 'COMPLETED' && !item.human_reviewed) {
    actHtml = `
      <button class="action-btn approve" style="padding:8px 16px;font-size:10px;" data-email="${sanitize(item.applicant_email)}" data-decision="APPROVED" data-action="ddbtn-modal">✓ APPROVE & CREATE USER</button>
      <button class="action-btn deny"    style="padding:8px 16px;font-size:10px;" data-email="${sanitize(item.applicant_email)}" data-decision="REJECTED" data-action="ddbtn-modal">✗ REJECT APPLICATION</button>`;
  } else if (item.human_reviewed) {
    actHtml = `<span style="font-size:9px;color:var(--text-muted);">✓ HUMAN REVIEWED — DECISION RECORDED</span>`;
  } else {
    actHtml = `<span style="font-size:9px;color:var(--text-muted);">DD PROCESSING IN PROGRESS — AWAITING AI REPORT</span>`;
  }
  if (item.report_pdf_path) {
    actHtml += `<button class="action-btn" data-path="${sanitize(item.report_pdf_path)}" data-action="dlpdf" style="padding:8px 16px;font-size:10px;">📄 DOWNLOAD PDF REPORT</button>`;
  }
  if (item.audit_reasoning) {
    actHtml += `<button class="action-btn" data-action="audittrail" style="padding:8px 16px;font-size:10px;" data-id="${sanitize(item.id)}">🔍 VIEW AUDIT TRAIL</button>`;
  }
  setHTML(document.getElementById('modalActions'), actHtml);

  const overlay = document.getElementById('ddModal');
  if(overlay) overlay.classList.add('open');
}

function closeModal() {
  const overlay = document.getElementById('ddModal');
  if(overlay) overlay.classList.remove('open');
}

async function downloadDDReport(btn) {
  const path = btn.getAttribute('data-path');
  if (!path || !_opsToken) return;
  btn.disabled = true; btn.textContent = '...';
  try {
    const res = await fetch(
      `${API_URL}?action=getDDReport&path=${encodeURIComponent(path)}&opsToken=${encodeURIComponent(_opsToken)}`
    );
    if (!res.ok) { alert('PDF NOT AVAILABLE'); return; }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `DD_Report_${path.split('/').pop()}.pdf`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
  } catch(e) { alert('DOWNLOAD ERROR — RETRY'); }
  btn.disabled = false; btn.textContent = 'PDF';
}

function openReasoningModal(content) {
  const el = document.getElementById('reasoningContent');
  const modal = document.getElementById('reasoningModal');
  if (el) el.textContent = content || 'No audit reasoning available for this record.';
  if (modal) modal.style.display = 'flex';
}
function closeReasoningModal() {
  const modal = document.getElementById('reasoningModal');
  if (modal) modal.style.display = 'none';
}

// ============================================================
// UNIVERSAL EVENT DELEGATION
// ============================================================
document.addEventListener('click', function(e) {
  const actionBtn = e.target.closest('[data-action]');
  if (actionBtn) {
    const action   = actionBtn.getAttribute('data-action');
    const id       = actionBtn.getAttribute('data-id');
    const email    = actionBtn.getAttribute('data-email');
    const decision = actionBtn.getAttribute('data-decision');
    const roomid   = actionBtn.getAttribute('data-roomid');
    const path     = actionBtn.getAttribute('data-path');

    if (action === 'review') openDDModal(actionBtn);
    if (action === 'ddbtn' || action === 'ddbtn-modal') {
      if (email && decision) opsDD(email, decision);
      if (action === 'ddbtn-modal') closeModal();
    }
    if (action === 'dlpdf') downloadDDReport(actionBtn);
    if (action === 'roomapprove' && roomid && decision) opsApproveRoom(roomid, decision);
    if (action === 'roomclose' && roomid) opsApproveCloseRoom(roomid);
    if (action === 'chatclick') {
      const roomId = actionBtn.getAttribute('data-id');
      const type   = actionBtn.getAttribute('data-type');
      const label  = actionBtn.getAttribute('data-label');
      if (roomId && type && label) openOpsChat(roomId, type, label);
    }
    if (action === 'audittrail') {
      const item = (_opsData?.ddQueue || []).find(d => d.id === id);
      openReasoningModal(item?.audit_reasoning || '');
    }
  }

  if (e.target.id === 'passphraseBtn') requestOTP();
  if (e.target.id === 'otpBtn') verifyOpsOTP();
  if (e.target.id === 'backBtn') backToPassphrase();
  if (e.target.classList.contains('modal-close')) closeModal();
  if (e.target.id === 'closeReasoningBtn') closeReasoningModal();
  if (e.target.classList.contains('ops-logout-btn')) opsLogout();
  if (e.target.id === 'refreshBtn') loadOpsData();
  if (e.target.id === 'approveRoomBtn') opsApproveCurrent('APPROVE');
  if (e.target.id === 'denyRoomBtn') opsApproveCurrent('DENY');
  if (e.target.id === 'opsSendBtn') opsSendMessage();
  if (e.target.id === 'closeTicketBtn') opsCloseTicket();
  if (e.target.id === 'closeRoomBtn') opsApproveCloseRoom();
});

document.addEventListener('change', function(e) {
  if (e.target.id === 'leadSearch') filterLeads(e.target.value);
});

document.addEventListener('click', function(e) {
  const tabBtn = e.target.closest('.ops-tab');
  if (!tabBtn) return;
  const tabName  = tabBtn.getAttribute('data-tab');
  if (tabName) { switchOpsTab(tabName, tabBtn); return; }
  const chatView = tabBtn.getAttribute('data-chat-view');
  if (chatView) { switchChatView(chatView, tabBtn); return; }
});

document.addEventListener('keydown', function(e) {
  if (e.key === 'Enter') {
    if (e.target.id === 'passphraseInput') requestOTP();
    if (e.target.id === 'otpInput') verifyOpsOTP();
    if (e.target.id === 'opsMessageInput' && !e.shiftKey) {
      e.preventDefault();
      opsSendMessage();
    }
  }
});

document.addEventListener('input', function(e) {
  if (e.target.id === 'otpInput') {
    const cleaned = e.target.value.replace(/\D/g,'').slice(0,6);
    if (e.target.value !== cleaned) e.target.value = cleaned;
  }
});
