// ============================================================
// ops.js SURGICAL PATCH — Apply these TWO changes manually
// to js/ops.js in your repository.
// ============================================================

// ══════════════════════════════════════════════════════════════
// PATCH 1 — BUG-11: opsDD() decision token fix
// In ops.js, find the opsDD() function and replace the ENTIRE
// function body with the version below.
//
// ROOT CAUSE: Worker handleApproveDDReview() validates 'token'
// against dd_queue.decision_token (a Python HMAC written by
// the DD worker). Sending opsToken (a session token) as 'token'
// will never match — approve/reject always returns INVALID TOKEN.
// ══════════════════════════════════════════════════════════════

// FIND this function:
/*
async function opsDD(email, decision) {
  if (!confirm(`${decision === 'APPROVED' ? 'APPROVE' : 'REJECT'} DD application for ${email}?`)) return;
  let reason = '';
  if (decision === 'REJECTED') {
    reason = prompt('Rejection reason (shown internally):') || 'Rejected by ops.';
  }
  try {
    const action = decision === 'APPROVED' ? 'approveDDReview' : 'rejectDDReview';
    const body = {
      action,
      opsToken: _opsToken,
      email,
      token:    _opsToken,   // <-- THIS IS THE BUG (wrong token)
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
*/

// REPLACE WITH:
async function opsDD(email, decision) {
  if (!confirm(`${decision === 'APPROVED' ? 'APPROVE' : 'REJECT'} DD application for ${email}?`)) return;

  // BUG-11 FIX: read the decision_token from the already-loaded _opsData.ddQueue row.
  // Worker validates token against dd_queue.decision_token (Python HMAC from DD worker).
  // opsToken is a session token and will never match that HMAC.
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
      token:    decisionToken, // BUG-11 FIX: actual Python HMAC from dd_queue row
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


// ══════════════════════════════════════════════════════════════
// PATCH 2 — BUG-12: Pillar labels in openDDModal()
// In ops.js, inside the openDDModal() function, find the
// 'const pillars' array and replace ALL six label strings.
//
// ROOT CAUSE: Python worker v4.4.0 pillar1-6 contains:
//   pillar1 = ENTITY VERIFICATION
//   pillar2 = BENEFICIAL OWNERSHIP
//   pillar3 = SANCTIONS SCREENING
//   pillar4 = NEGATIVE NEWS
//   pillar5 = FINANCIAL HEALTH
//   pillar6 = LEGAL & REGULATORY
// The old labels (OPERATIONAL INTEGRITY, PRODUCT/TECHNICAL MOAT,
// MARKET POSITION, CULTURAL/STRATEGIC FIT) were placeholder
// generic labels that never matched the Python output.
// ══════════════════════════════════════════════════════════════

// FIND:
/*
  const pillars = [
    ['PILLAR 1 — LEGAL & REGULATORY',      'pillar1'],
    ['PILLAR 2 — FINANCIAL HEALTH',         'pillar2'],
    ['PILLAR 3 — OPERATIONAL INTEGRITY',    'pillar3'],
    ['PILLAR 4 — PRODUCT / TECHNICAL MOAT', 'pillar4'],
    ['PILLAR 5 — MARKET POSITION',          'pillar5'],
    ['PILLAR 6 — CULTURAL / STRATEGIC FIT', 'pillar6'],
  ];
*/

// REPLACE WITH:
  // BUG-12 FIX: labels now match Python worker v4.4.0 pillar1-6 output
  const pillars = [
    ['PILLAR 1 — ENTITY VERIFICATION',   'pillar1'],
    ['PILLAR 2 — BENEFICIAL OWNERSHIP',  'pillar2'],
    ['PILLAR 3 — SANCTIONS SCREENING',   'pillar3'],
    ['PILLAR 4 — NEGATIVE NEWS',         'pillar4'],
    ['PILLAR 5 — FINANCIAL HEALTH',      'pillar5'],
    ['PILLAR 6 — LEGAL & REGULATORY',    'pillar6'],
  ];

// ══════════════════════════════════════════════════════════════
// NOTE: The rest of ops.js is correct and does NOT need changes.
// The getOpsData Bug-14 fix (opsToken in URL query param) is
// already applied in the current file (v6.1-sec FIXED v3.7).
// ══════════════════════════════════════════════════════════════
