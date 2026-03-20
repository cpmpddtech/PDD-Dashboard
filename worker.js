/**
 * ═══════════════════════════════════════════════════════════════
 *  PDP Dashboard — Cloudflare Worker v2.6.0
 *  Handles: auth, user management, data fetch, check-in writes,
 *           email alerts, audit logging, DCR Google Drive storage
 * ═══════════════════════════════════════════════════════════════
 *
 *  ENVIRONMENT VARIABLES (Workers → Settings → Variables & Secrets):
 *
 *    USERS_CONFIG          → JSON user store (managed by admin via dashboard)
 *    CF_API_TOKEN          → Cloudflare API token (to update USERS_CONFIG secret)
 *    CF_ACCOUNT_ID         → Cloudflare Account ID
 *    CF_WORKER_SCRIPT_NAME → Worker script name (e.g. pdp-dashboard)
 *    GOOGLE_API_KEY        → Google Sheets API key (read)
 *    SPREADSHEET_ID        → Google Sheet ID
 *    GMAIL_CLIENT_ID       → OAuth2 client ID (from Google Cloud Console)
 *    GMAIL_CLIENT_SECRET   → OAuth2 client secret
 *    GMAIL_REFRESH_TOKEN   → OAuth2 refresh token
 *    ALERT_EMAIL_TO        → email address to send alerts to
 *    ALERT_THRESHOLD       → number e.g. 0.70 for 70% threshold
 *    DRIVE_REFRESH_TOKEN   → OAuth2 refresh token with drive.file + spreadsheets + gmail.send scopes
 *    DRIVE_FOLDER_ID       → Google Drive folder ID for PDP_DCR_Reports
 *
 *  ── INITIAL USERS_CONFIG SETUP ──────────────────────────────
 *  Add this minimal JSON as a Secret in Cloudflare:
 *  Workers → pdp-dashboard → Settings → Variables → Add Secret
 *  Name: USERS_CONFIG  |  Type: Secret
 *
 *  {
 *    "director": {
 *      "name": "Director",
 *      "password": "ChangeMe123!",
 *      "role": "admin",
 *      "mustChangePassword": true
 *    }
 *  }
 *
 *  Then log in as Director → Role Management → User Accounts
 *  to add all remaining staff from the dashboard UI.
 *
 *  Role mapping (PDD org levels):
 *  Level 2  Director              → admin
 *  Level 3  Programme Manager     → manager
 *  Level 3  Finance Manager       → finance_manager
 *  Level 3  HR / Admin Manager    → manager
 *  Level 3  M&E Director          → manager
 *  Level 3  Programme Officers    → staff
 *  Level 3  Finance Officer       → finance_staff
 *  Level 4  Diocesan Dev Officers → staff
 */

// ─── Sheet names ──────────────────────────────────
// Base sheets always fetched
const BASE_SHEETS = [
  'Main Programs',
  'Weekly Reports',
  'Projects',
  // Login Audit is write-only — not needed in data fetch
];

// ─── Helpers ──────────────────────────────────────
function generateTempPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#';
  let pw = '';
  // Use timestamp + random for uniqueness (Workers don't have crypto.randomBytes easily)
  const seed = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  for (let i = 0; i < 12; i++) {
    pw += chars[Math.floor(Math.random() * chars.length)];
  }
  return pw;
}

// ─── CORS ─────────────────────────────────────────
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}

// ─── Read sheet ───────────────────────────────────
async function fetchSheet(apiKey, sheetId, sheetName) {
  const quotedName = `'${sheetName.replace(/'/g, "''")}'`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${encodeURIComponent(quotedName)}?key=${apiKey}&valueRenderOption=FORMATTED_VALUE`;
  const res = await fetch(url);
  if (res.status === 404 || res.status === 400) return []; // 400 = sheet doesn't exist yet
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Sheet "${sheetName}": ${err.error?.message || res.status}`);
  }
  return (await res.json()).values || [];
}

// ─── Append row to sheet (requires OAuth) ─────────
async function appendToSheet(accessToken, sheetId, sheetName, row) {
  const quotedName = `'${sheetName.replace(/'/g, "''")}'`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${encodeURIComponent(quotedName)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values: [row] }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Append failed: ${err.error?.message || res.status}`);
  }
  return res.json();
}

// ─── Create sheet tab if it doesn't exist ─────────
async function createSheetTab(accessToken, sheetId, sheetName) {
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}:batchUpdate`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ requests: [{ addSheet: { properties: { title: sheetName } } }] })
    }
  );
  // Ignore "already exists" error (code 400 with "already exists" message)
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const msg = err.error?.message || '';
    if (!msg.toLowerCase().includes('already exists')) {
      throw new Error(`createSheet failed: ${msg || res.status}`);
    }
  }
}

// ─── Get Gmail OAuth2 access token from refresh token ─
async function getAccessToken(clientId, clientSecret, refreshToken) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type:    'refresh_token',
    }),
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Failed to get access token: ' + JSON.stringify(data));
  return data.access_token;
}

// ─── Google Drive helpers ─────────────────────────

async function getDriveToken(env) {
  if (!env.DRIVE_REFRESH_TOKEN || !env.GMAIL_CLIENT_ID || !env.GMAIL_CLIENT_SECRET)
    throw new Error('Missing Drive OAuth secrets (DRIVE_REFRESH_TOKEN, GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET)');
  return getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, env.DRIVE_REFRESH_TOKEN);
}

// Create a new JSON file in Drive, or update an existing one by file ID
async function driveWriteFile(token, folderId, filename, content, existingFileId = null) {
  const boundary = 'PDP_BOUNDARY_314159';
  const metadata = JSON.stringify({
    name: filename,
    mimeType: 'application/json',
    ...(existingFileId ? {} : { parents: [folderId] }),
  });
  const body = [
    `--${boundary}`,
    'Content-Type: application/json',
    '',
    metadata,
    `--${boundary}`,
    'Content-Type: application/json',
    '',
    JSON.stringify(content),
    `--${boundary}--`,
  ].join('\r\n');

  const url = existingFileId
    ? `https://www.googleapis.com/upload/drive/v3/files/${existingFileId}?uploadType=multipart`
    : `https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart`;

  const res = await fetch(url, {
    method: existingFileId ? 'PATCH' : 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary="${boundary}"`,
    },
    body,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error('Drive write failed: ' + (err.error?.message || res.status));
  }
  return res.json(); // { id, name }
}

// Upload HTML content as a Google Doc (Drive auto-converts)
async function driveWriteGoogleDoc(token, folderId, filename, htmlContent, existingFileId = null) {
  const boundary = 'PDP_GDOC_BOUNDARY_271828';
  const metadata = JSON.stringify({
    name: filename,
    mimeType: 'application/vnd.google-apps.document',
    ...(existingFileId ? {} : { parents: [folderId] }),
  });
  const body = [
    `--${boundary}`,
    'Content-Type: application/json',
    '',
    metadata,
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    '',
    htmlContent,
    `--${boundary}--`,
  ].join('\r\n');

  const url = existingFileId
    ? `https://www.googleapis.com/upload/drive/v3/files/${existingFileId}?uploadType=multipart`
    : `https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart`;

  const res = await fetch(url, {
    method: existingFileId ? 'PATCH' : 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary="${boundary}"`,
    },
    body,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error('Drive GDoc write failed: ' + (err.error?.message || res.status));
  }
  return res.json(); // { id, name }
}

// List all JSON files in the DCR folder with their metadata stored in description
async function driveListFiles(token, folderId) {
  const q = encodeURIComponent(`'${folderId}' in parents and mimeType='application/json' and trashed=false`);
  const res = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name,description,modifiedTime)&orderBy=modifiedTime desc&pageSize=200`,
    { headers: { 'Authorization': `Bearer ${token}` } }
  );
  if (!res.ok) throw new Error('Drive list failed: ' + res.status);
  const data = await res.json();
  return data.files || [];
}

// Read one file's content
async function driveReadFile(token, fileId) {
  const res = await fetch(
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`,
    { headers: { 'Authorization': `Bearer ${token}` } }
  );
  if (!res.ok) throw new Error('Drive read failed: ' + res.status);
  return res.json();
}

// Find existing file by name in folder
async function driveFindFile(token, folderId, filename) {
  const q = encodeURIComponent(`'${folderId}' in parents and name='${filename}' and trashed=false`);
  const res = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name)`,
    { headers: { 'Authorization': `Bearer ${token}` } }
  );
  if (!res.ok) return null;
  const data = await res.json();
  return data.files?.[0] || null;
}

// Trash a file (soft delete)
async function driveTrashFile(token, fileId) {
  const res = await fetch(
    `https://www.googleapis.com/drive/v3/files/${fileId}`,
    {
      method: 'PATCH',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ trashed: true }),
    }
  );
  if (!res.ok) throw new Error('Drive trash failed: ' + res.status);
  return true;
}

// ─── Send email via Gmail API ─────────────────────
async function sendEmail(accessToken, to, subject, body, fromName) {
  const from = fromName ? `${fromName} <me>` : 'PDD Dashboard <me>';
  const message = [
    `To: ${to}`,
    `From: PDD Dashboard`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    '',
    body,
  ].join('\r\n');

  const encoded = btoa(unescape(encodeURIComponent(message)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw: encoded }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Email failed: ${err.error?.message || res.status}`);
  }
  return res.json();
}

// ─── Build alert email HTML ───────────────────────
function buildAlertEmail(cw, rate, threshold, weeklyData) {
  const pct = Math.round(rate * 100);
  const tpct = Math.round(threshold * 100);
  return `
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;">
      <div style="background:#1e3a5f;padding:24px 28px;border-radius:12px 12px 0 0;">
        <div style="color:#fff;font-size:20px;font-weight:800;">⚠️ PDP Performance Alert</div>
        <div style="color:#93c5fd;font-size:13px;margin-top:4px;">Week CW ${cw} — below threshold</div>
      </div>
      <div style="background:#fff;border:1px solid #e5e7eb;border-top:none;padding:24px 28px;border-radius:0 0 12px 12px;">
        <p style="color:#374151;font-size:15px;">This week's performance rate dropped below the <strong>${tpct}%</strong> threshold.</p>
        <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin:16px 0;text-align:center;">
          <div style="font-size:48px;font-weight:800;color:#dc2626;">${pct}%</div>
          <div style="color:#9ca3af;font-size:13px;">CW ${cw} Performance Rate</div>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
          <tr style="background:#f9fafb;">
            <th style="padding:8px 12px;text-align:left;color:#6b7280;border:1px solid #e5e7eb;">CW</th>
            <th style="padding:8px 12px;text-align:left;color:#6b7280;border:1px solid #e5e7eb;">Target</th>
            <th style="padding:8px 12px;text-align:left;color:#6b7280;border:1px solid #e5e7eb;">Completed</th>
            <th style="padding:8px 12px;text-align:left;color:#6b7280;border:1px solid #e5e7eb;">Rate</th>
          </tr>
          ${weeklyData.slice(-3).map(w => `
            <tr>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;">CW ${w.cw}</td>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;">${w.t}</td>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;">${w.d}</td>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;color:${w.p < threshold ? '#dc2626' : '#16a34a'}">${Math.round(w.p*100)}%</td>
            </tr>`).join('')}
        </table>
        <p style="color:#6b7280;font-size:12px;margin-top:16px;">This is an automated alert from the PDP Dashboard. Log in to view full details.</p>
      </div>
    </div>`;
}

// ─── Check & send performance alert ──────────────
async function checkAndSendAlert(env, weeklyRows) {
  const alertRefreshToken = env.GMAIL_REFRESH_TOKEN || env.DRIVE_REFRESH_TOKEN;
  if (!env.GMAIL_CLIENT_ID || !alertRefreshToken || !env.ALERT_EMAIL_TO) return;

  const threshold = parseFloat(env.ALERT_THRESHOLD || '0.70');

  // Parse weekly data
  const weekly = weeklyRows.slice(1)
    .filter(r => r[0] && !isNaN(parseFloat(r[0])) && parseFloat(r[0]) >= 1)
    .map(r => ({
      cw: Math.round(parseFloat(r[0])),
      t:  parseFloat(String(r[1]||'0').replace(/[^0-9.]/g,'')) || 0,
      d:  parseFloat(String(r[2]||'0').replace(/[^0-9.]/g,'')) || 0,
      p:  0,
    }))
    .map(w => ({ ...w, p: w.t > 0 ? w.d / w.t : 0 }));

  // Find current week's data
  const now = new Date();
  const day = now.getUTCDay() || 7;
  const d = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()));
  d.setUTCDate(d.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const currentCW = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);

  const thisWeek = weekly.find(w => w.cw === currentCW);
  if (!thisWeek || thisWeek.t === 0) return; // No data yet

  if (thisWeek.p < threshold) {
    try {
      const token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, env.GMAIL_REFRESH_TOKEN);
      const html  = buildAlertEmail(currentCW, thisWeek.p, threshold, weekly.slice(-5));
      await sendEmail(token, env.ALERT_EMAIL_TO, `⚠️ PDP Alert: CW ${currentCW} performance at ${Math.round(thisWeek.p*100)}%`, html);
    } catch(e) {
      console.error('Email alert failed:', e.message);
    }
  }
}

// ─── PDD Notification System ──────────────────────
// sendNotification(env, event, data)
//
// event types:
//   task_assigned       — new task assigned to a staff member
//   task_updated        — task status changed
//   program_created     — new program added
//   project_created     — new project added under a program
//   proposal_submitted  — budget proposal submitted
//   proposal_reviewed   — proposal approved or rejected
//   expense_reviewed    — expense approved or rejected
//   checkin_reminder    — weekly Monday reminder
//   dcr_submitted       — DCR report submitted
//
// data fields vary per event — see each template below.
// All sends are fire-and-forget (errors logged, never thrown).

async function sendNotification(env, event, data) {
  // Use GMAIL_REFRESH_TOKEN if available, fall back to DRIVE_REFRESH_TOKEN
  // (DRIVE_REFRESH_TOKEN has gmail.send scope so it works for both)
  const gmailRefreshToken = env.GMAIL_REFRESH_TOKEN || env.DRIVE_REFRESH_TOKEN;
  if (!env.GMAIL_CLIENT_ID || !env.GMAIL_CLIENT_SECRET || !gmailRefreshToken) return;

  try {
    // Build recipient list and email content for this event
    const { to, subject, html } = buildNotificationEmail(event, data, env);
    console.log(`[Notify] ${event} → recipients:`, JSON.stringify(to));
    if (!to || to.length === 0) {
      console.warn(`[Notify] ${event} skipped — no recipients resolved`);
      return;
    }

    console.log(`[Notify] fetching token for ${event}...`);
    const token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, gmailRefreshToken);
    console.log(`[Notify] token OK, sending to ${to.length} recipient(s)`);

    // Send to each recipient individually
    const results = await Promise.allSettled(
      to.map(addr => sendEmail(token, addr, subject, html))
    );
    results.forEach((r, i) => {
      if (r.status === 'rejected') console.error(`[Notify] ${event} → ${to[i]} FAILED:`, r.reason?.message);
      else console.log(`[Notify] ${event} → ${to[i]} sent OK`);
    });
  } catch(e) {
    console.error(`[Notify] ${event} error:`, e.message, e.stack);
  }
}

function buildNotificationEmail(event, data, env) {
  // Shared helpers
  const FROM_NAME = 'PDD Dashboard';
  const BASE_URL  = env.DASHBOARD_URL || 'https://www.gamalieltun.com/PDP-Dashboard/';

  // Resolve recipients — respects each user's notifOptOut preferences
  function emailOf(name, eventType) {
    if (!name) return null;
    try {
      const users = JSON.parse(env.USERS_CONFIG || '{}');
      // Match by display name OR by username key (case-insensitive)
      const match = Object.entries(users).find(([key, u]) =>
        u.name === name || key.toLowerCase() === name.toLowerCase()
      )?.[1];
      console.log(`[emailOf] looking for "${name}" → found: ${!!match}, email: ${match?.email || 'none'}`);
      if (!match?.email) return null;
      if (eventType && (match.notifOptOut || []).includes(eventType)) return null;
      return match.email;
    } catch(e) {
      console.error('[emailOf] error:', e.message);
      return null;
    }
  }

  function emailsOfRole(eventType, ...roles) {
    try {
      const users = JSON.parse(env.USERS_CONFIG || '{}');
      return Object.values(users)
        .filter(u => roles.includes(u.role) && u.email)
        .filter(u => !eventType || !(u.notifOptOut || []).includes(eventType))
        .map(u => u.email);
    } catch { return []; }
  }

  function wrap(body) {
    return `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1e293b;">
      <div style="background:#0f172a;padding:20px 28px;border-radius:10px 10px 0 0;">
        <span style="color:#fff;font-size:16px;font-weight:700;">PDD Dashboard</span>
        <span style="color:#94a3b8;font-size:12px;margin-left:10px;">Provincial Development Department</span>
      </div>
      <div style="background:#f8fafc;padding:28px;border-radius:0 0 10px 10px;border:1px solid #e2e8f0;border-top:none;">
        ${body}
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0 16px;">
        <p style="font-size:11px;color:#94a3b8;margin:0;">
          This is an automated notification from PDD Dashboard. Do not reply to this email.<br>
          <a href="${BASE_URL}" style="color:#2563eb;">Open Dashboard</a>
        </p>
      </div>
    </body></html>`;
  }

  function badge(text, color) {
    return `<span style="display:inline-block;background:${color};color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px;">${text}</span>`;
  }

  function row(label, value) {
    return `<tr>
      <td style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;white-space:nowrap;">${label}</td>
      <td style="padding:8px 12px;font-size:13px;color:#1e293b;">${value}</td>
    </tr>`;
  }

  function table(...rows) {
    return `<table style="width:100%;border-collapse:collapse;background:#fff;border-radius:8px;border:1px solid #e2e8f0;margin:16px 0;">${rows.join('')}</table>`;
  }

  // ── Event templates ────────────────────────────────────────────────────────

  if (event === 'task_assigned') {
    const { taskName, programId, programName, cw, quarter, assignee, assignedBy } = data;
    const ownerEmail = emailOf(assignee, 'task_assigned');
    return {
      to:      [ownerEmail].filter(Boolean),
      subject: `[PDD] New task assigned to you: ${taskName}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">You have a new task</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Assigned by ${assignedBy || 'admin'}</p>
        ${table(
          row('Task',    `<strong>${taskName}</strong>`),
          row('Program', `${programId} — ${programName || ''}`),
          row('CW',      `CW ${cw}`),
          row('Quarter', quarter || '—'),
          row('Owner',   assignee),
        )}
      `),
    };
  }

  if (event === 'task_updated') {
    const { taskName, programId, status, owner, updatedBy } = data;
    const ownerEmail    = emailOf(owner, 'task_updated');
    const managerEmails = emailsOfRole('task_updated', 'manager', 'admin');
    const statusColor   = status === 'Delivered' ? '#16a34a' : '#2563eb';
    return {
      to:      [...new Set([ownerEmail, ...managerEmails].filter(Boolean))],
      subject: `[PDD] Task status updated: ${taskName}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">Task status changed</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Updated by ${updatedBy || 'system'}</p>
        ${table(
          row('Task',    `<strong>${taskName}</strong>`),
          row('Program', programId || '—'),
          row('Status',  badge(status, statusColor)),
          row('Owner',   owner),
        )}
      `),
    };
  }

  if (event === 'program_created') {
    const { programId, programName, createdBy } = data;
    const directorEmails = emailsOfRole('program_created', 'admin');
    const managerEmails  = emailsOfRole('program_created', 'manager');
    return {
      to:      [...new Set([...directorEmails, ...managerEmails])],
      subject: `[PDD] New program: ${programId} - ${programName}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">New program added</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Created by ${createdBy || 'admin'}</p>
        ${table(
          row('Program ID',   programId),
          row('Program Name', programName),
          row('Created By',   createdBy || '—'),
        )}
      `),
    };
  }

  if (event === 'project_created') {
    const { projectId, projectName, programId, programName, createdBy } = data;
    const directorEmails = emailsOfRole('project_created', 'admin');
    const managerEmails  = emailsOfRole('project_created', 'manager');
    return {
      to:      [...new Set([...directorEmails, ...managerEmails])],
      subject: `[PDD] New project: ${projectName}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">New project added</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Created by ${createdBy || 'admin'}</p>
        ${table(
          row('Project',    `<strong>${projectName}</strong>`),
          row('Project ID', projectId),
          row('Program',    `${programId} — ${programName || ''}`),
          row('Created By', createdBy || '—'),
        )}
      `),
    };
  }

  if (event === 'proposal_submitted') {
    const { proposalId, programId, category, amount, proposedBy } = data;
    const directorEmails = emailsOfRole('proposal_submitted', 'admin');
    return {
      to:      directorEmails,
      subject: `[PDD] Budget proposal submitted: ${category} (${programId})`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">New budget proposal</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Requires your review</p>
        ${table(
          row('Proposal ID', proposalId),
          row('Program',     programId),
          row('Category',    category),
          row('Amount',      `MMK ${Number(amount||0).toLocaleString()}`),
          row('Proposed By', proposedBy),
        )}
        <p style="font-size:13px;color:#475569;">Log in to approve or reject this proposal.</p>
      `),
    };
  }

  if (event === 'proposal_reviewed') {
    const { proposalId, category, status, reviewedBy, reviewNotes, proposedBy } = data;
    const proposerEmail = emailOf(proposedBy, 'proposal_reviewed');
    const isApproved    = status === 'approved';
    return {
      to:      [proposerEmail].filter(Boolean),
      subject: `[PDD] Budget proposal ${status === 'approved' ? 'approved' : 'rejected'}: ${category}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">Budget proposal ${status === 'approved' ? 'approved' : 'rejected'}</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Reviewed by ${reviewedBy}</p>
        ${table(
          row('Proposal ID',  proposalId),
          row('Category',     category),
          row('Status',       badge(status.toUpperCase(), isApproved ? '#16a34a' : '#dc2626')),
          row('Reviewed By',  reviewedBy),
          row('Notes',        reviewNotes || '—'),
        )}
      `),
    };
  }

  if (event === 'expense_reviewed') {
    const { txId, description, amount, status, reviewedBy, submittedBy } = data;
    const submitterEmail = emailOf(submittedBy, 'expense_reviewed');
    const directorEmails = emailsOfRole('expense_reviewed', 'admin');
    const isApproved     = status === 'approved';
    return {
      to:      [...new Set([submitterEmail, ...directorEmails].filter(Boolean))],
      subject: `[PDD] Expense ${status === 'approved' ? 'approved' : 'rejected'}: ${description}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">Expense ${status === 'approved' ? 'approved' : 'rejected'}</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Reviewed by ${reviewedBy}</p>
        ${table(
          row('Transaction', txId),
          row('Description', description),
          row('Amount',      `MMK ${Number(amount||0).toLocaleString()}`),
          row('Status',      badge(status.toUpperCase(), isApproved ? '#16a34a' : '#dc2626')),
          row('Reviewed By', reviewedBy),
        )}
      `),
    };
  }

  if (event === 'checkin_submitted') {
    const { name, program, cw, done, missed } = data;
    const managerEmails = emailsOfRole('checkin_submitted', 'manager', 'admin');
    return {
      to:      managerEmails,
      subject: `[PDD] Check-in submitted: ${name} (CW ${cw})`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">Check-in submitted</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">CW ${cw}</p>
        ${table(
          row('Staff',    name),
          row('Program',  program || '—'),
          row('CW',       `CW ${cw}`),
          row('Delivered', `${done} task${done !== 1 ? 's' : ''}`),
          row('Missed',   `${missed} task${missed !== 1 ? 's' : ''}`),
        )}
      `),
    };
  }

  if (event === 'dcr_submitted') {
    const { reportType, submittedBy, diocese, period } = data;
    const managerEmails  = emailsOfRole('dcr_submitted', 'manager', 'admin');
    return {
      to:      managerEmails,
      subject: `[PDD] DCR report submitted: ${reportType} - ${diocese || 'Province'}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">DCR report submitted</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Submitted by ${submittedBy}</p>
        ${table(
          row('Report Type',  reportType),
          row('Diocese',      diocese || 'Province'),
          row('Period',       period  || '—'),
          row('Submitted By', submittedBy),
        )}
      `),
    };
  }

  if (event === 'checkin_reminder') {
    const { cw } = data;
    const allStaffEmails = emailsOfRole('checkin_reminder', 'staff', 'external', 'manager', 'finance_staff', 'finance_manager');
    return {
      to:      allStaffEmails,
      subject: `[PDD] Weekly check-in reminder: CW ${cw}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">Weekly check-in reminder</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Calendar Week ${cw}</p>
        <p style="font-size:14px;color:#475569;line-height:1.6;">
          Please log in and submit your weekly check-in for <strong>CW ${cw}</strong>.
          Mark your delivered tasks, note any blockers, and add comments for the week.
        </p>
        <a href="${BASE_URL}" style="display:inline-block;margin-top:12px;padding:10px 20px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:13px;">
          Open Dashboard →
        </a>
      `),
    };
  }

  // Unknown event — return empty
  return { to: [], subject: '', html: '' };
}


// ─── Main handler ─────────────────────────────────
// ─── Monday check-in reminder (called by cron) ───────────────
async function sendCheckinReminder(env) {
  try {
    // Calculate current calendar week
    const now = new Date();
    const day = now.getUTCDay() || 7;
    const d   = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()));
    d.setUTCDate(d.getUTCDate() + 4 - day);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    const cw = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);

    await sendNotification(env, 'checkin_reminder', { cw });
    console.log(`[Cron] Check-in reminder sent for CW ${cw}`);
  } catch(e) {
    console.error('[Cron] Reminder failed:', e.message);
  }
}

export default {
  // ── Cron trigger — runs on schedule set in Cloudflare Dashboard ──
  // Schedule: 0 1 * * 1  (every Monday at 01:00 UTC = ~08:00 Myanmar time)
  async scheduled(event, env, ctx) {
    ctx.waitUntil(sendCheckinReminder(env));
  },

  async fetch(request, env) {
    const headers = corsHeaders();

    // Always handle OPTIONS preflight
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });

    try {
      if (request.method !== 'POST')
        return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers });

      let body;
      try { body = await request.json(); }
      catch { return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers }); }

      const { action } = body;

    // ══════════════════════════════════════════════
    //  USER HELPERS
    // ══════════════════════════════════════════════

    function getUsers() {
      if (!env.USERS_CONFIG) return {};
      try { return JSON.parse(env.USERS_CONFIG); } catch { return {}; }
    }

    function validateUser(username, password) {
      const users = getUsers();
      const key = Object.keys(users).find(k => k.toLowerCase() === (username||'').toLowerCase());
      const u = key ? users[key] : null;
      if (!u) return null;
      if (u.password !== password) return null;
      return { ...u, _key: key };
    }

    function isAdminUser(username, password) {
      const u = validateUser(username, password);
      return u?.role === 'admin';
    }

    function usersPublicList(users) {
      // Return user list without passwords
      return Object.entries(users).map(([username, u]) => ({
        username, name: u.name, role: u.role, email: u.email || null,
        notifOptOut: u.notifOptOut || [], mustChangePassword: !!u.mustChangePassword
      }));
    }

    async function saveUsers(users) {
      // Update USERS_CONFIG secret via Cloudflare API
      if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID || !env.CF_WORKER_SCRIPT_NAME) {
        throw new Error('CF_API_TOKEN, CF_ACCOUNT_ID, and CF_WORKER_SCRIPT_NAME secrets are required to save users.');
      }
      const res = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/workers/scripts/${env.CF_WORKER_SCRIPT_NAME}/secrets`,
        {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${env.CF_API_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name: 'USERS_CONFIG',
            text: JSON.stringify(users),
            type: 'secret_text',
          })
        }
      );
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error('Cloudflare API error: ' + (e.errors?.[0]?.message || res.status));
      }
    }

    // ── Auth ─────────────────────────────────────
    if (action === 'auth') {
      const { username, password } = body;
      const users = getUsers();
      const u = users[username];

      if (!u || u.password !== password) {
        return new Response(JSON.stringify({ ok: false, error: 'Invalid credentials' }), { status: 401, headers });
      }

      // Log login to Google Sheets (fire and forget)
      console.log('Audit: GMAIL_REFRESH_TOKEN present:', !!env.GMAIL_REFRESH_TOKEN);
      console.log('Audit: SPREADSHEET_ID present:', !!env.SPREADSHEET_ID);
      if (env.GMAIL_REFRESH_TOKEN && env.GMAIL_CLIENT_ID && env.GMAIL_CLIENT_SECRET) {
        const resolvedUsername = u._key || username;
        const displayName = u.name;
        const userRole = u.role;
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        (async () => {
          try {
            console.log('Audit: getting access token...');
            const token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, env.GMAIL_REFRESH_TOKEN);
            console.log('Audit: token obtained, writing row...');
            const now = new Date();
            const row = [
              now.toISOString().split('T')[0],
              now.toTimeString().split(' ')[0],
              resolvedUsername, displayName, userRole, ip
            ];
            await appendToSheet(token, env.SPREADSHEET_ID, 'Login Audit', row);
            console.log('Audit: row written successfully');
          } catch(e) {
            console.error('Login audit write failed:', e.message);
          }
        })();
      } else {
        console.log('Audit: skipped - missing OAuth secrets');
      }

      // Build roleConfig from USERS_CONFIG (merged into each user record by save_roles)
      // This is keyed by display name for the Role Management panel
      let roleConfig = null;
      if (u.role === 'admin') {
        const allUsers = getUsers();
        roleConfig = {};
        Object.values(allUsers).forEach(usr => {
          roleConfig[usr.name] = {
            role:     usr.role     || 'staff',
            programs: usr.programs || [],
            features: usr.features || [],
            diocese:  usr.diocese  || null,
            email:      usr.email      || null,
            notifOptOut: usr.notifOptOut || [],
          };
        });
        // Fallback: also merge STAFF_ROLES secret if it exists (legacy support)
        if (env.STAFF_ROLES) {
          try {
            const legacy = JSON.parse(env.STAFF_ROLES);
            Object.entries(legacy).forEach(([name, cfg]) => {
              if (!roleConfig[name]) roleConfig[name] = cfg;
            });
          } catch(e) {}
        }
      }

      // Return public user list to admin
      const usersList = u.role === 'admin' ? usersPublicList(getUsers()) : null;

      return new Response(JSON.stringify({
        ok: true,
        name:               u.name,
        role:               u.role,
        programs:           u.programs    || null,
        features:           u.features    || null,
        diocese:            u.diocese     || null,
        email:              u.email       || null,
        notifOptOut:        u.notifOptOut || [],
        mustChangePassword: !!u.mustChangePassword,
        roleConfig,
        users: usersList,
      }), { status: 200, headers });
    }

    // ── Change own password ───────────────────────
    if (action === 'change_password') {
      const { username, oldPassword, newPassword } = body;
      const users = getUsers();
      const u = users[username];

      if (!u || u.password !== oldPassword) {
        return new Response(JSON.stringify({ ok: false, error: 'Current password is incorrect.' }), { status: 401, headers });
      }
      if (!newPassword || newPassword.length < 8) {
        return new Response(JSON.stringify({ ok: false, error: 'Password must be at least 8 characters.' }), { status: 400, headers });
      }

      users[username].password = newPassword;
      users[username].mustChangePassword = false;
      await saveUsers(users);

      return new Response(JSON.stringify({
        ok: true,
        user: { name: u.name, role: u.role, programs: u.programs || null, features: u.features || null, diocese: u.diocese || null, email: u.email || null, notifOptOut: u.notifOptOut || [] }
      }), { status: 200, headers });
    }

    // ── Add new user (Admin only) ─────────────────
    if (action === 'add_user') {
      const { username, password, newUser } = body;
      if (!isAdminUser(username, password))
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const users = getUsers();
      if (users[newUser.username])
        return new Response(JSON.stringify({ error: 'Username already exists' }), { status: 400, headers });

      // Generate secure temp password
      const tempPassword = generateTempPassword();

      users[newUser.username] = {
        name:               newUser.name,
        password:           tempPassword,
        role:               newUser.role || 'staff',
        mustChangePassword: true,
        ...(newUser.email   ? { email:   newUser.email.trim().toLowerCase() } : {}),
        ...(newUser.diocese ? { diocese: newUser.diocese } : {}),
      };
      await saveUsers(users);

      return new Response(JSON.stringify({
        ok: true, tempPassword,
        users: usersPublicList(users)
      }), { status: 200, headers });
    }

    // ── Reset user password (Admin only) ─────────
    if (action === 'reset_user_password') {
      const { username, password, targetUsername } = body;
      if (!isAdminUser(username, password))
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const users = getUsers();
      if (!users[targetUsername])
        return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
      if (targetUsername === username)
        return new Response(JSON.stringify({ error: 'Use Change Password to update your own password' }), { status: 400, headers });

      const tempPassword = generateTempPassword();
      users[targetUsername].password = tempPassword;
      users[targetUsername].mustChangePassword = true;
      await saveUsers(users);

      return new Response(JSON.stringify({
        ok: true, tempPassword,
        users: usersPublicList(users)
      }), { status: 200, headers });
    }

    // ── Delete user (Admin only) ──────────────────
    if (action === 'delete_user') {
      const { username, password, targetUsername } = body;
      if (!isAdminUser(username, password))
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });
      if (targetUsername === username)
        return new Response(JSON.stringify({ error: 'Cannot delete your own account' }), { status: 400, headers });

      const users = getUsers();
      if (!users[targetUsername])
        return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });

      delete users[targetUsername];
      await saveUsers(users);

      return new Response(JSON.stringify({
        ok: true, users: usersPublicList(users)
      }), { status: 200, headers });
    }

    // ── Data fetch ───────────────────────────────
    if (action === 'data') {
      const { username, password } = body;
      const u = validateUser(username, password);
      if (!u)
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const results = {};
      const errors  = {};

      // Step 1: fetch base sheets always
      for (const sheet of BASE_SHEETS) {
        try   { results[sheet] = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, sheet); }
        catch(e) { errors[sheet] = e.message; results[sheet] = []; }
      }

      // Step 2: discover all program IDs from Main Programs, then fetch each task sheet
      const mainRows = results['Main Programs'] || [];
      const programIds = mainRows.slice(1)
        .map(r => r[0])
        .filter(id => id && String(id).trim());

      for (const pid of programIds) {
        const taskSheet = `${pid} Task_List`;
        try   { results[taskSheet] = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, taskSheet); }
        catch(e) { errors[taskSheet] = e.message; results[taskSheet] = []; }
      }

      // Build roleConfig from USERS_CONFIG (same as auth action)
      let roleConfig = null;
      if (u.role === 'admin') {
        const allUsers = getUsers();
        roleConfig = {};
        Object.values(allUsers).forEach(usr => {
          roleConfig[usr.name] = { role: usr.role || 'staff', programs: usr.programs || [], features: usr.features || [], diocese: usr.diocese || null, email: usr.email || null, notifOptOut: usr.notifOptOut || [] };
        });
        if (env.STAFF_ROLES) {
          try { const lg = JSON.parse(env.STAFF_ROLES); Object.entries(lg).forEach(([n,c]) => { if (!roleConfig[n]) roleConfig[n]=c; }); } catch(e) {}
        }
      }
      const usersList  = u.role === 'admin' ? usersPublicList(getUsers()) : null;

      return new Response(JSON.stringify({ ok: true, sheets: results, errors, roleConfig, users: usersList }), { status: 200, headers });
    }

    // ── Add new program ──────────────────────────
    if (action === 'add_program') {
      const { username, password } = body;
      if (!isAdminUser(username, password))
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const { program } = body;
      if (!program?.id || !program?.name)
        return new Response(JSON.stringify({ error: 'Missing program data' }), { status: 400, headers });

      const sheetsRefreshToken = env.GMAIL_REFRESH_TOKEN || env.DRIVE_REFRESH_TOKEN;
      if (!sheetsRefreshToken)
        return new Response(JSON.stringify({ error: 'OAuth not configured' }), { status: 501, headers });

      let token;
      try { token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, sheetsRefreshToken); }
      catch(e) { return new Response(JSON.stringify({ error: 'OAuth failed: ' + e.message }), { status: 500, headers }); }

      const sheetName = `${program.id} Task_List`;
      const spreadsheetId = env.SPREADSHEET_ID;

      // 1. Create new sheet tab
      const addSheetRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`,
        {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requests: [{
              addSheet: {
                properties: { title: sheetName }
              }
            }]
          })
        }
      );
      if (!addSheetRes.ok) {
        const e = await addSheetRes.json().catch(() => ({}));
        return new Response(JSON.stringify({ error: 'Sheet creation failed: ' + (e.error?.message || addSheetRes.status) }), { status: 500, headers });
      }

      // 2. Add headers to new sheet — 8 clean data columns, no formulas
      const sheetHeaders = ['Task ID','Program ID','Program Name','Task Name','Quarter','CW','Status','Owner'];
      await appendToSheet(token, spreadsheetId, sheetName, sheetHeaders);

      // 3. Add program row to Main Programs sheet
      // No formulas — Target Tasks is updated by dashboard from actual task count
      const duration = program.end - program.start + 1;
      const projRow = [
        program.id, program.name, program.start, program.end,
        program.startQuarter, program.endQuarter, duration,
        0   // Target Tasks — starts at 0, grows as tasks are added
      ];
      await appendToSheet(token, spreadsheetId, 'Main Programs', projRow);

      // Fire notification — non-blocking
      await sendNotification(env, 'program_created', {
        programId:   program.id,
        programName: program.name,
        createdBy:   body.username,
      }).catch(() => {});

      return new Response(JSON.stringify({ ok: true, sheetName }), { status: 200, headers });
    }

    // ── Add task to program ───────────────────────
    if (action === 'add_task') {
      const { username, password } = body;
      if (!isAdminUser(username, password))
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const { task } = body;
      if (!task?.programId || !task?.name)
        return new Response(JSON.stringify({ error: 'Missing task data' }), { status: 400, headers });

      const sheetsRefreshToken = env.GMAIL_REFRESH_TOKEN || env.DRIVE_REFRESH_TOKEN;
      if (!sheetsRefreshToken)
        return new Response(JSON.stringify({ error: 'OAuth not configured' }), { status: 501, headers });

      let token;
      try { token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, sheetsRefreshToken); }
      catch(e) { return new Response(JSON.stringify({ error: 'OAuth failed: ' + e.message }), { status: 500, headers }); }

      const sheetName = `${task.programId} Task_List`;

      // Fetch existing rows to determine next task number
      const rows = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, sheetName);
      const cwNum = parseInt(task.cw) || 1;

      // Count real data rows (non-blank Task ID in col A) to generate unique Task ID
      const dataRows = rows.slice(1).filter(r => r[0] && String(r[0]).trim());
      const taskId   = `T${dataRows.length + 1}`;

      // 8 clean data columns — all KPI computed by dashboard from these
      const row = [
        taskId,               // col A — Task ID
        task.programId,       // col B — Program ID
        task.programName,     // col C — Program Name
        task.name,            // col D — Task Name
        task.quarter,         // col E — Quarter
        cwNum,                // col F — CW (number)
        task.status || 'Planned', // col G — Status
        task.owner,           // col H — Owner
      ];

      await appendToSheet(token, env.SPREADSHEET_ID, sheetName, row);

      // Update Target Tasks count in Main Programs sheet
      try {
        const mpRows = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, 'Main Programs');
        // Find the header row and the program row
        const headerIdx = mpRows.findIndex(r => r && r.some(c => String(c).trim() === 'Program ID'));
        if (headerIdx >= 0) {
          const projRowIdx = mpRows.findIndex((r, i) => i > headerIdx && String(r[0]||'').trim() === task.programId);
          if (projRowIdx >= 0) {
            // Col H (index 7) = Target Tasks — count all non-empty Task ID rows in the task sheet
            const taskRows = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, sheetName);
            const taskCount = taskRows.slice(1).filter(r => r[0] && String(r[0]).trim()).length;
            const targetRange = `Main Programs!H${projRowIdx + 1}`;
            const updateUrl = `https://sheets.googleapis.com/v4/spreadsheets/${env.SPREADSHEET_ID}/values/${encodeURIComponent(targetRange)}?valueInputOption=RAW`;
            await fetch(updateUrl, {
              method: 'PUT',
              headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ values: [[taskCount]] }),
            });
          }
        }
      } catch(e) {
        // Non-critical — continue even if Target Tasks update fails
        console.warn('Target Tasks update failed:', e.message);
      }

      // Fire notification — non-blocking
      await sendNotification(env, 'task_assigned', {
        taskName:    task.name,
        programId:   task.programId,
        programName: task.programName || task.programId,
        cw:          task.cw,
        quarter:     task.quarter,
        assignee:    task.owner,
        assignedBy:  body.username,
      }).catch(e => console.error('[Notify add_task]', e.message));

      return new Response(JSON.stringify({ ok: true, taskId, sheetName, row }), { status: 200, headers });
    }


    // ── Update single task status ─────────────────
    if (action === 'update_task') {
      const { username, password, taskName, programId, newStatus } = body;
      if (!validateUser(username, password))
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      if (!['Planned','Delivered','In Progress','Cancelled'].includes(newStatus))
        return new Response(JSON.stringify({ error: 'Invalid status' }), { status: 400, headers });

      const sheetsRefreshToken = env.GMAIL_REFRESH_TOKEN || env.DRIVE_REFRESH_TOKEN;
      if (!sheetsRefreshToken)
        return new Response(JSON.stringify({ error: 'OAuth not configured' }), { status: 501, headers });

      let token;
      try { token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, sheetsRefreshToken); }
      catch(e) { return new Response(JSON.stringify({ error: 'OAuth failed: ' + e.message }), { status: 500, headers }); }

      const sheetName = `${programId} Task_List`;
      const rows = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, sheetName);
      const header = rows[0] || [];
      const statusCol = header.findIndex(h => String(h).toLowerCase().includes('status'));
      const nameCol   = header.findIndex(h => String(h).toLowerCase() === 'task name');

      if (statusCol === -1 || nameCol === -1)
        return new Response(JSON.stringify({ error: 'Sheet headers not found' }), { status: 500, headers });

      const rowIdx = rows.findIndex((r, i) => i > 0 && String(r[nameCol]||'').trim() === taskName.trim());
      if (rowIdx === -1)
        return new Response(JSON.stringify({ error: `Task "${taskName}" not found in ${sheetName}` }), { status: 404, headers });

      const colLetter = String.fromCharCode(65 + statusCol);
      const _sq = "'" + sheetName.replace(/'/g, "''") + "'";
      const range = encodeURIComponent(_sq) + '!' + colLetter + (rowIdx + 1);
      const url       = `https://sheets.googleapis.com/v4/spreadsheets/${env.SPREADSHEET_ID}/values/${range}?valueInputOption=USER_ENTERED`;
      const res = await fetch(url, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ values: [[newStatus]] }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        return new Response(JSON.stringify({ error: err.error?.message || res.status }), { status: 500, headers });
      }
      // Fire notification — non-blocking
      await sendNotification(env, 'task_updated', {
        taskName:  taskName,
        programId: programId,
        status:    newStatus,
        owner:     String(rows[rowIdx][7] || ''),
        updatedBy: body.username,
      }).catch(() => {});

      return new Response(JSON.stringify({ ok: true, taskName, programId, newStatus, row: rowIdx + 1 }), { status: 200, headers });
    }

    // ── Save role config (Admin only) ────────────
    // ── Test notification (debug — admin only) ──────────
    if (action === 'test_notification') {
      const u = validateUser(body.username, body.password);
      if (!u || u.role !== 'admin')
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const gmailRefreshToken = env.GMAIL_REFRESH_TOKEN || env.DRIVE_REFRESH_TOKEN;
      const diagnostics = {
        GMAIL_CLIENT_ID:     !!env.GMAIL_CLIENT_ID,
        GMAIL_CLIENT_SECRET: !!env.GMAIL_CLIENT_SECRET,
        GMAIL_REFRESH_TOKEN: !!env.GMAIL_REFRESH_TOKEN,
        DRIVE_REFRESH_TOKEN: !!env.DRIVE_REFRESH_TOKEN,
        resolvedToken:       !!gmailRefreshToken,
        targetEmail:         body.email || null,
      };

      if (!env.GMAIL_CLIENT_ID || !env.GMAIL_CLIENT_SECRET || !gmailRefreshToken)
        return new Response(JSON.stringify({ ok: false, error: 'Missing OAuth secrets', diagnostics }), { status: 200, headers });

      try {
        const token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, gmailRefreshToken);
        diagnostics.tokenFetched = true;

        const to = body.email || u.email;
        if (!to)
          return new Response(JSON.stringify({ ok: false, error: 'No email address — pass email in request body', diagnostics }), { status: 200, headers });

        await sendEmail(token, to,
          '[PDD] Notification test',
          `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:24px;">
            <div style="background:#0f172a;padding:20px;border-radius:10px 10px 0 0;">
              <span style="color:#fff;font-size:16px;font-weight:700;">PDD Dashboard</span>
            </div>
            <div style="background:#f8fafc;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e2e8f0;border-top:none;">
              <h2 style="color:#16a34a;margin:0 0 12px;">✅ Notification test successful</h2>
              <p style="color:#475569;font-size:14px;">Your email notifications are configured correctly. This confirms that the Gmail OAuth connection is working and emails will be delivered.</p>
              <p style="color:#94a3b8;font-size:12px;margin-top:20px;">Sent from PDD Dashboard · Provincial Development Department</p>
            </div>
          </body></html>`
        );
        diagnostics.emailSent = true;
        return new Response(JSON.stringify({ ok: true, message: `Test email sent to ${to}`, diagnostics }), { status: 200, headers });
      } catch(e) {
        diagnostics.error = e.message;
        return new Response(JSON.stringify({ ok: false, error: e.message, diagnostics }), { status: 200, headers });
      }
    }

    // ── Save notification opt-out prefs (any authenticated user) ──
    if (action === 'save_notif_prefs') {
      const u = validateUser(body.username, body.password);
      if (!u) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const { optOut } = body;
      if (!Array.isArray(optOut))
        return new Response(JSON.stringify({ error: 'optOut must be an array' }), { status: 400, headers });

      const users = getUsers();
      const key   = u._key;
      if (!users[key]) return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });

      users[key].notifOptOut = optOut;
      await saveUsers(users);

      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (action === 'save_roles') {
      const { username, password, config } = body;
      if (!isAdminUser(username, password))
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      if (!config) return new Response(JSON.stringify({ error: 'No config provided' }), { status: 400, headers });

      // Merge role config (programs, features, role) into each user in USERS_CONFIG
      // Config is keyed by display name: { "Gamaliel": { role, programs, features }, ... }
      const users = getUsers();

      // Build a lookup: display name → username key
      const nameToKey = {};
      Object.entries(users).forEach(([key, u]) => { nameToKey[u.name] = key; });

      let changed = 0;
      for (const [displayName, cfg] of Object.entries(config)) {
        const key = nameToKey[displayName];
        if (!key || !users[key]) continue; // unknown user — skip
        users[key].role     = cfg.role     || users[key].role;
        users[key].programs = cfg.programs || [];
        users[key].features = cfg.features || [];
        if (cfg.diocese !== undefined) users[key].diocese = cfg.diocese  || null;
        if (cfg.email   !== undefined) users[key].email   = cfg.email?.trim().toLowerCase() || null;
        changed++;
      }

      if (changed === 0)
        return new Response(JSON.stringify({ ok: true, saved: 0, note: 'No matching users found in config' }), { status: 200, headers });

      try {
        await saveUsers(users);
        return new Response(JSON.stringify({ ok: true, saved: changed }), { status: 200, headers });
      } catch(e) {
        // saveUsers failed (CF API token missing etc.) — return config for manual paste
        return new Response(JSON.stringify({
          ok: false,
          manualPaste: true,
          config,
          error: e.message,
          note: 'Auto-save failed. Copy the config JSON and paste as STAFF_ROLES in Cloudflare.'
        }), { status: 200, headers });
      }
    }

    // ── Check-in write ───────────────────────────
    if (action === 'checkin') {
      const { username, password } = body;
      const checkinUser = validateUser(username, password);
      if (!checkinUser)
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const { entry } = body;
      if (!entry || !entry.name) return new Response(JSON.stringify({ error: 'Missing entry' }), { status: 400, headers });

      // Staff can only submit for themselves — admin/manager can submit for anyone
      if (checkinUser.role === 'staff') {
        if (entry.name.trim().toLowerCase() !== checkinUser.name.trim().toLowerCase()) {
          return new Response(JSON.stringify({ error: `Staff can only submit their own check-in. You are logged in as "${checkinUser.name}".` }), { status: 403, headers });
        }
      }

      // Check secrets exist
      const missingSecrets = [];
      if (!env.GMAIL_CLIENT_ID)     missingSecrets.push('GMAIL_CLIENT_ID');
      if (!env.GMAIL_CLIENT_SECRET) missingSecrets.push('GMAIL_CLIENT_SECRET');
      if (!env.GMAIL_REFRESH_TOKEN) missingSecrets.push('GMAIL_REFRESH_TOKEN');
      if (missingSecrets.length > 0) {
        return new Response(JSON.stringify({ ok: false, error: 'Missing secrets: ' + missingSecrets.join(', ') }), { status: 500, headers });
      }

      let token;
      try {
        token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, env.GMAIL_REFRESH_TOKEN);
      } catch(e) {
        return new Response(JSON.stringify({ ok: false, error: 'OAuth token failed: ' + e.message }), { status: 500, headers });
      }

      const taskErrors = [];

      // ── Update task statuses — lookup row by task name ──
      if (entry.taskUpdates?.length) {
        // Group by program sheet
        const bySheet = {};
        entry.taskUpdates.forEach(u => {
          const sheet = `${u.programId} Task_List`;
          if (!bySheet[sheet]) bySheet[sheet] = [];
          bySheet[sheet].push(u);
        });

        for (const [sheet, updates] of Object.entries(bySheet)) {
          try {
            const rows     = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, sheet);
            const header   = rows[0] || [];
            const statusCol = header.findIndex(h => String(h).toLowerCase().includes('status'));
            const nameCol   = header.findIndex(h => String(h).toLowerCase().includes('task name'));
            if (statusCol === -1 || nameCol === -1) continue;

            for (const u of updates) {
              const rowIdx = rows.findIndex((r, i) => i > 0 && String(r[nameCol] || '') === u.taskName);
              if (rowIdx === -1) { taskErrors.push({ task: u.taskName, error: 'Row not found' }); continue; }

              const colLetter = String.fromCharCode(65 + statusCol);
              const range     = `${encodeURIComponent(sheet)}!${colLetter}${rowIdx + 1}`;
              const url       = `https://sheets.googleapis.com/v4/spreadsheets/${env.SPREADSHEET_ID}/values/${range}?valueInputOption=USER_ENTERED`;
              const res = await fetch(url, {
                method: 'PUT',
                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ values: [[u.newStatus]] }),
              });
              if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                taskErrors.push({ task: u.taskName, error: err.error?.message || res.status });
              }
            }
          } catch(e) {
            taskErrors.push({ sheet, error: e.message });
          }
        }
      }

      // ── Append check-in summary to Weekly Reports ──
      try {
        const row = [
          entry.date || new Date().toLocaleDateString(),
          entry.cw, entry.name, entry.program,
          entry.done, entry.missed,
          entry.blockers || '', entry.notes || '',
          entry.time || '',
          entry.taskUpdates?.length || 0,
        ];
        await appendToSheet(token, env.SPREADSHEET_ID, 'Weekly Reports', row);
      } catch(e) {
        console.error('Check-in append failed:', e.message);
      }

      // Notify managers when staff submit check-in
      if (!['admin', 'manager'].includes(checkinUser.role)) {
        await sendNotification(env, 'checkin_submitted', {
          name:    checkinUser.name || body.username,
          program: entry.program || '',
          cw:      entry.cw || '',
          done:    entry.done || 0,
          missed:  entry.missed || 0,
        }).catch(e => console.error('[Notify checkin]', e.message));
      }

      return new Response(JSON.stringify({ ok: true, taskErrors }), { status: 200, headers });
    }


    // ── Setup sheets (Admin only) — creates required sheets with headers ──
    if (action === 'setup_sheets') {
      const { username, password } = body;
      if (!isAdminUser(username, password))
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      if (!env.GMAIL_REFRESH_TOKEN)
        return new Response(JSON.stringify({ error: 'OAuth not configured — add Gmail OAuth secrets' }), { status: 501, headers });

      let token;
      try { token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, env.GMAIL_REFRESH_TOKEN); }
      catch(e) { return new Response(JSON.stringify({ error: 'OAuth failed: ' + e.message }), { status: 500, headers }); }

      const spreadsheetId = env.SPREADSHEET_ID;
      const created = [];
      const skipped = [];

      // Sheets to ensure exist, with their header rows
      const sheetsToSetup = [
        {
          name: 'Main Programs',
          // Columns match what parseSheetData expects — no underscore, consistent naming
          headers: ['Program ID','Program Name','Start CW','End CW','Start Quarter','End Quarter','Duration Weeks','Target Tasks'],
        },
        {
          name: 'Weekly Reports',
          headers: ['Date','CW','Name','Program','Done','Missed','Blockers','Notes','Time'],
        },
        {
          name: 'Login Audit',
          headers: ['Date','Time','Username','Name','Role','IP'],
        },
      ];

      for (const sheet of sheetsToSetup) {
        // Check if sheet already has correct headers
        const existing = await fetchSheet(env.GOOGLE_API_KEY, spreadsheetId, sheet.name);

        // Find the header row — look for the row that contains 'Program ID' or the first expected header
        const firstExpected = sheet.headers[0];
        const hasCorrectHeader = existing.some(row =>
          row.some(cell => String(cell).trim() === firstExpected)
        );

        if (hasCorrectHeader) {
          skipped.push(sheet.name);
          continue;
        }

        // Sheet doesn't exist or has wrong/no headers — create it (ignore error if already exists)
        if (existing.length === 0) {
          const addRes = await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`,
            {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ requests: [{ addSheet: { properties: { title: sheet.name } } }] })
            }
          );
          if (!addRes.ok) {
            const e = await addRes.json().catch(() => ({}));
            if (!e.error?.message?.includes('already exists')) {
              // Real error creating sheet — skip it
              continue;
            }
          }
        }

        // Clear and re-write headers to row 1
        const clearUrl = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(sheet.name)}!A1:Z1:clear`;
        await fetch(clearUrl, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        });
        await appendToSheet(token, spreadsheetId, sheet.name, sheet.headers);
        created.push(sheet.name);
      }

      // ── Migrate any existing Px Task_List sheets with offset data ──
      // Old Excel structure had task data in cols J-Q instead of A-H
      // Detect this and move the data to the correct columns

      // First get all sheet names from the spreadsheet
      const metaRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}?fields=sheets.properties.title`,
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      const meta = await metaRes.json();
      const allSheetNames = (meta.sheets || []).map(s => s.properties.title);
      const taskSheets = allSheetNames.filter(n => /^P\d+ Task_List$/.test(n));

      const migrated = [];

      for (const tsName of taskSheets) {
        const tsRows = await fetchSheet(env.GOOGLE_API_KEY, spreadsheetId, tsName);
        if (tsRows.length < 2) continue;

        // Check if row 2 (first data row) has data starting at col J (index 9)
        // and cols A-H are mostly empty
        const dataRow = tsRows[1]; // index 1 = row 2
        const colAH_filled = dataRow.slice(0, 8).filter(v => v !== null && v !== undefined && v !== '').length;
        const colJQ_filled = (dataRow[9] || dataRow[10] || dataRow[11]) ? true : false;

        if (colAH_filled === 0 && colJQ_filled) {
          // Offset structure detected — migrate all data rows
          // The real data starts at col J (index 9) and is 8 cols wide
          const dataRows = tsRows.slice(1).filter(row =>
            row[9] !== null && row[9] !== undefined && row[9] !== ''
          );

          if (dataRows.length === 0) continue;

          // Build clean rows: take cols 9-16 (J-Q) as the new A-H
          const cleanRows = dataRows.map(r => [
            r[9]  || '',  // Task ID
            r[10] || '',  // Program ID
            r[11] || '',  // Program Name
            r[12] || '',  // Task Name
            r[13] || '',  // Quarter
            r[14] || '',  // CW
            r[15] || '',  // Status
            r[16] || '',  // Owner
          ]);

          // 1. Clear entire sheet
          await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(tsName)}:clear`,
            { method: 'POST', headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
          );

          // 2. Write clean header row
          const headers = ['Task ID','Program ID','Program Name','Task Name','Quarter','CW','Status','Owner'];
          await appendToSheet(token, spreadsheetId, tsName, headers);

          // 3. Write all migrated data rows
          for (const row of cleanRows) {
            await appendToSheet(token, spreadsheetId, tsName, row);
          }

          migrated.push(`${tsName} (${cleanRows.length} tasks)`);
        }
      }

      if (migrated.length > 0) {
        return new Response(JSON.stringify({ ok: true, created, skipped, migrated }), { status: 200, headers });
      }

      return new Response(JSON.stringify({ ok: true, created, skipped }), { status: 200, headers });
    }

    // ─── save_dcr ────────────────────────────────────────────
    if (action === 'save_dcr') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const report = body.report;
      if (!report || !report.id || !report.type)
        return new Response(JSON.stringify({ error: 'Missing report data' }), { status: 400, headers });

      // Stamp server-side fields
      const resolvedUsername = user._key || body.username;
      report.pdpUsername  = resolvedUsername;
      report.submittedBy  = user.name || resolvedUsername;
      report.savedAt      = new Date().toISOString();
      if (body.submit) {
        report.status      = 'submitted';
        report.submittedAt = new Date().toISOString();
      } else {
        report.status = report.status || 'draft';
      }

      // Clean filename: DCR_Monthly_John_2026-03-13.json
      // Use report.id as a tie-breaker suffix to allow multiple reports of same type/user
      const typeLabel = { monthly: 'Monthly', biannual: 'Biannual', annual: 'Annual' }[report.type] || report.type;
      const safeName  = (user.name || resolvedUsername).replace(/[^a-zA-Z0-9]/g, '_');
      const dateStr   = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
      // Keep report.id suffix so the same report can be updated (not duplicated)
      const idSuffix  = report.id ? '_' + String(report.id).slice(-6) : '';
      const filename  = `DCR_${typeLabel}_${safeName}_${dateStr}${idSuffix}.json`;

      try {
        const token = await getDriveToken(env);
        const jsonFolderId = env.DRIVE_JSON_FOLDER_ID || env.DRIVE_FOLDER_ID;
        const pdfFolderId  = env.DRIVE_PDF_FOLDER_ID  || env.DRIVE_FOLDER_ID;

        // Save/update JSON to Reports_JSON folder
        const existing = await driveFindFile(token, jsonFolderId, filename);
        const file = await driveWriteFile(token, jsonFolderId, filename, report, existing?.id || null);

        // On submit: also upload a Google Doc to Reports_PDF folder
        let gdocId = null;
        if (body.submit && body.htmlContent) {
          const gdocName = filename.replace('.json', '');
          // Find existing GDoc to update instead of duplicating
          const existingDoc = await driveFindFile(token, pdfFolderId, gdocName);
          const gdoc = await driveWriteGoogleDoc(token, pdfFolderId, gdocName, body.htmlContent, existingDoc?.id || null);
          gdocId = gdoc.id;
        }

        // Fire notification — non-blocking
        await sendNotification(env, 'dcr_submitted', {
          reportType:  report.reportType || body.reportType || 'Report',
          submittedBy: user.name || body.username,
          diocese:     report.diocese    || body.diocese    || null,
          period:      report.period     || body.period     || null,
        }).catch(() => {});

        return new Response(JSON.stringify({ ok: true, fileId: file.id, filename, status: report.status, gdocId }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: 'Drive error: ' + e.message }), { status: 500, headers });
      }
    }

    // ─── get_dcr ─────────────────────────────────────────────
    if (action === 'get_dcr') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      try {
        const token = await getDriveToken(env);
        const files = await driveListFiles(token, env.DRIVE_JSON_FOLDER_ID || env.DRIVE_FOLDER_ID);

        // Read each file's content in parallel (cap at 50)
        const toFetch = files.slice(0, 50);
        const reports = await Promise.all(
          toFetch.map(async f => {
            try {
              const content = await driveReadFile(token, f.id);
              return { ...content, _fileId: f.id, _filename: f.name, _modifiedTime: f.modifiedTime };
            } catch { return null; }
          })
        );

        const valid = reports.filter(Boolean);

        // Staff only see their own reports — match _key (login username)
        const selfUsername = user._key || body.username;
        const filtered = (user.role === 'staff')
          ? valid.filter(r => r.pdpUsername === selfUsername)
          : valid;

        return new Response(JSON.stringify({ ok: true, reports: filtered }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: 'Drive error: ' + e.message }), { status: 500, headers });
      }
    }

    // ─── delete_dcr ──────────────────────────────────────────
    if (action === 'delete_dcr') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      // Only admin can delete
      if (user.role !== 'admin')
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const { fileId } = body;
      if (!fileId) return new Response(JSON.stringify({ error: 'Missing fileId' }), { status: 400, headers });

      try {
        const token = await getDriveToken(env);
        await driveTrashFile(token, fileId);
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: 'Drive error: ' + e.message }), { status: 500, headers });
      }
    }


    // ─── get_finance_data ─────────────────────────────────────
    if (action === 'get_finance_data') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const allowed = ['admin', 'manager', 'finance', 'finance_staff', 'finance_manager'];
      if (!allowed.includes(user.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      if (!finSheetId) return new Response(JSON.stringify({ error: 'FINANCE_SPREADSHEET_ID not configured' }), { status: 500, headers });

      try {
        // Use OAuth token — Finance sheet is private (API key only works on public sheets)
        const token = await getDriveToken(env);
        const finFetch = (sheet) => fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent(sheet)}`,
          { headers: { Authorization: `Bearer ${token}` } }
        );

        const [budgetRes, txRes, queueRes, propRes] = await Promise.all([
          finFetch('Budget'),
          finFetch('Transactions'),
          finFetch('Approval_Queue'),
          finFetch('Budget_Proposals'),
        ]);

        const toObjects = async (res) => {
          const d = await res.json();
          if (d.error) return []; // sheet may not exist yet
          const rows = d.values || [];
          if (rows.length < 2) return [];
          const [headers, ...data] = rows;
          return data.map(r => Object.fromEntries(headers.map((h, i) => [h.trim(), r[i] || ''])));
        };

        let [budget, transactions, queue, allProposals] = await Promise.all([
          toObjects(budgetRes), toObjects(txRes), toObjects(queueRes), toObjects(propRes)
        ]);

        // Role-filter proposals: finance_staff sees own only
        const proposals = (user.role === 'finance_staff')
          ? allProposals.filter(p => p['Proposed By'] === (user.name || user._key))
          : allProposals;

        // Also fetch programs from main PDP sheet so finance.html can sync
        let programs = [];
        try {
          const mainRows = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, 'Main Programs');
          const hIdx = mainRows.findIndex(r => r && r.some(c => String(c).trim() === 'Program ID'));
          if (hIdx >= 0) {
            const [hdrs, ...rows] = mainRows.slice(hIdx);
            programs = rows
              .map(r => Object.fromEntries(hdrs.map((h,i) => [h.trim(), r[i] || ''])))
              .filter(r => r['Program ID'] && !String(r['Program ID']).startsWith('#'))
              .map(r => ({ id: r['Program ID'].trim(), name: (r['Program Name '] || r['Program Name'] || r['Program ID']).trim() }));
          }
        } catch(_) {}

        return new Response(JSON.stringify({ ok: true, budget, transactions, queue, proposals, programs }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── log_expense ──────────────────────────────────────────
    if (action === 'log_expense') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const allowed = ['admin', 'manager', 'finance', 'finance_staff', 'finance_manager'];
      if (!allowed.includes(user.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const { program, projectId, category, amount, description } = body;
      if (!program || !category || !amount || !description)
        return new Response(JSON.stringify({ error: 'Missing fields: program, category, amount, description' }), { status: 400, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      const now = new Date().toISOString();
      const txId = 'TX-' + Date.now().toString(36).toUpperCase();

      try {
        const token = await getDriveToken(env);
        // Append to Transactions sheet
        const txRow = [txId, now.slice(0,10), program, projectId || '', category, amount, description,
                       user.name || user._key, 'pending', '', ''];
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Transactions:append?valueInputOption=USER_ENTERED`,
          {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ values: [txRow] })
          }
        );

        // Append to Approval_Queue
        const reqId = 'REQ-' + Date.now().toString(36).toUpperCase();
        const queueRow = [reqId, txId, user.name || user._key, now, amount, description, 'pending', '', '', ''];
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Approval_Queue:append?valueInputOption=USER_ENTERED`,
          {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ values: [queueRow] })
          }
        );

        return new Response(JSON.stringify({ ok: true, txId }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── approve_expense / reject_expense ─────────────────────
    if (action === 'approve_expense' || action === 'reject_expense') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      if (!['admin', 'manager'].includes(user.role))
        return new Response(JSON.stringify({ error: 'Manager or Admin only' }), { status: 403, headers });

      const { txId, notes } = body;
      if (!txId) return new Response(JSON.stringify({ error: 'Missing txId' }), { status: 400, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      const newStatus = action === 'approve_expense' ? 'approved' : 'rejected';
      const now = new Date().toISOString();

      try {
        const token = await getDriveToken(env);

        // Find and update Transactions row
        const txData = await (await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Transactions`,
          { headers: { Authorization: `Bearer ${token}` } }
        )).json();
        const txRows = txData.values || [];
        const txHeaderIdx = { id: 0, status: 7, approvedBy: 8, approvedAt: 9 };
        const txRowIdx = txRows.findIndex((r, i) => i > 0 && r[txHeaderIdx.id] === txId);
        if (txRowIdx > 0) {
          const sheetRow = txRowIdx + 1;
          await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Transactions!H${sheetRow}:J${sheetRow}?valueInputOption=USER_ENTERED`,
            {
              method: 'PUT',
              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ values: [[newStatus, user.name || user._key, now]] })
            }
          );
        }

        // Find and update Approval_Queue row
        const qData = await (await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Approval_Queue`,
          { headers: { Authorization: `Bearer ${token}` } }
        )).json();
        const qRows = qData.values || [];
        const qRowIdx = qRows.findIndex((r, i) => i > 0 && r[1] === txId);
        if (qRowIdx > 0) {
          const sheetRow = qRowIdx + 1;
          await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Approval_Queue!G${sheetRow}:J${sheetRow}?valueInputOption=USER_ENTERED`,
            {
              method: 'PUT',
              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ values: [[newStatus, user.name || user._key, now, notes || '']] })
            }
          );
        }

        // On approval: recalculate Budget Spent/Remaining for matching budget line
        if (action === 'approve_expense') {
          try {
            const txRow       = txRows[txRowIdx];
            const txProgram   = txRow[2] || '';   // col C = Program
            const txprojectId = txRow[3] || '';   // col D = Project ID
            const txCategory  = txRow[4] || '';   // col E = Category
            // col F = Amount (index 5)

            // Fetch all transactions to recalculate total spent for this budget line
            const allTxData = await fetch(
              `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Transactions`,
              { headers: { Authorization: `Bearer ${token}` } }
            ).then(r => r.json());

            const allTxRows = allTxData.values || [];
            // Sum approved amounts for same Program + Project + Category
            // Include the current txId (being approved right now) in the sum
            const totalSpent = allTxRows.slice(1)
              .filter(r =>
                r[2] === txProgram &&
                (r[3] || '') === txprojectId &&
                r[4] === txCategory &&
                (r[8] === 'approved' || r[0] === txId)
              )
              .reduce((sum, r) => sum + parseFloat(r[5] || 0), 0); // r[5] = Amount

            // Find matching Budget row: Program + Project ID + Category
            const bData = await fetch(
              `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Budget`,
              { headers: { Authorization: `Bearer ${token}` } }
            ).then(r => r.json());

            const bRows = bData.values || [];
            // Budget schema: A(0)=ID B(1)=Program C(2)=ProjectID D(3)=Category E(4)=Alloc F(5)=Spent G(6)=Rem
            const bRowIdx = bRows.findIndex((r, i) =>
              i > 0 &&
              r[1] === txProgram &&
              (r[2] || '') === txprojectId &&
              r[3] === txCategory
            );

            if (bRowIdx > 0) {
              const allocated = parseFloat(bRows[bRowIdx][4] || 0); // col E
              const remaining = allocated - totalSpent;
              const bSheetRow = bRowIdx + 1;
              await fetch(
                `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Budget!F${bSheetRow}:G${bSheetRow}?valueInputOption=USER_ENTERED`,
                {
                  method: 'PUT',
                  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                  body: JSON.stringify({ values: [[totalSpent, remaining]] })
                }
              );
            }
          } catch(_) {} // Budget update is best-effort; don't fail the approval
        }

        // Fire notification — non-blocking
        if (txRowIdx > 0) {
          const txRow = txRows[txRowIdx];
          await sendNotification(env, 'expense_reviewed', {
            txId:        txId,
            description: txRow[6] || '',
            amount:      txRow[5] || 0,
            status:      newStatus,
            reviewedBy:  user.name || body.username,
            submittedBy: txRow[7] || '',
          }).catch(() => {});
        }

        return new Response(JSON.stringify({ ok: true, status: newStatus }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── update_budget ────────────────────────────────────────
    if (action === 'update_budget') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      if (user.role !== 'admin')
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const { budgetId, allocated, notes } = body;
      if (!budgetId || !allocated)
        return new Response(JSON.stringify({ error: 'Missing budgetId or allocated' }), { status: 400, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;

      try {
        const token = await getDriveToken(env);

        const bData = await (await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Budget`,
          { headers: { Authorization: `Bearer ${token}` } }
        )).json();
        const bRows = bData.values || [];
        const bRowIdx = bRows.findIndex((r, i) => i > 0 && r[0] === budgetId);

        if (bRowIdx < 1)
          return new Response(JSON.stringify({ error: 'Budget ID not found' }), { status: 404, headers });

        const sheetRow = bRowIdx + 1;
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Budget!E${sheetRow}:I${sheetRow}?valueInputOption=USER_ENTERED`,
          {
            method: 'PUT',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ values: [[allocated, bRows[bRowIdx][5] || 0,
              parseFloat(allocated) - parseFloat(bRows[bRowIdx][5] || 0),
              bRows[bRowIdx][7] || '', notes || bRows[bRowIdx][8] || '']] })
          }
        );

        return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }


    // ─── add_budget ───────────────────────────────────────────
    if (action === 'add_budget') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      if (user.role !== 'admin')
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const { program, projectId, category, allocated, period, notes } = body;
      if (!program || !category || !allocated)
        return new Response(JSON.stringify({ error: 'Missing required fields: program, category, allocated' }), { status: 400, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      if (!finSheetId) return new Response(JSON.stringify({ error: 'FINANCE_SPREADSHEET_ID not configured' }), { status: 500, headers });

      try {
        const token = await getDriveToken(env);

        // Generate Budget ID: BDG-<PROJECT>-<CATEGORY>-<timestamp short>
        const safeProj = String(program).replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 6);
        const safeCat  = String(category).replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 4);
        const budgetId = `BDG-${safeProj}-${safeCat}-${Date.now().toString(36).toUpperCase().slice(-4)}`;

        const spent     = 0;
        const remaining = parseFloat(allocated) - spent;

        // Budget columns: Budget ID | Program | Project ID | Category | Allocated | Spent | Remaining | Period | Notes
        const row = [budgetId, program, projectId || '', category, parseFloat(allocated), spent, remaining, period || '', notes || ''];

        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/Budget:append?valueInputOption=USER_ENTERED`,
          {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ values: [row] })
          }
        );

        return new Response(JSON.stringify({ ok: true, budgetId }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }


    // ─── get_projects ─────────────────────────────────────────
    if (action === 'get_projects') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      try {
        const rows = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, 'Projects');
        const hIdx = rows.findIndex(r => r && r.some(c => String(c).trim() === 'Project ID'));
        if (hIdx < 0) return new Response(JSON.stringify({ ok: true, projects: [] }), { status: 200, headers });
        const [hdrs, ...data] = rows.slice(hIdx);
        const projects = data
          .map(r => Object.fromEntries(hdrs.map((h,i) => [h.trim(), r[i] || ''])))
          .filter(r => r['Project ID']);
        const programId = body.programId;
        const filtered = programId ? projects.filter(p => p['Program ID'] === programId) : projects;
        return new Response(JSON.stringify({ ok: true, projects: filtered }), { status: 200, headers });
      } catch(e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── add_project ──────────────────────────────────────────
    if (action === 'add_project') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      if (!['admin', 'manager'].includes(user.role))
        return new Response(JSON.stringify({ error: 'Admin or Manager only' }), { status: 403, headers });

      const { programId, projectName, description, startCW, endCW, quarter, status, responsible } = body;
      if (!programId || !projectName)
        return new Response(JSON.stringify({ error: 'Missing programId or projectName' }), { status: 400, headers });

      try {
        const token = await getDriveToken(env);
        // Ensure Projects sheet has headers
        const existing = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, 'Projects').catch(() => []);
        if (!existing.length || !existing[0] || !existing[0].includes('Project ID')) {
          await appendToSheet(token, env.SPREADSHEET_ID, 'Projects',
            ['Project ID', 'Program ID', 'Project Name', 'Description', 'Start CW', 'End CW', 'Quarter', 'Status', 'Responsible', 'Created By', 'Created At']);
        }
        const projectId = `PRG-${String(programId).replace(/[^a-zA-Z0-9]/g,'').toUpperCase()}-${Date.now().toString(36).toUpperCase().slice(-5)}`;
        const now = new Date().toISOString();
        await appendToSheet(token, env.SPREADSHEET_ID, 'Projects',
          [projectId, programId, projectName, description || '',
           startCW || '', endCW || '', quarter || '', status || 'Planning', responsible || '',
           user.name || user._key, now]);
        // Fire notification — non-blocking
        await sendNotification(env, 'project_created', {
          projectId:   projectId,
          projectName: projectName,
          programId:   programId,
          programName: programId,
          createdBy:   user.name || body.username,
        }).catch(() => {});

        return new Response(JSON.stringify({ ok: true, projectId }), { status: 200, headers });
      } catch(e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── get_proposals ────────────────────────────────────────
    if (action === 'get_proposals') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const finRoles = ['finance_staff', 'finance_manager'];
      const allRoles = ['admin', 'manager', 'finance_manager'];
      if (!['admin', 'manager', 'finance_staff', 'finance_manager'].includes(user.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      if (!finSheetId) return new Response(JSON.stringify({ error: 'FINANCE_SPREADSHEET_ID not configured' }), { status: 500, headers });

      try {
        const token = await getDriveToken(env);
        const res = await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        const d = await res.json();
        if (d.error) return new Response(JSON.stringify({ ok: true, proposals: [] }), { status: 200, headers });
        const rows = d.values || [];
        if (rows.length < 2) return new Response(JSON.stringify({ ok: true, proposals: [] }), { status: 200, headers });
        const [hdrs, ...data] = rows;
        let proposals = data
          .map(r => Object.fromEntries(hdrs.map((h,i) => [h.trim(), r[i] || ''])))
          .filter(r => r['Proposal ID']);
        // finance_staff only sees own proposals
        if (user.role === 'finance_staff') {
          proposals = proposals.filter(p => p['Proposed By'] === (user.name || user._key));
        }
        return new Response(JSON.stringify({ ok: true, proposals }), { status: 200, headers });
      } catch(e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── save_proposal ────────────────────────────────────────
    if (action === 'save_proposal') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      if (!['admin', 'manager', 'finance_staff', 'finance_manager'].includes(user.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const { programId, projectId, category, requestedAmount, justification, period, notes, proposalId } = body;
      if (!programId || !projectId || !requestedAmount || !justification)
        return new Response(JSON.stringify({ error: 'Missing required fields' }), { status: 400, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      const token = await getDriveToken(env);
      const now = new Date().toISOString();
      const proposedBy = user.name || user._key;
      const PROP_HEADERS = ['Proposal ID','Program ID','Project ID','Category','Requested Amount',
                            'Justification','Period','Notes','Proposed By','Proposed At','Status',
                            'Reviewed By','Reviewed At','Review Notes'];

      // Helper: fetch current sheet rows with OAuth
      const fetchPropRows = async () => {
        const d = await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}`,
          { headers: { Authorization: `Bearer ${token}` } }
        ).then(r => r.json());
        return d.values || [];
      };

      try {
        // Ensure sheet exists with correct headers
        let rows = await fetchPropRows();
        const hasCorrectHeader = rows.length > 0 && rows[0][0] === 'Proposal ID';

        if (!hasCorrectHeader) {
          // Create sheet tab (ignore "already exists")
          await createSheetTab(token, finSheetId, 'Budget_Proposals');

          if (rows.length === 0) {
            // Brand new sheet — just append header
            await appendToSheet(token, finSheetId, 'Budget_Proposals', PROP_HEADERS);
          } else {
            // Sheet exists but has wrong headers (data from earlier broken saves)
            // Overwrite row 1 with correct headers using PUT
            await fetch(
              `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}!A1:N1?valueInputOption=USER_ENTERED`,
              {
                method: 'PUT',
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ values: [PROP_HEADERS] })
              }
            );
          }
          // Re-fetch after fixing headers
          rows = await fetchPropRows();
        }

        if (proposalId) {
          // Update existing draft — find row by Proposal ID in col A
          const rowIdx = rows.findIndex((r, i) => i > 0 && r[0] === proposalId);
          if (rowIdx < 1) return new Response(JSON.stringify({ error: 'Proposal not found' }), { status: 404, headers });
          const sheetRow = rowIdx + 1;
          const existingRow = rows[rowIdx];
          await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}!A${sheetRow}:N${sheetRow}?valueInputOption=USER_ENTERED`,
            {
              method: 'PUT',
              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ values: [[
                proposalId, programId, projectId, category || '',
                requestedAmount, justification, period || '', notes || '',
                proposedBy,
                existingRow[9] || now,          // Proposed At — preserve original
                existingRow[10] || 'draft',     // Status — preserve
                existingRow[11] || '',          // Reviewed By
                existingRow[12] || '',          // Reviewed At
                existingRow[13] || ''           // Review Notes
              ]] })
            }
          );
          return new Response(JSON.stringify({ ok: true, proposalId }), { status: 200, headers });
        } else {
          // New proposal
          const newId = `PROP-${Date.now().toString(36).toUpperCase()}`;
          await appendToSheet(token, finSheetId, 'Budget_Proposals',
            [newId, programId, projectId, category || '', requestedAmount,
             justification, period || '', notes || '', proposedBy, now, 'draft', '', '', '']);
          return new Response(JSON.stringify({ ok: true, proposalId: newId }), { status: 200, headers });
        }
      } catch(e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── submit_proposal ──────────────────────────────────────
    if (action === 'submit_proposal') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      if (!['admin', 'manager', 'finance_staff', 'finance_manager'].includes(user.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const { proposalId } = body;
      if (!proposalId) return new Response(JSON.stringify({ error: 'Missing proposalId' }), { status: 400, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      const token = await getDriveToken(env);

      try {
        const d = await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}`,
          { headers: { Authorization: `Bearer ${token}` } }
        ).then(r => r.json());

        const rows = d.values || [];
        const rowIdx = rows.findIndex((r, i) => i > 0 && r[0] === proposalId);
        if (rowIdx < 1) return new Response(JSON.stringify({ error: 'Proposal not found' }), { status: 404, headers });

        // Finance staff can only submit their own
        const proposedBy = rows[rowIdx][8] || '';
        if (user.role === 'finance_staff' && proposedBy !== (user.name || user._key))
          return new Response(JSON.stringify({ error: 'Can only submit your own proposals' }), { status: 403, headers });

        const sheetRow = rowIdx + 1;
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}!K${sheetRow}?valueInputOption=USER_ENTERED`,
          {
            method: 'PUT',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ values: [['submitted']] })
          }
        );
        // Fire notification — non-blocking
        const submittedRow = rows[rowIdx];
        await sendNotification(env, 'proposal_submitted', {
          proposalId:  proposalId,
          programId:   submittedRow[1] || '',
          category:    submittedRow[3] || '',
          amount:      submittedRow[4] || 0,
          proposedBy:  submittedRow[8] || user.name,
        }).catch(() => {});

        return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
      } catch(e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

    // ─── review_proposal ──────────────────────────────────────
    if (action === 'review_proposal') {
      const user = validateUser(body.username, body.password);
      if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      if (user.role !== 'admin')
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const { proposalId, decision, reviewNotes } = body;
      if (!proposalId || !decision) return new Response(JSON.stringify({ error: 'Missing proposalId or decision' }), { status: 400, headers });
      if (!['approved', 'rejected'].includes(decision)) return new Response(JSON.stringify({ error: 'Decision must be approved or rejected' }), { status: 400, headers });

      const finSheetId = env.FINANCE_SPREADSHEET_ID;
      const token = await getDriveToken(env);
      const now = new Date().toISOString();

      try {
        const d = await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}`,
          { headers: { Authorization: `Bearer ${token}` } }
        ).then(r => r.json());

        const rows = d.values || [];
        const rowIdx = rows.findIndex((r, i) => i > 0 && r[0] === proposalId);
        if (rowIdx < 1) return new Response(JSON.stringify({ error: 'Proposal not found' }), { status: 404, headers });

        const row = rows[rowIdx];
        const sheetRow = rowIdx + 1;

        // Update status, reviewer, reviewed at, review notes
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finSheetId}/values/${encodeURIComponent('Budget_Proposals')}!K${sheetRow}:N${sheetRow}?valueInputOption=USER_ENTERED`,
          {
            method: 'PUT',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ values: [[decision, user.name || user._key, now, reviewNotes || '']] })
          }
        );

        // On approval: auto-create Budget line
        if (decision === 'approved') {
          const [, programId, projectId, category, requestedAmount, , period, notes] = row;
          const safeProj = String(programId).replace(/[^a-zA-Z0-9]/g,'').toUpperCase().slice(0,6);
          const safeCat  = String(category || 'GEN').replace(/[^a-zA-Z0-9]/g,'').toUpperCase().slice(0,4);
          const budgetId = `BDG-${safeProj}-${safeCat}-${Date.now().toString(36).toUpperCase().slice(-4)}`;
          const allocated = parseFloat(requestedAmount) || 0;
          // Budget: Budget ID | Program | Category | Allocated | Spent | Remaining | Period | Notes
          // Clean projectId: ALL_PROJECTS means entire program → store as empty
          const cleanprojectId = (projectId === 'ALL_PROJECTS' || !projectId) ? '' : projectId;
          const budgetRow = [budgetId, programId, cleanprojectId, category || 'General', allocated, 0, allocated,
                             period || '', `Auto from proposal ${proposalId}. ${notes || ''}`.trim()];
          await appendToSheet(token, finSheetId, 'Budget', budgetRow);
        }

        // Fire notification — non-blocking
        await sendNotification(env, 'proposal_reviewed', {
          proposalId:  proposalId,
          category:    row[3] || '',
          status:      decision,
          reviewedBy:  user.name || body.username,
          reviewNotes: reviewNotes || '',
          proposedBy:  row[8] || '',
        }).catch(e => console.error('[Notify review_proposal]', e.message));

        return new Response(JSON.stringify({ ok: true, decision, budgetCreated: decision === 'approved' }), { status: 200, headers });
      } catch(e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 500, headers });
      }
    }

      return new Response(JSON.stringify({ error: 'Unknown action' }), { status: 400, headers });

    } catch(e) {
      // Catch-all — always return CORS headers so browser doesn't show CORS error
      console.error('Worker unhandled error:', e.message);
      return new Response(JSON.stringify({ error: 'Internal error: ' + e.message }), { status: 500, headers });
    }
  }
};