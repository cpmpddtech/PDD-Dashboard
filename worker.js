/**
 * ═══════════════════════════════════════════════════════════════
 *  PDP Dashboard — Cloudflare Worker v3.0.0  (Finance v2 — MMK donor-aware budgets)
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
 *    ANNOUNCEMENTS_FOLDER_ID → Google Drive folder ID for Announcement logs
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
//   expense_submitted   — expense submitted, awaiting approval
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
    const { taskName, programId, programName, projectName, cw, quarter, assignee, assignedBy } = data;
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
          ...(projectName ? [row('Project', projectName)] : []),
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
    const submitterEmail  = emailOf(submittedBy, 'expense_reviewed');
    const directorEmails  = emailsOfRole('expense_reviewed', 'admin', 'manager', 'finance_manager');
    const fallbackEmail   = env.ALERT_EMAIL_TO || null;
    const recipients      = [...new Set([submitterEmail, ...directorEmails, fallbackEmail].filter(Boolean))];
    const isApproved      = status === 'approved';
    return {
      to:      recipients.length > 0 ? recipients : (fallbackEmail ? [fallbackEmail] : []),
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

  if (event === 'expense_submitted') {
    const { txId, description, amount, quarter, submittedBy, budgetName, donorName } = data;
    // Submitter gets a confirmation
    const submitterEmail  = emailOf(submittedBy, 'expense_submitted');
    // Managers get an approval request
    const managerEmails   = emailsOfRole('expense_submitted', 'admin', 'manager', 'finance_manager');
    const fallbackEmail   = env.ALERT_EMAIL_TO || null;
    const recipients      = [...new Set([submitterEmail, ...managerEmails, fallbackEmail].filter(Boolean))];
    return {
      to:      recipients,
      subject: `[PDD] Expense submitted for approval: ${description}`,
      html:    wrap(`
        <h2 style="margin:0 0 6px;font-size:18px;">Expense submitted for approval</h2>
        <p style="color:#64748b;margin:0 0 20px;font-size:13px;">Submitted by ${submittedBy} — awaiting Finance Manager review</p>
        ${table(
          row('Transaction', txId),
          row('Budget',      budgetName || '—'),
          row('Donor',       donorName  || '—'),
          row('Description', description),
          row('Amount',      'MMK ' + Number(amount||0).toLocaleString()),
          row('Quarter',     quarter || '—'),
          row('Status',      badge('PENDING APPROVAL', '#d97706')),
          row('Submitted By',submittedBy),
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
      const sheetHeaders = ['Task ID','Program ID','Program Name','Task Name','Quarter','CW','Status','Owner','Project Name'];
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
      const taskUser = validateUser(username, password);
      if (!taskUser)
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      // Staff/external can only add tasks to their assigned programs
      const allowedRoles = ['admin','manager','staff','external','finance_staff','finance_manager','finance'];
      if (!allowedRoles.includes(taskUser.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });
      // Staff/external: verify program is assigned to them
      if (['staff','external'].includes(taskUser.role) && taskUser.programs?.length) {
        const programId = body.task?.programId;
        if (programId && !taskUser.programs.includes(programId))
          return new Response(JSON.stringify({ error: 'Program not assigned to you' }), { status: 403, headers });
      }

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
        taskId,                    // col A — Task ID
        task.programId,            // col B — Program ID
        task.programName,          // col C — Program Name
        task.name,                 // col D — Task Name
        task.quarter,              // col E — Quarter
        cwNum,                     // col F — CW (number)
        task.status || 'Planned',  // col G — Status
        task.owner,                // col H — Owner
        task.projectName || '',    // col I — Project Name      // col H — Owner
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
        projectName: task.projectName || '',
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

      // ═══════════════════════════════════════════════════════════════
    //  FINANCE v2 — MMK-only donor-aware budget system
    //  Sheets: Donors | Budgets | Budget_Donors | Line_Items | Expenditures
    // ═══════════════════════════════════════════════════════════════

    // ── Helper: get finance sheet ID ─────────────────────────────
    function getFinSheetId() {
      if (!env.FINANCE_SPREADSHEET_ID) throw new Error('FINANCE_SPREADSHEET_ID secret not set');
      return env.FINANCE_SPREADSHEET_ID;
    }

    // ── Helper: read finance sheet with OAuth ─────────────────────
    async function readFinSheet(token, sheetName) {
      const res = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${getFinSheetId()}/values/${encodeURIComponent(sheetName)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const d = await res.json();
      if (d.error) return [];
      const rows = d.values || [];
      if (rows.length < 2) return [];
      const [hdrs, ...data] = rows;
      return data.map(r => Object.fromEntries(hdrs.map((h, i) => [h.trim(), r[i] ?? ''])));
    }

    // ── Helper: append to finance sheet ──────────────────────────
    async function appendFin(token, sheetName, row) {
      return appendToSheet(token, getFinSheetId(), sheetName, row);
    }

    // ── Helper: update a single cell range in finance sheet ───────
    async function updateFinRange(token, range, values) {
      const url = `https://sheets.googleapis.com/v4/spreadsheets/${getFinSheetId()}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`;
      const res = await fetch(url, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ values }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error('Sheet update failed: ' + (e.error?.message || res.status));
      }
      return res.json();
    }

    // ── Helper: generate short ID ─────────────────────────────────
    function genId(prefix) {
      return `${prefix}-${Date.now().toString(36).toUpperCase().slice(-6)}`;
    }

    // ── Roles allowed in finance v2 ───────────────────────────────
    const FIN_ROLES = ['admin', 'manager', 'finance_manager', 'finance_staff', 'finance'];
    const FIN_MANAGER_ROLES = ['admin', 'manager', 'finance_manager'];

    // ════════════════════════════════════════════════════════════════
    //  setup_finance_sheets
    //  Creates the 5 finance sheets with correct headers.
    //  Safe to run multiple times — skips sheets that already exist.
    // ════════════════════════════════════════════════════════════════
    if (action === 'setup_finance_sheets') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_MANAGER_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      const driveToken = await getDriveToken(env);
      const finId = getFinSheetId();
      const created = [], skipped = [];

      const SHEETS = [
        {
          name: 'Donors',
          headers: ['Donor ID', 'Name', 'Currency', 'Report Format', 'Notes', 'Created By', 'Created At'],
        },
        {
          name: 'Budgets',
          headers: ['Budget ID', 'Programme ID', 'Name', 'Fiscal Year', 'Period Start', 'Period End', 'Diocese', 'Status', 'Created By', 'Created At'],
        },
        {
          name: 'Budget_Donors',
          headers: ['BD ID', 'Budget ID', 'Donor ID', 'Donor Name', 'Allocated MMK', 'Ref Rate', 'Ref Currency', 'Notes'],
        },
        {
          name: 'Line_Items',
          headers: ['LI ID', 'Budget ID', 'Section No', 'Section Name', 'Description', 'Unit Cost MMK', 'Num Units', 'Total MMK', 'Donor Splits JSON', 'Notes'],
        },
        {
          name: 'Expenditures',
          headers: ['Exp ID', 'Line Item ID', 'BD ID', 'Budget ID', 'Donor ID', 'Quarter', 'Amount MMK', 'Description', 'Expense Date', 'Submitted By', 'Submitted At', 'Approved By', 'Approved At', 'Status'],
        },
      ];

      for (const sheet of SHEETS) {
        // Check if sheet already has correct header
        const existing = await fetchSheet(env.GOOGLE_API_KEY, finId, sheet.name).catch(() => []);
        const hasHeader = existing.some(row => row && row[0] === sheet.headers[0]);

        if (hasHeader) {
          skipped.push(sheet.name);
          continue;
        }

        // Create the sheet tab (ignore "already exists" error)
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${finId}:batchUpdate`,
          {
            method: 'POST',
            headers: { Authorization: `Bearer ${driveToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ requests: [{ addSheet: { properties: { title: sheet.name } } }] }),
          }
        ).catch(() => {});

        // Write headers to row 1
        await appendFin(driveToken, sheet.name, sheet.headers);
        created.push(sheet.name);
      }

      return new Response(JSON.stringify({ ok: true, created, skipped }), { status: 200, headers });
    }

    // ════════════════════════════════════════════════════════════════
    //  get_finance_v2
    //  Returns all 5 tables in one call — the main data load for finance.html
    // ════════════════════════════════════════════════════════════════
    if (action === 'get_finance_v2') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const token = await getDriveToken(env);
      const [donors, budgets, budgetDonors, lineItems, expenditures] = await Promise.all([
        readFinSheet(token, 'Donors'),
        readFinSheet(token, 'Budgets'),
        readFinSheet(token, 'Budget_Donors'),
        readFinSheet(token, 'Line_Items'),
        readFinSheet(token, 'Expenditures'),
      ]);

      // Diocese staff: filter budgets to their diocese only
      let filteredBudgets = budgets;
      if (u.role === 'finance_staff' && u.diocese) {
        filteredBudgets = budgets.filter(b => !b['Diocese'] || b['Diocese'] === u.diocese);
      }
      const allowedBudgetIds = new Set(filteredBudgets.map(b => b['Budget ID']));

      // Filter downstream tables to match allowed budgets
      const filteredBDs    = budgetDonors.filter(bd => allowedBudgetIds.has(bd['Budget ID']));
      const allowedBDIds   = new Set(filteredBDs.map(bd => bd['BD ID']));
      const filteredLIs    = lineItems.filter(li => allowedBudgetIds.has(li['Budget ID']));
      const allowedLIIds   = new Set(filteredLIs.map(li => li['LI ID']));
      const filteredExps   = expenditures.filter(e =>
        allowedLIIds.has(e['Line Item ID']) ||
        allowedBDIds.has(e['BD ID']) ||
        (u.role === 'finance_staff' && e['Submitted By'] === u.name)
      );

      // Also return programmes list from main sheet for dropdowns
      let programmes = [];
      try {
        const mainRows = await fetchSheet(env.GOOGLE_API_KEY, env.SPREADSHEET_ID, 'Main Programs');
        const hIdx = mainRows.findIndex(r => r && r.some(c => String(c).trim() === 'Program ID'));
        if (hIdx >= 0) {
          const [hdrs, ...data] = mainRows.slice(hIdx);
          programmes = data
            .map(r => Object.fromEntries(hdrs.map((h, i) => [h.trim(), r[i] || ''])))
            .filter(r => r['Program ID'] && !String(r['Program ID']).startsWith('#') && !String(r['Program ID']).startsWith('='))
            .map(r => ({ id: r['Program ID'].trim(), name: (r['Program Name '] || r['Program Name'] || r['Program ID']).trim() }));
        }
      } catch (_) {}

      return new Response(JSON.stringify({
        ok: true,
        donors,
        budgets: filteredBudgets,
        budgetDonors: filteredBDs,
        lineItems: filteredLIs,
        expenditures: filteredExps,
        programmes,
        userRole: u.role,
        userDiocese: u.diocese || null,
      }), { status: 200, headers });
    }

    // ════════════════════════════════════════════════════════════════
    //  save_donor
    //  Create or update a donor record
    // ════════════════════════════════════════════════════════════════
    if (action === 'save_donor') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_MANAGER_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      const { donorId, name, currency, reportFormat, notes } = body;
      if (!name)
        return new Response(JSON.stringify({ error: 'Name and currency are required' }), { status: 400, headers });

      const token = await getDriveToken(env);

      if (donorId) {
        // Update existing — find row by Donor ID
        const rows = await fetchSheet(env.GOOGLE_API_KEY, env.FINANCE_SPREADSHEET_ID, 'Donors');
        const hIdx = rows.findIndex(r => r && r[0] === 'Donor ID');
        const rowIdx = rows.findIndex((r, i) => i > hIdx && r[0] === donorId);
        if (rowIdx < 0) return new Response(JSON.stringify({ error: 'Donor not found' }), { status: 404, headers });
        const sheetRow = rowIdx + 1;
        await updateFinRange(token, `Donors!A${sheetRow}:G${sheetRow}`, [[donorId, name, currency || 'MMK', reportFormat || '', notes || '', u.name, rows[rowIdx][6] || new Date().toISOString()]]);
        return new Response(JSON.stringify({ ok: true, donorId }), { status: 200, headers });
      } else {
        // Create new
        const id = genId('D');
        await appendFin(token, 'Donors', [id, name, currency || 'MMK', reportFormat || '', notes || '', u.name, new Date().toISOString()]);
        return new Response(JSON.stringify({ ok: true, donorId: id }), { status: 200, headers });
      }
    }

    // ════════════════════════════════════════════════════════════════
    //  save_budget
    //  Create or update a budget header record
    // ════════════════════════════════════════════════════════════════
    if (action === 'save_budget') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_MANAGER_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      const { budgetId, programmeId, name, fiscalYear, periodStart, periodEnd, diocese } = body;
      if (!name || !programmeId || !fiscalYear)
        return new Response(JSON.stringify({ error: 'Name, programme and fiscal year are required' }), { status: 400, headers });

      const token = await getDriveToken(env);
      const now = new Date().toISOString();

      if (budgetId) {
        // Update existing
        const rows = await fetchSheet(env.GOOGLE_API_KEY, env.FINANCE_SPREADSHEET_ID, 'Budgets');
        const hIdx = rows.findIndex(r => r && r[0] === 'Budget ID');
        const rowIdx = rows.findIndex((r, i) => i > hIdx && r[0] === budgetId);
        if (rowIdx < 0) return new Response(JSON.stringify({ error: 'Budget not found' }), { status: 404, headers });
        const sheetRow = rowIdx + 1;
        await updateFinRange(token, `Budgets!A${sheetRow}:J${sheetRow}`, [[budgetId, programmeId, name, fiscalYear, periodStart || '', periodEnd || '', diocese || '', rows[rowIdx][7] || 'draft', u.name, rows[rowIdx][9] || now]]);
        return new Response(JSON.stringify({ ok: true, budgetId }), { status: 200, headers });
      } else {
        const id = genId('B');
        await appendFin(token, 'Budgets', [id, programmeId, name, fiscalYear, periodStart || '', periodEnd || '', diocese || '', 'draft', u.name, now]);
        return new Response(JSON.stringify({ ok: true, budgetId: id }), { status: 200, headers });
      }
    }

    // ════════════════════════════════════════════════════════════════
    //  save_budget_donor
    //  Attach a donor to a budget with their MMK allocation
    // ════════════════════════════════════════════════════════════════
    if (action === 'save_budget_donor') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_MANAGER_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      const { bdId, budgetId, donorId, donorName, allocatedMmk, refRate, refCurrency, notes } = body;
      if (!budgetId || !donorId || !allocatedMmk)
        return new Response(JSON.stringify({ error: 'Budget ID, donor ID and allocated MMK are required' }), { status: 400, headers });

      const token = await getDriveToken(env);

      if (bdId) {
        // Update existing
        const rows = await fetchSheet(env.GOOGLE_API_KEY, env.FINANCE_SPREADSHEET_ID, 'Budget_Donors');
        const hIdx = rows.findIndex(r => r && r[0] === 'BD ID');
        const rowIdx = rows.findIndex((r, i) => i > hIdx && r[0] === bdId);
        if (rowIdx < 0) return new Response(JSON.stringify({ error: 'Budget donor not found' }), { status: 404, headers });
        const sheetRow = rowIdx + 1;
        await updateFinRange(token, `Budget_Donors!A${sheetRow}:H${sheetRow}`, [[bdId, budgetId, donorId, donorName || '', allocatedMmk, refRate || '', refCurrency || '', notes || '']]);
        return new Response(JSON.stringify({ ok: true, bdId }), { status: 200, headers });
      } else {
        const id = genId('BD');
        await appendFin(token, 'Budget_Donors', [id, budgetId, donorId, donorName || '', allocatedMmk, refRate || '', refCurrency || '', notes || '']);
        return new Response(JSON.stringify({ ok: true, bdId: id }), { status: 200, headers });
      }
    }

    // ════════════════════════════════════════════════════════════════
    //  save_line_item
    //  Add or update a budget line item with donor splits
    // ════════════════════════════════════════════════════════════════
    if (action === 'save_line_item') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_MANAGER_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      const { liId, budgetId, sectionNo, sectionName, description, unitCostMmk, numUnits, donorSplits, notes } = body;
      if (!budgetId || !description || !unitCostMmk || !numUnits)
        return new Response(JSON.stringify({ error: 'Budget ID, description, unit cost and units are required' }), { status: 400, headers });

      const totalMmk = Math.round(parseFloat(unitCostMmk) * parseFloat(numUnits));
      const splitsJson = JSON.stringify(donorSplits || {});
      const token = await getDriveToken(env);

      if (liId) {
        // Update existing
        const rows = await fetchSheet(env.GOOGLE_API_KEY, env.FINANCE_SPREADSHEET_ID, 'Line_Items');
        const hIdx = rows.findIndex(r => r && r[0] === 'LI ID');
        const rowIdx = rows.findIndex((r, i) => i > hIdx && r[0] === liId);
        if (rowIdx < 0) return new Response(JSON.stringify({ error: 'Line item not found' }), { status: 404, headers });
        const sheetRow = rowIdx + 1;
        await updateFinRange(token, `Line_Items!A${sheetRow}:J${sheetRow}`, [[liId, budgetId, sectionNo || '', sectionName || '', description, unitCostMmk, numUnits, totalMmk, splitsJson, notes || '']]);
        return new Response(JSON.stringify({ ok: true, liId, totalMmk }), { status: 200, headers });
      } else {
        const id = genId('LI');
        await appendFin(token, 'Line_Items', [id, budgetId, sectionNo || '', sectionName || '', description, unitCostMmk, numUnits, totalMmk, splitsJson, notes || '']);
        return new Response(JSON.stringify({ ok: true, liId: id, totalMmk }), { status: 200, headers });
      }
    }

    // ════════════════════════════════════════════════════════════════
    //  delete_line_item
    //  Soft-delete: marks the row's description with [DELETED] prefix
    // ════════════════════════════════════════════════════════════════
    if (action === 'delete_line_item') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_MANAGER_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      const { liId } = body;
      if (!liId) return new Response(JSON.stringify({ error: 'Missing liId' }), { status: 400, headers });

      const token = await getDriveToken(env);
      const rows = await fetchSheet(env.GOOGLE_API_KEY, env.FINANCE_SPREADSHEET_ID, 'Line_Items');
      const hIdx = rows.findIndex(r => r && r[0] === 'LI ID');
      const rowIdx = rows.findIndex((r, i) => i > hIdx && r[0] === liId);
      if (rowIdx < 0) return new Response(JSON.stringify({ error: 'Line item not found' }), { status: 404, headers });
      const sheetRow = rowIdx + 1;
      const existing = rows[rowIdx];
      // Prefix description with [DELETED] so it filters out on read
      await updateFinRange(token, `Line_Items!E${sheetRow}`, [['[DELETED] ' + (existing[4] || '')]]);
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    // ════════════════════════════════════════════════════════════════
    //  log_expenditure_v2
    //  Finance staff submits actual quarterly spending
    // ════════════════════════════════════════════════════════════════
    if (action === 'log_expenditure_v2') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const { lineItemId, bdId, budgetId, donorId, quarter, amountMmk, expenseDate, description } = body;
      if (!lineItemId || !bdId || !quarter || !amountMmk)
        return new Response(JSON.stringify({ error: 'Line item, BD ID, quarter and amount are required' }), { status: 400, headers });

      if (!['Q1', 'Q2', 'Q3', 'Q4'].includes(quarter))
        return new Response(JSON.stringify({ error: 'Quarter must be Q1, Q2, Q3 or Q4' }), { status: 400, headers });

      const token = await getDriveToken(env);
      const id = genId('E');
      const now = new Date().toISOString();

      await appendFin(token, 'Expenditures', [
        id, lineItemId, bdId, budgetId || '', donorId || '',
        quarter, amountMmk, description || '',
        expenseDate || now.slice(0,10),
        u.name, now, '', '', 'pending'
      ]);

      // Notify submitter + managers — non-blocking
      const expBudget = FIN_MANAGER_ROLES.includes(u.role) ? null :
        (await readFinSheet(token, 'Budgets').catch(()=>[])).find(b => b['Budget ID'] === (budgetId||''));
      const expDonorRow = (await readFinSheet(token, 'Budget_Donors').catch(()=>[])).find(bd => bd['BD ID'] === bdId);
      await sendNotification(env, 'expense_submitted', {
        txId:        id,
        description: description || lineItemId,
        amount:      amountMmk,
        quarter,
        submittedBy: u.name,
        budgetName:  expBudget?.['Name'] || budgetId || '',
        donorName:   expDonorRow?.['Donor Name'] || donorId || '',
      }).catch(() => {});

      return new Response(JSON.stringify({ ok: true, expId: id }), { status: 200, headers });
    }

    // ════════════════════════════════════════════════════════════════
    //  approve_expenditure_v2 / reject_expenditure_v2
    //  Finance Manager or Admin approves/rejects an expenditure record
    // ════════════════════════════════════════════════════════════════
    if (action === 'approve_expenditure_v2' || action === 'reject_expenditure_v2') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_MANAGER_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      const { expId, notes } = body;
      if (!expId) return new Response(JSON.stringify({ error: 'Missing expId' }), { status: 400, headers });

      const token = await getDriveToken(env);
      const rows = await fetchSheet(env.GOOGLE_API_KEY, env.FINANCE_SPREADSHEET_ID, 'Expenditures');
      const hIdx = rows.findIndex(r => r && r[0] === 'Exp ID');
      const rowIdx = rows.findIndex((r, i) => i > hIdx && r[0] === expId);
      if (rowIdx < 0) return new Response(JSON.stringify({ error: 'Expenditure not found' }), { status: 404, headers });

      const newStatus = action === 'approve_expenditure_v2' ? 'approved' : 'rejected';
      const sheetRow = rowIdx + 1;
      const now = new Date().toISOString();

      // Update columns K (Approved By), L (Approved At), M (Status)
      await updateFinRange(token, `Expenditures!K${sheetRow}:M${sheetRow}`, [[u.name, now, newStatus]]);

      // Notify submitter — non-blocking
      const expRow = rows[rowIdx];
      await sendNotification(env, 'expense_reviewed', {
        txId: expId,
        description: expRow[7] || expRow[1] || expId,
        amount: expRow[6] || '0',
        status: newStatus,
        reviewedBy: u.name,
        submittedBy: expRow[8] || '',
      }).catch(() => {});

      return new Response(JSON.stringify({ ok: true, expId, status: newStatus }), { status: 200, headers });
    }

    // ════════════════════════════════════════════════════════════════
    //  get_budget_detail
    //  Returns full detail for one budget: donors, line items, expenditures, summary
    // ════════════════════════════════════════════════════════════════
    if (action === 'get_budget_detail') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const { budgetId } = body;
      if (!budgetId) return new Response(JSON.stringify({ error: 'Missing budgetId' }), { status: 400, headers });

      const token = await getDriveToken(env);
      const [budgetDonors, lineItems, expenditures] = await Promise.all([
        readFinSheet(token, 'Budget_Donors'),
        readFinSheet(token, 'Line_Items'),
        readFinSheet(token, 'Expenditures'),
      ]);

      const bds  = budgetDonors.filter(bd => bd['Budget ID'] === budgetId);
      const bdIds = new Set(bds.map(bd => bd['BD ID']));
      const lis  = lineItems.filter(li => li['Budget ID'] === budgetId && !String(li['Description'] || '').startsWith('[DELETED]'));
      const liIds = new Set(lis.map(li => li['LI ID']));
      const exps = expenditures.filter(e => e['Budget ID'] === budgetId || liIds.has(e['Line Item ID']));

      // Compute summary per donor
      const summary = bds.map(bd => {
        const allocated = parseFloat(bd['Allocated MMK'] || 0);
        const approved  = exps.filter(e => e['BD ID'] === bd['BD ID'] && e['Status'] === 'approved')
                              .reduce((s, e) => s + parseFloat(e['Amount MMK'] || 0), 0);
        const pending   = exps.filter(e => e['BD ID'] === bd['BD ID'] && e['Status'] === 'pending')
                              .reduce((s, e) => s + parseFloat(e['Amount MMK'] || 0), 0);
        return { ...bd, allocated, approved, pending, balance: allocated - approved };
      });

      // Compute per-quarter totals
      const quarterTotals = { Q1: 0, Q2: 0, Q3: 0, Q4: 0 };
      exps.filter(e => e['Status'] === 'approved').forEach(e => {
        if (quarterTotals[e['Quarter']] !== undefined)
          quarterTotals[e['Quarter']] += parseFloat(e['Amount MMK'] || 0);
      });

      return new Response(JSON.stringify({
        ok: true, budgetDonors: bds, lineItems: lis,
        expenditures: exps, donorSummary: summary, quarterTotals,
      }), { status: 200, headers });
    }

    // ════════════════════════════════════════════════════════════════
    //  get_finance_summary
    //  Province-level consolidated view across all budgets
    // ════════════════════════════════════════════════════════════════
    if (action === 'get_finance_summary') {
      const u = validateUser(body.username, body.password);
      if (!u || !FIN_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      const token = await getDriveToken(env);
      const [budgets, budgetDonors, expenditures] = await Promise.all([
        readFinSheet(token, 'Budgets'),
        readFinSheet(token, 'Budget_Donors'),
        readFinSheet(token, 'Expenditures'),
      ]);

      // Total allocated across all budgets
      const totalAllocated = budgetDonors.reduce((s, bd) => s + parseFloat(bd['Allocated MMK'] || 0), 0);
      const totalApproved  = expenditures.filter(e => e['Status'] === 'approved')
                                         .reduce((s, e) => s + parseFloat(e['Amount MMK'] || 0), 0);
      const totalPending   = expenditures.filter(e => e['Status'] === 'pending')
                                         .reduce((s, e) => s + parseFloat(e['Amount MMK'] || 0), 0);

      // Per-diocese breakdown
      const dioceseSummary = {};
      budgets.forEach(b => {
        const diocese = b['Diocese'] || 'Province';
        if (!dioceseSummary[diocese]) dioceseSummary[diocese] = { allocated: 0, approved: 0, pending: 0, budgetCount: 0 };
        dioceseSummary[diocese].budgetCount++;
        // Sum BDs for this budget
        budgetDonors.filter(bd => bd['Budget ID'] === b['Budget ID']).forEach(bd => {
          dioceseSummary[diocese].allocated += parseFloat(bd['Allocated MMK'] || 0);
        });
        // Sum expenditures for this budget
        expenditures.filter(e => e['Budget ID'] === b['Budget ID']).forEach(e => {
          if (e['Status'] === 'approved') dioceseSummary[diocese].approved += parseFloat(e['Amount MMK'] || 0);
          if (e['Status'] === 'pending')  dioceseSummary[diocese].pending  += parseFloat(e['Amount MMK'] || 0);
        });
      });

      // Per-programme breakdown
      const programmeSummary = {};
      budgets.forEach(b => {
        const prog = b['Programme ID'] || 'Unknown';
        if (!programmeSummary[prog]) programmeSummary[prog] = { allocated: 0, approved: 0, budgetCount: 0 };
        programmeSummary[prog].budgetCount++;
        budgetDonors.filter(bd => bd['Budget ID'] === b['Budget ID']).forEach(bd => {
          programmeSummary[prog].allocated += parseFloat(bd['Allocated MMK'] || 0);
        });
        expenditures.filter(e => e['Budget ID'] === b['Budget ID'] && e['Status'] === 'approved').forEach(e => {
          programmeSummary[prog].approved += parseFloat(e['Amount MMK'] || 0);
        });
      });

      // Pending approvals list
      const pendingList = expenditures
        .filter(e => e['Status'] === 'pending')
        .sort((a, b) => (b['Submitted At'] || '').localeCompare(a['Submitted At'] || ''));

      return new Response(JSON.stringify({
        ok: true,
        totals: { allocated: totalAllocated, approved: totalApproved, pending: totalPending, balance: totalAllocated - totalApproved },
        dioceseSummary,
        programmeSummary,
        pendingList,
        budgetCount: budgets.length,
      }), { status: 200, headers });
    }

    // ════════════════════════════════════════════════════════════════
    //  generate_report
    //  Builds a Google Sheet report in the Finance Reports Drive folder.
    //  reportType: 'budget' | 'donor' | 'consolidated' | 'diocese'
    //  Role gates:
    //    - 'consolidated'  → admin, finance_manager only
    //    - 'donor'         → admin, finance_manager only
    //    - 'budget'        → admin, finance_manager; staff only if budget is in their diocese
    //    - 'diocese'       → all finance roles (staff sees own diocese only)
    // ════════════════════════════════════════════════════════════════
    if (action === 'generate_report') {
      let u = validateUser(body.username, body.password);
      if (!u || !FIN_ROLES.includes(u.role))
        return new Response(JSON.stringify({ error: 'Access denied' }), { status: 403, headers });

      let { reportType, budgetId, donorId, diocese } = body;
      let IS_MGR = FIN_MANAGER_ROLES.includes(u.role);

      // Role gate per report type
      if ((reportType === 'consolidated' || reportType === 'donor') && !IS_MGR)
        return new Response(JSON.stringify({ error: 'Finance Manager or Admin only' }), { status: 403, headers });

      if (!env.FINANCE_REPORTS_FOLDER_ID)
        return new Response(JSON.stringify({ error: 'FINANCE_REPORTS_FOLDER_ID secret not set. Create a "Finance Reports" folder in Drive and add its ID.' }), { status: 500, headers });

      let token = await getDriveToken(env);

      // ── Load all finance data ─────────────────────────────────────
      let [donors, budgets, budgetDonors, lineItems, expenditures] = await Promise.all([
        readFinSheet(token, 'Donors'),
        readFinSheet(token, 'Budgets'),
        readFinSheet(token, 'Budget_Donors'),
        readFinSheet(token, 'Line_Items'),
        readFinSheet(token, 'Expenditures'),
      ]);

      // ── Helper: format number ─────────────────────────────────────
      let n = v => Math.round(parseFloat(v || 0));
      let pct = (a, b) => b > 0 ? Math.round(a / b * 100) + '%' : '0%';
      let now = new Date();
      let dateStr = now.toISOString().slice(0, 10);
      let quarters = ['Q1', 'Q2', 'Q3', 'Q4'];

      // ── Helper: compute budget summary row ────────────────────────
      function budgetSummary(bId) {
        let bds  = budgetDonors.filter(bd => bd['Budget ID'] === bId);
        let exps = expenditures.filter(e  => e['Budget ID']  === bId);
        let allocated = bds.reduce((s, bd) => s + n(bd['Allocated MMK']), 0);
        let approved  = exps.filter(e => e['Status'] === 'approved').reduce((s, e) => s + n(e['Amount MMK']), 0);
        let pending   = exps.filter(e => e['Status'] === 'pending').reduce((s, e) => s + n(e['Amount MMK']), 0);
        let qTotals   = Object.fromEntries(quarters.map(q => [q,
          exps.filter(e => e['Quarter'] === q && e['Status'] === 'approved').reduce((s, e) => s + n(e['Amount MMK']), 0)
        ]));
        return { allocated, approved, pending, balance: allocated - approved, qTotals };
      }

      // ── Helper: build line-item detail rows for a budget ──────────
      function buildDetailRows(bId) {
        let bds = budgetDonors.filter(bd => bd['Budget ID'] === bId);
        let lis = lineItems.filter(li => li['Budget ID'] === bId && !String(li['Description'] || '').startsWith('[DELETED]'));
        let exps = expenditures.filter(e => e['Budget ID'] === bId);

        let rows = [];
        let sections = [...new Set(lis.map(li => li['Section No'] || '?'))].sort();
        let SECTION_NAMES = {
          '1': 'Training & Community Mobilization',
          '2': 'Program Inputs & Activities',
          '3': 'Monitoring & Evaluation',
          '4': 'Other Travel / Networking',
          '5': 'Office & Administrative',
          '6': 'Equipment & Maintenance',
          '7': 'Personnel',
        };

        for (let sec of sections) {
          let secLIs = lis.filter(li => (li['Section No'] || '?') === sec);
          rows.push([`${sec}. ${SECTION_NAMES[sec] || 'Section ' + sec}`, '', '', '', '', '', '', '', '']);
          let secTotal = 0;
          for (let li of secLIs) {
            let liExps = exps.filter(e => e['Line Item ID'] === li['LI ID']);
            let qAmts  = quarters.map(q =>
              liExps.filter(e => e['Quarter'] === q && e['Status'] === 'approved').reduce((s, e) => s + n(e['Amount MMK']), 0)
            );
            let totalSpent = qAmts.reduce((s, v) => s + v, 0);
            let budgeted   = n(li['Total MMK']);
            secTotal += budgeted;
            rows.push([
              '  ' + li['Description'],
              n(li['Unit Cost MMK']),
              n(li['Num Units']),
              budgeted,
              ...qAmts,
              totalSpent,
              budgeted - totalSpent,
              pct(totalSpent, budgeted),
            ]);
          }
          let secSpent = secLIs.reduce((s, li) => {
            return s + exps.filter(e => e['Line Item ID'] === li['LI ID'] && e['Status'] === 'approved').reduce((ss, e) => ss + n(e['Amount MMK']), 0);
          }, 0);
          rows.push([`Section ${sec} total`, '', '', secTotal, '', '', '', secSpent, secTotal - secSpent, pct(secSpent, secTotal)]);
          rows.push([]);
        }
        return rows;
      }

      // ── Helper: build expenditure log rows ────────────────────────
      function buildExpLog(filteredExps, budgetsMap, lineItemsMap, budgetDonorsMap) {
        return [
          ['Exp ID', 'Budget', 'Line Item', 'Donor', 'Quarter', 'Amount MMK', 'Submitted By', 'Submitted At', 'Approved By', 'Approved At', 'Status'],
          ...filteredExps.map(e => [
            e['Exp ID'],
            budgetsMap[e['Budget ID']]?.['Name'] || e['Budget ID'],
            lineItemsMap[e['Line Item ID']]?.['Description'] || e['Line Item ID'],
            budgetDonorsMap[e['BD ID']]?.['Donor Name'] || e['Donor ID'],
            e['Quarter'],
            n(e['Amount MMK']),
            e['Submitted By'],
            e['Submitted At']?.slice(0, 10) || '',
            e['Approved By'] || '',
            e['Approved At']?.slice(0, 10) || '',
            e['Status'],
          ])
        ];
      }

      // Build lookup maps
      let budgetsMap      = Object.fromEntries(budgets.map(b  => [b['Budget ID'],   b]));
      let lineItemsMap    = Object.fromEntries(lineItems.map(l => [l['LI ID'],       l]));
      let budgetDonorsMap = Object.fromEntries(budgetDonors.map(bd => [bd['BD ID'],  bd]));
      let donorsMap       = Object.fromEntries(donors.map(d  => [d['Donor ID'],      d]));

      // ── Helper: create a Google Sheet in Finance Reports folder ───
      // ── Formatting helpers ──────────────────────────────────────
      const FMT = {
        NUM:    { numberFormat: { type: 'NUMBER', pattern: '#,##0' } },
        PCT:    { numberFormat: { type: 'NUMBER', pattern: '0%' } },
        BOLD:   { textFormat: { bold: true } },
        CENTER: { horizontalAlignment: 'CENTER' },
        RIGHT:  { horizontalAlignment: 'RIGHT' },
        WRAP:   { wrapStrategy: 'WRAP' },
        // Fill colors matching ABM Excel exactly
        FILL_TITLE:    { backgroundColor: { red: 1,    green: 1,    blue: 0 } },      // yellow #FFFF00
        FILL_HEADER:   { backgroundColor: { red: 0.565,green: 0.663,blue: 0.855 } }, // steel blue #90A9DA
        FILL_SUBHDR:   { backgroundColor: { red: 0.792,green: 0.851,blue: 0.937 } }, // light blue #CACDEF  
        FILL_SECTION:  { backgroundColor: { red: 0.855,green: 0.902,blue: 0.984 } }, // pale blue #DAE6FB
        FILL_TOTAL:    { backgroundColor: { red: 1,    green: 0.831,blue: 0 } },      // amber #FFD400
        FILL_GRAND:    { backgroundColor: { red: 1,    green: 0.6,  blue: 0 } },      // orange #FF9900
        FILL_DONOR1:   { backgroundColor: { red: 0.969,green: 0.890,blue: 0.769 } }, // peach Diocese
        FILL_DONOR2:   { backgroundColor: { red: 0.851,green: 0.918,blue: 0.827 } }, // mint ABM
        FILL_WHITE:    { backgroundColor: { red: 1,    green: 1,    blue: 1 } },
      };

      function cell(v, ...fmts) {
        let val = typeof v === 'number'
          ? { numberValue: v }
          : (v === null || v === undefined || v === '')
            ? { stringValue: '' }
            : { stringValue: String(v) };
        let fmt = Object.assign({}, ...fmts);
        return { userEnteredValue: val, userEnteredFormat: fmt };
      }
      function numCell(v, ...fmts) {
        return cell(typeof v === 'string' ? (parseFloat(v) || 0) : (v || 0), FMT.NUM, FMT.RIGHT, ...fmts);
      }
      function pctCell(v, ...fmts) {
        let raw = typeof v === 'string' ? parseFloat(v)/100 : (v||0)/100;
        return { userEnteredValue: { numberValue: raw }, userEnteredFormat: Object.assign({}, FMT.PCT, FMT.RIGHT, ...fmts) };
      }
      function emptyRow(n=18) { return Array(n).fill(cell('')); }

      // ── Build ABM-format Joint Budget sheet ──────────────────────
      function buildABMSheet(budget, bds, lis, exps, donorsMap) {
        let rows    = [];
        let nv      = v => Math.round(parseFloat(v || 0));
        let quarters = ['Q1','Q2','Q3','Q4'];
        let SNAMES  = {
          '1':'Training Costs and Community Mobilization Activities',
          '2':'Program Inputs and Activities',
          '3':'Baseline, Monitoring and Evaluation (include travel for M&E)',
          '4':"Other Travel (Networking, Stakeholder's Meetings, etc)",
          '5':'Office Running / Administrative Expenses',
          '6':'Equipment Purchases and Maintenance',
          '7':'Personnel',
        };

        // FX setup — reads Ref Rate / Ref Currency from Budget_Donors record
        let fxDonors  = bds.filter(bd => bd['Ref Rate'] && parseFloat(bd['Ref Rate']) > 0 && bd['Ref Currency'] && bd['Ref Currency'] !== 'MMK');
        let primaryFX = fxDonors[0] || null;
        let fxRate     = primaryFX ? parseFloat(primaryFX['Ref Rate']) : 0;
        let fxCur      = primaryFX ? (primaryFX['Ref Currency'] || '') : '';
        let hasFX      = fxRate > 0 && fxCur;
        let toFX       = mmk => hasFX ? Math.round(mmk / fxRate) : 0;

        let nd = Math.min(bds.length, 2);
        let dnames = bds.map(bd => bd['Donor Name'] || donorsMap[bd['Donor ID']]?.['Name'] || bd['Donor ID']);
        let tc = 4 + nd + (nd * 4) + (hasFX ? 5 : 3);
        let er = n => Array(Math.max(0,n)).fill(cell(''));

        // Title block
        rows.push([...er(tc)]);
        rows.push([cell('Joint Financial Budget & Reporting Template', FMT.BOLD, FMT.CENTER, FMT.FILL_TITLE), ...er(tc-1).map(()=>cell('',FMT.FILL_TITLE))]);
        rows.push([cell(budget['Name']||'', FMT.BOLD, FMT.CENTER, FMT.FILL_TITLE), ...er(tc-1).map(()=>cell('',FMT.FILL_TITLE))]);
        rows.push([...er(tc)]);

        // Exchange rate row
        if (hasFX) {
          rows.push([cell('Exchange rate', FMT.BOLD), cell('1 '+fxCur+' = '+fxRate.toLocaleString()+' MMK', FMT.BOLD, FMT.FILL_TITLE), ...er(tc-2)]);
        } else {
          rows.push([...er(tc)]);
        }
        rows.push([cell('Fiscal Year: '+(budget['Fiscal Year']||''), FMT.BOLD), cell('Diocese: '+(budget['Diocese']||'Province-wide'), FMT.BOLD), ...er(tc-2)]);
        rows.push([cell('Generated: '+new Date().toISOString().slice(0,10), FMT.BOLD), ...er(tc-1)]);
        rows.push([...er(tc)]);

        // Column headers
        let hdr = [
          cell('LINE ITEM CATEGORIES', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER),
          cell('Unit Cost (MMK)', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER, FMT.WRAP),
          cell('Nº of Units', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER),
          cell('TOTAL BUDGET (MMK)', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER, FMT.WRAP),
          ...bds.slice(0,2).map((bd,i) => cell((dnames[i]||'Donor'+(i+1))+' Budget MMK', FMT.BOLD, FMT.CENTER, FMT.WRAP, i===0?FMT.FILL_DONOR1:FMT.FILL_DONOR2)),
          ...quarters.flatMap(q => bds.slice(0,2).map((bd,i) => cell(q+' '+(dnames[i]||'D'+(i+1)), FMT.BOLD, FMT.CENTER, FMT.WRAP, i===0?FMT.FILL_DONOR1:FMT.FILL_DONOR2))),
          cell('TOTAL EXPENSE (MMK)', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER, FMT.WRAP),
        ];
        if (hasFX) hdr.push(cell('TOTAL EXPENSE ('+fxCur+')', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER, FMT.WRAP));
        hdr.push(cell('BALANCE (MMK)', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER, FMT.WRAP));
        if (hasFX) hdr.push(cell('BALANCE ('+fxCur+')', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER, FMT.WRAP));
        hdr.push(cell('%', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER));
        rows.push(hdr);

        // Sections
        let secs = [...new Set(lis.map(li => li['Section No']||'?'))].sort();
        let gBudget = 0, gSpent = 0;

        for (let sec of secs) {
          let sname = SNAMES[sec] || 'Section '+sec;
          let sLIs  = lis.filter(li => (li['Section No']||'?') === sec);
          rows.push([cell(sec+'. '+sname, FMT.BOLD, FMT.FILL_SECTION), ...er(tc-1).map(()=>cell('',FMT.FILL_SECTION))]);

          let sBudget = 0, sSpent = 0;
          for (let li of sLIs) {
            let liExps = exps.filter(e => e['Line Item ID'] === li['LI ID']);
            let splits = {};
            try { splits = JSON.parse(li['Donor Splits JSON']||'{}'); } catch(_){}

            let budgeted = nv(li['Total MMK']);
            sBudget  += budgeted;
            gBudget  += budgeted;

            let dBudgets = bds.slice(0,2).map(bd => nv(splits[bd['BD ID']]||0));
            let qAmts    = quarters.flatMap(q => bds.slice(0,2).map(bd =>
              liExps.filter(e => e['Quarter']===q && e['BD ID']===bd['BD ID'] && e['Status']==='approved')
                    .reduce((s,e) => s+nv(e['Amount MMK']), 0)
            ));
            let spent = qAmts.reduce((s,v) => s+v, 0);
            sSpent  += spent;
            gSpent  += spent;
            let pct  = budgeted > 0 ? spent/budgeted : 0;

            let r = [cell('  '+li['Description'], FMT.WRAP), numCell(nv(li['Unit Cost MMK'])), numCell(nv(li['Num Units'])), numCell(budgeted),
              ...dBudgets.map(v => numCell(v)), ...qAmts.map(v => numCell(v)), numCell(spent, FMT.BOLD)];
            if (hasFX) r.push(numCell(toFX(spent)));
            r.push(numCell(budgeted - spent));
            if (hasFX) r.push(numCell(toFX(budgeted - spent)));
            r.push({ userEnteredValue:{numberValue:pct}, userEnteredFormat:Object.assign({},FMT.PCT,FMT.RIGHT) });
            rows.push(r);
          }

          let sPct = sBudget > 0 ? sSpent/sBudget : 0;
          let st = [cell('Total '+sname, FMT.BOLD, FMT.FILL_TOTAL), cell('',FMT.FILL_TOTAL), cell('',FMT.FILL_TOTAL),
            numCell(sBudget, FMT.BOLD, FMT.FILL_TOTAL),
            ...Array(nd + nd*4).fill(cell('',FMT.FILL_TOTAL)),
            numCell(sSpent, FMT.BOLD, FMT.FILL_TOTAL)];
          if (hasFX) st.push(numCell(toFX(sSpent), FMT.BOLD, FMT.FILL_TOTAL));
          st.push(numCell(sBudget-sSpent, FMT.BOLD, FMT.FILL_TOTAL));
          if (hasFX) st.push(numCell(toFX(sBudget-sSpent), FMT.BOLD, FMT.FILL_TOTAL));
          st.push({ userEnteredValue:{numberValue:sPct}, userEnteredFormat:Object.assign({},FMT.PCT,FMT.RIGHT,FMT.BOLD,FMT.FILL_TOTAL) });
          rows.push(st);
          rows.push([...er(tc)]);
        }

        // Grand total
        let gPct = gBudget > 0 ? gSpent/gBudget : 0;
        let gt = [cell('TOTAL', FMT.BOLD, FMT.FILL_GRAND), cell('',FMT.FILL_GRAND), cell('',FMT.FILL_GRAND),
          numCell(gBudget, FMT.BOLD, FMT.FILL_GRAND),
          ...Array(nd + nd*4).fill(cell('',FMT.FILL_GRAND)),
          numCell(gSpent, FMT.BOLD, FMT.FILL_GRAND)];
        if (hasFX) gt.push(numCell(toFX(gSpent), FMT.BOLD, FMT.FILL_GRAND));
        gt.push(numCell(gBudget-gSpent, FMT.BOLD, FMT.FILL_GRAND));
        if (hasFX) gt.push(numCell(toFX(gBudget-gSpent), FMT.BOLD, FMT.FILL_GRAND));
        gt.push({ userEnteredValue:{numberValue:gPct}, userEnteredFormat:Object.assign({},FMT.PCT,FMT.RIGHT,FMT.BOLD,FMT.FILL_GRAND) });
        rows.push(gt);

        // FX footnote
        if (hasFX) {
          rows.push([...er(tc)]);
          rows.push([cell('* '+fxCur+' amounts at agreed rate: 1 '+fxCur+' = '+fxRate.toLocaleString()+' MMK', FMT.BOLD), ...er(tc-1)]);
        }

        // Signature block
        rows.push([...er(tc)]);
        rows.push([...er(tc)]);
        rows.push([cell('Prepared by', FMT.BOLD), ...er(2), cell('Approved by', FMT.BOLD), ...er(tc-4)]);
        rows.push([...er(tc)]);
        rows.push([cell('_________________________'), ...er(2), cell('_________________________'), ...er(tc-4)]);
        rows.push([cell('Finance Manager'), ...er(2), cell('Director / Head of Department'), ...er(tc-4)]);

        return rows;
      }

      // ── Build expenditure log sheet ───────────────────────────────
      function buildExpSheet(filteredExps, budgetsMap, lineItemsMap, budgetDonorsMap) {
        let headers = [
          cell('Exp ID', FMT.BOLD, FMT.FILL_HEADER),
          cell('Budget', FMT.BOLD, FMT.FILL_HEADER),
          cell('Line Item', FMT.BOLD, FMT.FILL_HEADER),
          cell('Donor', FMT.BOLD, FMT.FILL_HEADER),
          cell('Quarter', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER),
          cell('Amount MMK', FMT.BOLD, FMT.RIGHT, FMT.FILL_HEADER),
          cell('Submitted By', FMT.BOLD, FMT.FILL_HEADER),
          cell('Date', FMT.BOLD, FMT.FILL_HEADER),
          cell('Approved By', FMT.BOLD, FMT.FILL_HEADER),
          cell('Approved At', FMT.BOLD, FMT.FILL_HEADER),
          cell('Status', FMT.BOLD, FMT.CENTER, FMT.FILL_HEADER),
        ];
        let dataRows = filteredExps.map((e, idx) => {
          let isApproved = e['Status'] === 'approved';
          let rowFill = idx % 2 === 0 ? {} : { backgroundColor: { red: 0.969, green: 0.973, blue: 0.984 } };
          return [
            cell(e['Exp ID'] || '', rowFill),
            cell(budgetsMap[e['Budget ID']]?.['Name'] || e['Budget ID'] || '', rowFill),
            cell(lineItemsMap[e['Line Item ID']]?.['Description'] || '', rowFill, FMT.WRAP),
            cell(budgetDonorsMap[e['BD ID']]?.['Donor Name'] || '', rowFill),
            cell(e['Quarter'] || '', FMT.CENTER, rowFill),
            numCell(Math.round(parseFloat(e['Amount MMK']||0)), rowFill),
            cell(e['Submitted By'] || '', rowFill),
            cell((e['Submitted At'] || '').slice(0,10), rowFill),
            cell(e['Approved By'] || '', rowFill),
            cell((e['Approved At'] || '').slice(0,10), rowFill),
            cell(e['Status'] || '', FMT.CENTER,
              isApproved
                ? { backgroundColor: { red: 0.851, green: 0.918, blue: 0.827 } }
                : e['Status'] === 'pending'
                  ? { backgroundColor: { red: 1, green: 0.949, blue: 0.800 } }
                  : { backgroundColor: { red: 0.988, green: 0.878, blue: 0.878 } }),
          ];
        });
        return [headers, ...dataRows];
      }

      // ── Build summary sheet ───────────────────────────────────────
      function buildSummarySheet(title, rows2D) {
        return rows2D.map((row, ri) => {
          if (!row || !row.length) return emptyRow(12);
          return row.map((v, ci) => {
            if (typeof v === 'number') return numCell(v);
            let s = String(v || '');
            // Section heading detection
            if (ci === 0 && s.match(/^[A-Z\s]{4,}$/) && ri > 1) return cell(s, FMT.BOLD, FMT.FILL_SUBHDR);
            if (ci === 0 && s.startsWith('Total') || s === 'TOTAL') return cell(s, FMT.BOLD, FMT.FILL_TOTAL);
            return cell(s);
          }).concat(Array(Math.max(0, 12 - row.length)).fill(cell('')));
        });
      }

      // ── Column width requests ─────────────────────────────────────
      function colWidthRequests(sheetId, widths) {
        return widths.map((px, i) => ({
          updateDimensionProperties: {
            range: { sheetId, dimension: 'COLUMNS', startIndex: i, endIndex: i+1 },
            properties: { pixelSize: px },
            fields: 'pixelSize',
          }
        }));
      }

      // ── Freeze row/col request ────────────────────────────────────
      function freezeRequest(sheetId, rows=1, cols=1) {
        return {
          updateSheetProperties: {
            properties: { sheetId, gridProperties: { frozenRowCount: rows, frozenColumnCount: cols } },
            fields: 'gridProperties.frozenRowCount,gridProperties.frozenColumnCount',
          }
        };
      }

      // ── Main createReportSheet ────────────────────────────────────
      async function createReportSheet(title, sheets) {
        // sheets: [{ title, rows: [[cellObj,...]] , colWidths: [px,...], freeze: {rows,cols} }]

        let spreadsheetBody = {
          properties: { title, defaultFormat: { textFormat: { fontFamily: 'Arial', fontSize: 9 } } },
          sheets: sheets.map((s, i) => ({
            properties: { sheetId: i, title: s.title, index: i,
              tabColor: i === 0
                ? { red: 0.129, green: 0.478, blue: 0.784 }
                : i === 1
                  ? { red: 0.204, green: 0.659, blue: 0.325 }
                  : { red: 0.984, green: 0.631, blue: 0.129 },
            },
            data: [{ startRow: 0, startColumn: 0, rowData: s.rows.map(r => ({ values: r })) }],
          })),
        };

        let createRes = await fetch('https://sheets.googleapis.com/v4/spreadsheets', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(spreadsheetBody),
        });
        if (!createRes.ok) {
          let e = await createRes.json().catch(() => ({}));
          throw new Error('Sheet create failed: ' + (e.error?.message || createRes.status));
        }
        let sheet = await createRes.json();
        let spreadsheetId = sheet.spreadsheetId;

        // Apply column widths + freeze panes via batchUpdate
        let batchRequests = [];
        sheets.forEach((s, i) => {
          if (s.colWidths) batchRequests.push(...colWidthRequests(i, s.colWidths));
          if (s.freeze)    batchRequests.push(freezeRequest(i, s.freeze.rows || 0, s.freeze.cols || 0));
        });

        if (batchRequests.length) {
          await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ requests: batchRequests }),
          });
        }

        // Move to Finance Reports folder
        await fetch(
          `https://www.googleapis.com/drive/v3/files/${spreadsheetId}?addParents=${env.FINANCE_REPORTS_FOLDER_ID}&removeParents=root&fields=id,parents`,
          { method: 'PATCH', headers: { Authorization: `Bearer ${token}` } }
        );

        return { spreadsheetId, spreadsheetUrl: `https://docs.google.com/spreadsheets/d/${spreadsheetId}/edit`, title };
      }

      // ══════════════════════════════════════════
      //  REPORT TYPE: budget — one budget full detail
      // ══════════════════════════════════════════
      if (reportType === 'budget') {
        if (!budgetId) return new Response(JSON.stringify({ error: 'Missing budgetId' }), { status: 400, headers });
        let budget = budgets.find(b => b['Budget ID'] === budgetId);
        if (!budget) return new Response(JSON.stringify({ error: 'Budget not found' }), { status: 404, headers });

        // Diocese staff can only access their own diocese
        if (!IS_MGR && u.diocese && budget['Diocese'] && budget['Diocese'] !== u.diocese)
          return new Response(JSON.stringify({ error: 'Access denied to this diocese' }), { status: 403, headers });

        let bds  = budgetDonors.filter(bd => bd['Budget ID'] === budgetId);
        let summ = budgetSummary(budgetId);
        let title = `${budget['Name']} — Report ${dateStr}`;

        // Sheet 1: Summary
        let summaryData = [
          ['Budget Report', budget['Name']],
          ['Programme', budget['Programme ID'] || ''],
          ['Diocese', budget['Diocese'] || 'Province-wide'],
          ['Fiscal Year', budget['Fiscal Year'] || ''],
          ['Period', `${budget['Period Start'] || ''} – ${budget['Period End'] || ''}`],
          ['Generated', dateStr],
          [],
          ['FINANCIAL SUMMARY', ''],
          ['Total Allocated (MMK)', summ.allocated],
          ['Total Spent — Approved (MMK)', summ.approved],
          ['Total Pending (MMK)', summ.pending],
          ['Balance (MMK)', summ.balance],
          ['Utilisation', pct(summ.approved, summ.allocated)],
          [],
          ['DONOR BREAKDOWN', '', 'Allocated MMK', 'Spent MMK', 'Balance MMK', '%'],
          ...bds.map(bd => {
            let bdExps = expenditures.filter(e => e['BD ID'] === bd['BD ID'] && e['Status'] === 'approved');
            let spent  = bdExps.reduce((s, e) => s + n(e['Amount MMK']), 0);
            let alloc  = n(bd['Allocated MMK']);
            return ['', bd['Donor Name'] || '', alloc, spent, alloc - spent, pct(spent, alloc)];
          }),
          [],
          ['QUARTERLY BREAKDOWN', '', 'Q1', 'Q2', 'Q3', 'Q4', 'Total'],
          ['', 'Approved spend', ...quarters.map(q => summ.qTotals[q]), summ.approved],
        ];

        // Sheet 2: Line items
        let liHeaders = ['Line Item', 'Unit Cost MMK', 'Units', 'Budgeted MMK', 'Q1 Actual', 'Q2 Actual', 'Q3 Actual', 'Q4 Actual', 'Total Spent', 'Balance', '%'];
        let liData = [liHeaders, ...buildDetailRows(budgetId)];

        // Sheet 3: Expenditure log
        let filteredExps = expenditures.filter(e => e['Budget ID'] === budgetId);
        let expData = buildExpLog(filteredExps, budgetsMap, lineItemsMap, budgetDonorsMap);

        let lis = lineItems.filter(li => li['Budget ID'] === budgetId && !String(li['Description'] || '').startsWith('[DELETED]'));
        let abmRows = buildABMSheet(budget, bds, lis, filteredExps, donorsMap);
        let expRows = buildExpSheet(filteredExps, budgetsMap, lineItemsMap, budgetDonorsMap);
        let summRows = buildSummarySheet(title, summaryData);

        let ABM_COL_WIDTHS = [340, 90, 70, 100, 100, 100, 80, 80, 80, 80, 80, 80, 80, 80, 100, 100, 60];
        let EXP_COL_WIDTHS = [100, 200, 220, 120, 60, 100, 100, 90, 100, 90, 80];
        let SUM_COL_WIDTHS = [200, 140, 100, 100, 100, 100, 80];

        let result = await createReportSheet(title, [
          { title: 'Budget Detail',    rows: abmRows,  colWidths: ABM_COL_WIDTHS, freeze: { rows: 8, cols: 1 } },
          { title: 'Summary',         rows: summRows, colWidths: SUM_COL_WIDTHS },
          { title: 'Expenditure Log', rows: expRows,  colWidths: EXP_COL_WIDTHS, freeze: { rows: 1, cols: 0 } },
        ]);
        return new Response(JSON.stringify({ ok: true, ...result }), { status: 200, headers });
      }

      // ══════════════════════════════════════════
      //  REPORT TYPE: donor — all budgets for one donor
      // ══════════════════════════════════════════
      if (reportType === 'donor') {
        if (!donorId) return new Response(JSON.stringify({ error: 'Missing donorId' }), { status: 400, headers });
        let donor = donors.find(d => d['Donor ID'] === donorId);
        if (!donor) return new Response(JSON.stringify({ error: 'Donor not found' }), { status: 404, headers });

        let donorBDs    = budgetDonors.filter(bd => bd['Donor ID'] === donorId);
        let donorBudgetIds = [...new Set(donorBDs.map(bd => bd['Budget ID']))];
        let donorBudgets   = budgets.filter(b => donorBudgetIds.includes(b['Budget ID']));
        let title = `${donor['Name']} — Donor Report ${dateStr}`;

        // Sheet 1: Summary across all budgets for this donor
        let totalAlloc   = donorBDs.reduce((s, bd) => s + n(bd['Allocated MMK']), 0);
        let donorExps    = expenditures.filter(e => donorBDs.some(bd => bd['BD ID'] === e['BD ID']) && e['Status'] === 'approved');
        let totalSpent   = donorExps.reduce((s, e) => s + n(e['Amount MMK']), 0);

        let summaryData = [
          ['Donor Report', donor['Name']],
          ['Report Format', donor['Report Format'] || ''],
          ['Generated', dateStr],
          [],
          ['SUMMARY ACROSS ALL BUDGETS'],
          ['Total Allocated (MMK)', totalAlloc],
          ['Total Spent — Approved (MMK)', totalSpent],
          ['Balance (MMK)', totalAlloc - totalSpent],
          ['Utilisation', pct(totalSpent, totalAlloc)],
          [],
          ['BUDGET BREAKDOWN', '', 'Programme', 'Diocese', 'Allocated MMK', 'Q1', 'Q2', 'Q3', 'Q4', 'Total Spent', 'Balance', '%'],
          ...donorBudgets.map(b => {
            let bd   = donorBDs.find(bd => bd['Budget ID'] === b['Budget ID']);
            let alloc = n(bd?.['Allocated MMK'] || 0);
            let bExps = expenditures.filter(e => e['BD ID'] === bd?.['BD ID'] && e['Status'] === 'approved');
            let spent = bExps.reduce((s, e) => s + n(e['Amount MMK']), 0);
            let qAmts = quarters.map(q => bExps.filter(e => e['Quarter'] === q).reduce((s, e) => s + n(e['Amount MMK']), 0));
            return [b['Name'], b['Fiscal Year'] || '', b['Programme ID'] || '', b['Diocese'] || '', alloc, ...qAmts, spent, alloc - spent, pct(spent, alloc)];
          }),
        ];

        // Sheet 2: Line items across all budgets for this donor
        let liHeaders = ['Budget', 'Section', 'Line Item', 'Budgeted MMK (this donor)', 'Q1', 'Q2', 'Q3', 'Q4', 'Total Spent', 'Balance', '%'];
        let liRows = [liHeaders];
        for (let b of donorBudgets) {
          let bd  = donorBDs.find(bd => bd['Budget ID'] === b['Budget ID']);
          if (!bd) continue;
          let lis = lineItems.filter(li => li['Budget ID'] === b['Budget ID'] && !String(li['Description'] || '').startsWith('[DELETED]'));
          for (let li of lis) {
            let splits = {};
            try { splits = JSON.parse(li['Donor Splits JSON'] || '{}'); } catch (_) {}
            let donorAmt = splits[bd['BD ID']] || 0;
            if (!donorAmt) continue;
            let liExps = expenditures.filter(e => e['Line Item ID'] === li['LI ID'] && e['BD ID'] === bd['BD ID'] && e['Status'] === 'approved');
            let qAmts  = quarters.map(q => liExps.filter(e => e['Quarter'] === q).reduce((s, e) => s + n(e['Amount MMK']), 0));
            let spent  = qAmts.reduce((s, v) => s + v, 0);
            liRows.push([b['Name'], `${li['Section No']}. ${li['Section Name'] || ''}`, li['Description'], donorAmt, ...qAmts, spent, donorAmt - spent, pct(spent, donorAmt)]);
          }
        }

        // Sheet 3: Expenditure log for this donor
        let donorExpAll = expenditures.filter(e => donorBDs.some(bd => bd['BD ID'] === e['BD ID']));
        let expData = buildExpLog(donorExpAll, budgetsMap, lineItemsMap, budgetDonorsMap);

        let summRows  = buildSummarySheet(title, summaryData);
        let liCells  = [
          [cell('Budget',FMT.BOLD,FMT.FILL_HEADER), cell('Section',FMT.BOLD,FMT.FILL_HEADER), cell('Line Item',FMT.BOLD,FMT.FILL_HEADER,FMT.WRAP), cell('Budgeted MMK',FMT.BOLD,FMT.RIGHT,FMT.FILL_HEADER), cell('Q1',FMT.BOLD,FMT.CENTER,FMT.FILL_HEADER), cell('Q2',FMT.BOLD,FMT.CENTER,FMT.FILL_HEADER), cell('Q3',FMT.BOLD,FMT.CENTER,FMT.FILL_HEADER), cell('Q4',FMT.BOLD,FMT.CENTER,FMT.FILL_HEADER), cell('Total Spent',FMT.BOLD,FMT.RIGHT,FMT.FILL_HEADER), cell('Balance',FMT.BOLD,FMT.RIGHT,FMT.FILL_HEADER), cell('%',FMT.BOLD,FMT.CENTER,FMT.FILL_HEADER)],
          ...liRows.slice(1).map((r,ri) => r.map((v,ci) => typeof v==='number' ? numCell(v) : cell(String(v||''), ri%2===1 ? { backgroundColor:{red:0.969,green:0.973,blue:0.984} } : {}))
          ),
        ];
        let donorExpAll2 = expenditures.filter(e => donorBDs.some(bd => bd['BD ID'] === e['BD ID']));
        let expRows  = buildExpSheet(donorExpAll2, budgetsMap, lineItemsMap, budgetDonorsMap);

        let result = await createReportSheet(title, [
          { title: 'Summary',         rows: summRows, colWidths: [200,120,120,120,80,80,80,80,100,100,60] },
          { title: 'Line Items',      rows: liCells,  colWidths: [180,80,220,100,80,80,80,80,100,100,60], freeze: { rows:1, cols:1 } },
          { title: 'Expenditure Log', rows: expRows,  colWidths: [100,200,220,120,60,100,100,90,100,90,80], freeze: { rows:1, cols:0 } },
        ]);
        return new Response(JSON.stringify({ ok: true, ...result }), { status: 200, headers });
      }

      // ══════════════════════════════════════════
      //  REPORT TYPE: consolidated — province-wide
      // ══════════════════════════════════════════
      if (reportType === 'consolidated') {
        let title = `Province Consolidated Finance Report — ${dateStr}`;
        let totalAlloc  = budgetDonors.reduce((s, bd) => s + n(bd['Allocated MMK']), 0);
        let totalApproved = expenditures.filter(e => e['Status'] === 'approved').reduce((s, e) => s + n(e['Amount MMK']), 0);
        let totalPending  = expenditures.filter(e => e['Status'] === 'pending').reduce((s, e) => s + n(e['Amount MMK']), 0);

        // Sheet 1: Province summary
        let summaryData = [
          ['Province Consolidated Finance Report'],
          ['Generated', dateStr],
          ['Total Budgets', budgets.length],
          [],
          ['PROVINCE TOTALS', ''],
          ['Total Allocated (MMK)', totalAlloc],
          ['Total Spent — Approved (MMK)', totalApproved],
          ['Total Pending Approval (MMK)', totalPending],
          ['Balance (MMK)', totalAlloc - totalApproved],
          ['Province-wide Utilisation', pct(totalApproved, totalAlloc)],
          [],
          ['BY DIOCESE', '', 'Budgets', 'Allocated MMK', 'Spent MMK', 'Balance MMK', '%'],
        ];
        let byDiocese = {};
        budgets.forEach(b => {
          let d = b['Diocese'] || 'Province-wide';
          if (!byDiocese[d]) byDiocese[d] = { count: 0, alloc: 0, spent: 0 };
          byDiocese[d].count++;
          budgetDonors.filter(bd => bd['Budget ID'] === b['Budget ID']).forEach(bd => { byDiocese[d].alloc += n(bd['Allocated MMK']); });
          expenditures.filter(e => e['Budget ID'] === b['Budget ID'] && e['Status'] === 'approved').forEach(e => { byDiocese[d].spent += n(e['Amount MMK']); });
        });
        Object.entries(byDiocese).forEach(([d, s]) => summaryData.push(['', d, s.count, s.alloc, s.spent, s.alloc - s.spent, pct(s.spent, s.alloc)]));

        summaryData.push([]);
        summaryData.push(['BY PROGRAMME', '', 'Budgets', 'Allocated MMK', 'Spent MMK', 'Balance MMK', '%']);
        let byProg = {};
        budgets.forEach(b => {
          let p = b['Programme ID'] || 'Unknown';
          if (!byProg[p]) byProg[p] = { count: 0, alloc: 0, spent: 0 };
          byProg[p].count++;
          budgetDonors.filter(bd => bd['Budget ID'] === b['Budget ID']).forEach(bd => { byProg[p].alloc += n(bd['Allocated MMK']); });
          expenditures.filter(e => e['Budget ID'] === b['Budget ID'] && e['Status'] === 'approved').forEach(e => { byProg[p].spent += n(e['Amount MMK']); });
        });
        Object.entries(byProg).forEach(([p, s]) => summaryData.push(['', p, s.count, s.alloc, s.spent, s.alloc - s.spent, pct(s.spent, s.alloc)]));

        summaryData.push([]);
        summaryData.push(['BY DONOR', '', 'Budgets linked', 'Allocated MMK', 'Spent MMK', 'Balance MMK', '%']);
        let byDonor = {};
        budgetDonors.forEach(bd => {
          let d = bd['Donor Name'] || bd['Donor ID'];
          if (!byDonor[d]) byDonor[d] = { count: 0, alloc: 0, spent: 0 };
          byDonor[d].count++;
          byDonor[d].alloc += n(bd['Allocated MMK']);
          expenditures.filter(e => e['BD ID'] === bd['BD ID'] && e['Status'] === 'approved').forEach(e => { byDonor[d].spent += n(e['Amount MMK']); });
        });
        Object.entries(byDonor).forEach(([d, s]) => summaryData.push(['', d, s.count, s.alloc, s.spent, s.alloc - s.spent, pct(s.spent, s.alloc)]));

        // Sheet 2: All budgets list
        let allBudgetsData = [
          ['Budget ID', 'Name', 'Programme', 'Diocese', 'Fiscal Year', 'Allocated MMK', 'Spent MMK', 'Pending MMK', 'Balance MMK', '%', 'Status'],
          ...budgets.map(b => {
            let s = budgetSummary(b['Budget ID']);
            return [b['Budget ID'], b['Name'], b['Programme ID'] || '', b['Diocese'] || '', b['Fiscal Year'] || '', s.allocated, s.approved, s.pending, s.balance, pct(s.approved, s.allocated), b['Status'] || ''];
          })
        ];

        // Sheet 3: Full expenditure log
        let expData = buildExpLog(expenditures, budgetsMap, lineItemsMap, budgetDonorsMap);

        let summRows   = buildSummarySheet(title, summaryData);
        let budgCells  = [
          ['Budget ID','Name','Programme','Diocese','Fiscal Year','Allocated MMK','Spent MMK','Pending MMK','Balance MMK','%','Status']
            .map(h => cell(h, FMT.BOLD, FMT.FILL_HEADER)),
          ...allBudgetsData.slice(1).map((r,ri) => r.map((v,ci) => {
            let alt = ri%2===1 ? { backgroundColor:{red:0.969,green:0.973,blue:0.984} } : {};
            return typeof v==='number' ? numCell(v, alt) : cell(String(v||''), alt);
          })),
        ];
        let expRows2 = buildExpSheet(expenditures, budgetsMap, lineItemsMap, budgetDonorsMap);

        let result = await createReportSheet(title, [
          { title: 'Province Summary', rows: summRows,  colWidths: [220,140,120,120,120,120,80] },
          { title: 'All Budgets',      rows: budgCells, colWidths: [100,220,120,100,120,110,100,100,100,60,70], freeze: { rows:1, cols:0 } },
          { title: 'Expenditure Log',  rows: expRows2,  colWidths: [100,200,220,120,60,100,100,90,100,90,80], freeze: { rows:1, cols:0 } },
        ]);
        return new Response(JSON.stringify({ ok: true, ...result }), { status: 200, headers });
      }

      // ══════════════════════════════════════════
      //  REPORT TYPE: diocese — one diocese
      // ══════════════════════════════════════════
      if (reportType === 'diocese') {
        let targetDiocese = IS_MGR ? (diocese || u.diocese) : u.diocese;
        if (!targetDiocese) return new Response(JSON.stringify({ error: 'Diocese not specified' }), { status: 400, headers });

        let dioceseBudgets = budgets.filter(b => b['Diocese'] === targetDiocese);
        let dioceseBudgetIds = new Set(dioceseBudgets.map(b => b['Budget ID']));
        let dioceseBDs  = budgetDonors.filter(bd => dioceseBudgetIds.has(bd['Budget ID']));
        let dioceseExps = expenditures.filter(e => dioceseBudgetIds.has(e['Budget ID']));
        let title = `${targetDiocese} Diocese — Finance Report ${dateStr}`;

        let totalAlloc  = dioceseBDs.reduce((s, bd) => s + n(bd['Allocated MMK']), 0);
        let totalSpent  = dioceseExps.filter(e => e['Status'] === 'approved').reduce((s, e) => s + n(e['Amount MMK']), 0);
        let totalPending= dioceseExps.filter(e => e['Status'] === 'pending').reduce((s, e) => s + n(e['Amount MMK']), 0);

        let summaryData = [
          ['Diocese Finance Report', targetDiocese],
          ['Generated', dateStr],
          [],
          ['TOTALS'],
          ['Total Allocated (MMK)', totalAlloc],
          ['Total Spent (MMK)', totalSpent],
          ['Pending Approval (MMK)', totalPending],
          ['Balance (MMK)', totalAlloc - totalSpent],
          ['Utilisation', pct(totalSpent, totalAlloc)],
          [],
          ['BUDGETS', '', 'Programme', 'Fiscal Year', 'Allocated MMK', 'Spent MMK', 'Balance MMK', '%'],
          ...dioceseBudgets.map(b => {
            let s = budgetSummary(b['Budget ID']);
            return [b['Name'], '', b['Programme ID'] || '', b['Fiscal Year'] || '', s.allocated, s.approved, s.balance, pct(s.approved, s.allocated)];
          }),
        ];

        // Sheet 2: all line items across all diocese budgets
        let liHeaders = ['Budget', 'Section', 'Line Item', 'Budgeted MMK', 'Q1', 'Q2', 'Q3', 'Q4', 'Total Spent', 'Balance', '%'];
        let liRows = [liHeaders];
        for (let b of dioceseBudgets) {
          let lis = lineItems.filter(li => li['Budget ID'] === b['Budget ID'] && !String(li['Description'] || '').startsWith('[DELETED]'));
          for (let li of lis) {
            let liExps = dioceseExps.filter(e => e['Line Item ID'] === li['LI ID'] && e['Status'] === 'approved');
            let qAmts  = quarters.map(q => liExps.filter(e => e['Quarter'] === q).reduce((s, e) => s + n(e['Amount MMK']), 0));
            let spent  = qAmts.reduce((s, v) => s + v, 0);
            let bud    = n(li['Total MMK']);
            liRows.push([b['Name'], `${li['Section No']}.`, li['Description'], bud, ...qAmts, spent, bud - spent, pct(spent, bud)]);
          }
        }

        // Sheet 3: expenditure log for diocese (all statuses for managers, own submissions for staff)
        let filteredExps = IS_MGR
          ? dioceseExps
          : dioceseExps.filter(e => e['Submitted By'] === u.name);
        let expData = buildExpLog(filteredExps, budgetsMap, lineItemsMap, budgetDonorsMap);

        let summRows3  = buildSummarySheet(title, summaryData);
        let liCells3   = [
          ['Budget','Section','Line Item','Budgeted MMK','Q1','Q2','Q3','Q4','Total Spent','Balance','%']
            .map(h => cell(h, FMT.BOLD, FMT.FILL_HEADER)),
          ...liRows.slice(1).map((r,ri) => r.map((v,ci) => {
            let alt = ri%2===1 ? { backgroundColor:{red:0.969,green:0.973,blue:0.984} } : {};
            return typeof v==='number' ? numCell(v, alt) : cell(String(v||''), alt);
          })),
        ];
        let expRows3 = buildExpSheet(filteredExps, budgetsMap, lineItemsMap, budgetDonorsMap);

        let result = await createReportSheet(title, [
          { title: 'Summary',         rows: summRows3, colWidths: [220,140,120,120,120,120,80] },
          { title: 'Line Items',      rows: liCells3,  colWidths: [180,70,220,100,80,80,80,80,100,100,60], freeze: { rows:1, cols:1 } },
          { title: 'Expenditure Log', rows: expRows3,  colWidths: [100,200,220,120,60,100,100,90,100,90,80], freeze: { rows:1, cols:0 } },
        ]);
        return new Response(JSON.stringify({ ok: true, ...result }), { status: 200, headers });
      }

      return new Response(JSON.stringify({ error: 'Unknown reportType. Use: budget | donor | consolidated | diocese' }), { status: 400, headers });
    }


    // ════════════════════════════════════════════════════════════════
    //  ANNOUNCEMENT SYSTEM
    //  get_staff_list       — returns all users with email/role/diocese
    //  get_announcement_perms  — returns which roles can send
    //  save_announcement_perms — admin saves role permissions
    //  send_announcement    — send email + log to Drive
    // ════════════════════════════════════════════════════════════════

    // ── get_staff_list ───────────────────────────────────────────────
    if (action === 'get_staff_list') {
      const u = validateUser(body.username, body.password);
      if (!u) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      // Any authenticated user can fetch the staff list for recipient selection
      // Sending permission is checked separately in send_announcement
      const users = getUsers();
      const staff = Object.entries(users).map(([username, usr]) => ({
        username,
        name:     usr.name     || username,
        role:     usr.role     || 'staff',
        diocese:  usr.diocese  || null,
        email:    usr.email    || null,
        hasEmail: !!(usr.email && usr.email.trim()),
      })).sort((a, b) => (a.name||'').localeCompare(b.name||''));

      return new Response(JSON.stringify({ ok: true, staff }), { status: 200, headers });
    }

    // ── get_announcement_perms ───────────────────────────────────────
    if (action === 'get_announcement_perms') {
      const u = validateUser(body.username, body.password);
      if (!u) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const perms = JSON.parse(env.ANNOUNCEMENT_PERMS || '{}');
      return new Response(JSON.stringify({ ok: true, permissions: perms }), { status: 200, headers });
    }

    // ── save_announcement_perms ──────────────────────────────────────
    if (action === 'save_announcement_perms') {
      const u = validateUser(body.username, body.password);
      if (!u || u.role !== 'admin')
        return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers });

      const { permissions } = body;
      if (!permissions)
        return new Response(JSON.stringify({ error: 'Missing permissions object' }), { status: 400, headers });

      // Accept per-user structure: { users: { username: bool } }
      // Validate: only known usernames allowed
      const users = getUsers();
      const clean = { users: {} };
      if (permissions.users && typeof permissions.users === 'object') {
        Object.entries(permissions.users).forEach(([username, val]) => {
          if (users[username] && typeof val === 'boolean') clean.users[username] = val;
        });
      }

      // Save to Cloudflare secret via API
      const cfToken = env.CF_API_TOKEN;
      const cfAccount = env.CF_ACCOUNT_ID;
      const cfScript  = env.CF_WORKER_SCRIPT_NAME;

      if (!cfToken || !cfAccount || !cfScript) {
        // Return the value for manual paste if CF API not configured
        return new Response(JSON.stringify({
          ok: false,
          manualPaste: true,
          value: JSON.stringify(clean),
          note: 'CF API not configured. Add this as ANNOUNCEMENT_PERMS secret in Cloudflare manually.',
        }), { status: 200, headers });
      }

      const cfRes = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${cfAccount}/workers/scripts/${cfScript}/secrets`,
        {
          method: 'PUT',
          headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'ANNOUNCEMENT_PERMS', text: JSON.stringify(clean), type: 'secret_text' }),
        }
      );
      if (!cfRes.ok) {
        const e = await cfRes.json().catch(() => ({}));
        return new Response(JSON.stringify({ ok: false, error: 'CF API error: ' + (e.errors?.[0]?.message || cfRes.status) }), { status: 200, headers });
      }
      return new Response(JSON.stringify({ ok: true, permissions: clean }), { status: 200, headers });
    }

    // ── send_announcement ────────────────────────────────────────────
    if (action === 'send_announcement') {
      const u = validateUser(body.username, body.password);
      if (!u) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const annPerms  = JSON.parse(env.ANNOUNCEMENT_PERMS || '{}');
      const userPerms = annPerms.users || {};
      const canSend   = u.role === 'admin' || userPerms[body.username] === true;
      if (!canSend)
        return new Response(JSON.stringify({ error: 'No announcement permission' }), { status: 403, headers });

      const { subject, body: msgBody, recipients, senderName } = body;
      if (!subject || !msgBody)
        return new Response(JSON.stringify({ error: 'Subject and body are required' }), { status: 400, headers });
      if (!recipients || !recipients.length)
        return new Response(JSON.stringify({ error: 'No recipients specified' }), { status: 400, headers });

      const users = getUsers();
      const now   = new Date();
      const dateStr = now.toISOString();

      // Resolve email addresses
      const resolved = recipients.map(username => {
        const usr = users[username];
        return usr?.email ? { username, name: usr.name||username, email: usr.email } : null;
      }).filter(Boolean);

      if (!resolved.length)
        return new Response(JSON.stringify({ error: 'None of the selected recipients have emails set' }), { status: 400, headers });

      // Build HTML email
      const gmailToken = env.GMAIL_REFRESH_TOKEN || env.DRIVE_REFRESH_TOKEN;
      if (!env.GMAIL_CLIENT_ID || !env.GMAIL_CLIENT_SECRET || !gmailToken)
        return new Response(JSON.stringify({ error: 'Gmail OAuth secrets not configured' }), { status: 500, headers });

      const token = await getAccessToken(env.GMAIL_CLIENT_ID, env.GMAIL_CLIENT_SECRET, gmailToken);

      const htmlBody = `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1e293b;">
        <div style="background:#0f1e38;padding:20px 28px;border-radius:10px 10px 0 0;">
          <span style="color:#fff;font-size:16px;font-weight:700;">PDD Dashboard</span>
          <span style="color:#94a3b8;font-size:12px;margin-left:10px;">Provincial Development Department</span>
        </div>
        <div style="background:#fff;border:1px solid #e5e7eb;border-top:none;padding:28px;border-radius:0 0 10px 10px;">
          <h2 style="margin:0 0 8px;font-size:18px;color:#0f1e38;">${subject}</h2>
          <p style="color:#64748b;font-size:12px;margin:0 0 20px;">From: ${senderName||u.name||'PDD Dashboard'} · ${now.toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'})}</p>
          <div style="font-size:14px;color:#374151;line-height:1.8;white-space:pre-wrap;">${msgBody.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
          <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">
          <p style="font-size:11px;color:#94a3b8;margin:0;">This is an official announcement from the PDD Dashboard. Do not reply to this email.</p>
          <a href="${env.DASHBOARD_URL||'https://www.gamalieltun.com/PDP-Dashboard/'}" style="font-size:11px;color:#2563eb;">Open Dashboard</a>
        </div>
      </body></html>`;

      // Send to each recipient individually — collect results
      const results = await Promise.allSettled(
        resolved.map(r => sendEmail(token, r.email, subject, htmlBody))
      );

      let sent = 0, failed = 0;
      results.forEach((r, i) => {
        if (r.status === 'fulfilled') { sent++; console.log(`[Announce] sent to ${resolved[i].email}`); }
        else { failed++; console.error(`[Announce] failed ${resolved[i].email}:`, r.reason?.message); }
      });

      // Log to Google Drive
      try {
        const driveToken = await getDriveToken(env);
        const logFolderId = env.ANNOUNCEMENTS_FOLDER_ID || env.DRIVE_FOLDER_ID;
        if (logFolderId) {
          const logData = {
            subject,
            body: msgBody,
            sentBy:         u.name || u._key || body.username,
            sentAt:         dateStr,
            recipientCount: resolved.length,
            sentCount:      sent,
            failedCount:    failed,
            recipients:     resolved.map(r => r.name),
            recipientEmails:resolved.map(r => r.email),
          };
          const filename = `Announcement_${now.toISOString().slice(0,10)}_${Date.now().toString(36).toUpperCase()}.json`;
          await driveWriteFile(driveToken, logFolderId, filename, logData);
        }
      } catch(logErr) {
        console.error('[Announce] Drive log failed:', logErr.message);
      }

      return new Response(JSON.stringify({
        ok: true, sent, failed,
        total: resolved.length,
        skipped: recipients.length - resolved.length,
      }), { status: 200, headers });
    }

    // ── get_announcements ────────────────────────────────────────────
    if (action === 'get_announcements') {
      const u = validateUser(body.username, body.password);
      if (!u) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

      const annPerms  = JSON.parse(env.ANNOUNCEMENT_PERMS || '{}');
      const userPerms = annPerms.users || {};
      const canSend   = u.role === 'admin' || userPerms[body.username] === true;
      if (!canSend)
        return new Response(JSON.stringify({ error: 'No announcement permission' }), { status: 403, headers });

      try {
        const driveToken = await getDriveToken(env);
        const folderId   = env.ANNOUNCEMENTS_FOLDER_ID || env.DRIVE_FOLDER_ID;
        if (!folderId) return new Response(JSON.stringify({ ok: true, announcements: [] }), { status: 200, headers });

        // List JSON files in Drive folder that match announcement naming
        const q   = encodeURIComponent(`'${folderId}' in parents and name contains 'Announcement_' and mimeType='application/json' and trashed=false`);
        const res = await fetch(
          `https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name,modifiedTime)&orderBy=modifiedTime desc&pageSize=50`,
          { headers: { Authorization: `Bearer ${driveToken}` } }
        );
        const data = await res.json();
        const files = data.files || [];

        // Fetch content of each file
        const announcements = await Promise.all(files.map(async f => {
          try {
            const r = await fetch(
              `https://www.googleapis.com/drive/v3/files/${f.id}?alt=media`,
              { headers: { Authorization: `Bearer ${driveToken}` } }
            );
            return await r.json();
          } catch(_) { return null; }
        }));

        return new Response(JSON.stringify({
          ok: true,
          announcements: announcements.filter(Boolean),
        }), { status: 200, headers });
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