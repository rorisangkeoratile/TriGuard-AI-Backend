// Reads the open email and sends it to TriGuard's email check (same server that serves this page).
const API = '/api/v1/email/analyze'
// The server's five levels, shown as High / Medium / Low. TriGuard never says "safe".
const LEVELS = { critical: 'high', high: 'high', medium: 'medium', low: 'low', safe: 'low' }

const $ = id => document.getElementById(id)

function call(fn) {
  return new Promise((resolve, reject) =>
    fn(r => (r.status === Office.AsyncResultStatus.Succeeded ? resolve(r.value) : reject(r.error))))
}

// Raw email source: the real headers (with SPF/DKIM/DMARC results) when Outlook supports reading them,
// otherwise a minimal From/Subject header, then the text and attachment names.
async function rawEmail(item) {
  const body = await call(cb => item.body.getAsync(Office.CoercionType.Text, cb))
  let headers = ''
  if (Office.context.requirements.isSetSupported('Mailbox', '1.8')) {
    try { headers = await call(cb => item.getAllInternetHeadersAsync(cb)) } catch { /* fall back below */ }
  }
  if (!/^from:/im.test(headers)) {
    const from = item.from || {}
    headers = `From: ${from.displayName || ''} <${from.emailAddress || ''}>\r\nSubject: ${item.subject || ''}\r\n`
  }
  // Drop the original MIME headers: we send the plain text, not the original (possibly base64) parts.
  headers = headers.replace(/^content-(type|transfer-encoding):.*(\r?\n[ \t].*)*\r?\n?/gim, '').replace(/\s*$/, '\r\n')
  const files = (item.attachments || []).map(a => a.name).filter(Boolean)
  const extra = files.length ? `\n\nAttachments: ${files.join(', ')}` : ''
  return `${headers}Content-Type: text/plain; charset=utf-8\r\n\r\n${body}${extra}`
}

function el(tag, text, cls) {
  const e = document.createElement(tag)
  if (text) e.textContent = text
  if (cls) e.className = cls
  return e
}

function list(title, items) {
  if (!items.length) return []
  const ul = el('ul')
  items.forEach(t => ul.appendChild(el('li', t)))
  return [el('h2', title), ul]
}

function show(r) {
  const level = LEVELS[r.risk_level] || 'medium'
  const box = el('div', '', `verdict ${level}`)
  box.append(el('div', `${level} risk · ${r.risk_score}/100`, 'level'), el('div', r.headline, 'headline'), el('div', r.summary))
  const reasons = [...new Set((r.indicators || []).map(i => i.title))]
  $('out').replaceChildren(box, ...list('Why', reasons), ...list('What to do', r.advice || []),
    el('p', r.disclaimer, 'muted'))
}

async function check() {
  const btn = $('check')
  btn.disabled = true
  btn.textContent = 'Checking…'
  $('out').replaceChildren()
  try {
    const form = new FormData()
    form.append('raw', await rawEmail(Office.context.mailbox.item))
    form.append('language', 'auto')
    const res = await fetch(API, { method: 'POST', body: form })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `The TriGuard server answered ${res.status}.`)
    show(data)
  } catch (e) {
    $('out').replaceChildren(el('p', e.message || 'Can’t reach the TriGuard server.', 'err'))
  } finally {
    btn.disabled = false
    btn.textContent = 'Check again'
  }
}

Office.onReady(() => {
  $('check').disabled = false
  $('check').addEventListener('click', check)
})
