// Reads the open email and sends it to TriGuard's email check (same server that serves this page).
const API = '/api/v1/email/analyze'
// The TriGuard app, where a risky email becomes a payment hold that needs a call-back and PIN to release.
const APP_URL = 'https://triguard-ai-frontend.onrender.com/app/check'
// The server's five levels, shown as High / Medium / Low. TriGuard never says "safe".
const LEVELS = { critical: 'high', high: 'high', medium: 'medium', low: 'low', safe: 'low' }
let lastEmail = null

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

// Opens the TriGuard app with this email ready to check. The text travels in the URL fragment (#), which browsers
// never send to the web server, so it doesn't end up in hosting logs.
function holdPayment() {
  const url = `${APP_URL}#from=outlook&text=${encodeURIComponent(lastEmail || '')}`
  if (Office.context.ui && Office.context.ui.openBrowserWindow) Office.context.ui.openBrowserWindow(url)
  else window.open(url, '_blank', 'noopener')
}

function show(r) {
  const level = LEVELS[r.risk_level] || 'medium'
  const codes = new Set((r.indicators || []).map(i => i.code))
  const parts = []
  if (level === 'high') {
    const stop = el('div', '', 'stop')
    stop.append(el('div', 'STOP', 'stop-title'),
      el('div', 'Don’t pay, reply, open links or join a meeting from this email until you’ve called the person on a number you already have.'))
    parts.push(stop)
  }
  if (codes.has('meeting_link')) {
    const call = el('div', '', 'callout')
    call.append(el('b', 'A video call is not proof.'),
      el('div', 'Deepfakes can copy a face and voice live on Teams or Zoom. Verify by phoning the person on a number you already have, not through a meeting from this email.'))
    parts.push(call)
  }
  const box = el('div', '', `verdict ${level}`)
  box.append(el('div', `${level} risk · ${r.risk_score}/100`, 'level'), el('div', r.headline, 'headline'), el('div', r.summary))
  parts.push(box)
  if (level !== 'low') {
    const hold = el('button', 'Put the payment on hold in TriGuard', 'hold')
    hold.type = 'button'
    hold.addEventListener('click', holdPayment)
    parts.push(hold, el('p', 'Opens a check in TriGuard. The payment can only be released after a confirmed call-back and your payment PIN.', 'muted'))
  }
  const reasons = [...new Set((r.indicators || []).map(i => i.title))]
  $('out').replaceChildren(...parts, ...list('Why', reasons), ...list('What to do', r.advice || []),
    el('p', r.disclaimer, 'muted'))
}

async function check() {
  const btn = $('check')
  btn.disabled = true
  btn.textContent = 'Checking…'
  $('out').replaceChildren()
  try {
    const item = Office.context.mailbox.item
    const raw = await rawEmail(item)
    const body = raw.split(/\r?\n\r?\n/).slice(1).join('\n\n')
    lastEmail = `${item.subject ? `Subject: ${item.subject}\n` : ''}${body}`.slice(0, 1500)
    const form = new FormData()
    form.append('raw', raw)
    form.append('language', 'auto')
    // Only the domain of the user's own address, to spot look-alike domains and outsiders posing as executives.
    const own = (Office.context.mailbox.userProfile.emailAddress || '').split('@')[1]
    if (own) form.append('recipient_domain', own)
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
