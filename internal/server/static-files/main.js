const nameEl = document.getElementById('name');
const len = document.getElementById('len');
const tokenEl = document.getElementById('token');
const msg = document.getElementById('msg');
const tokenList = document.getElementById('tokenList');
const expSelect = document.getElementById('expSelect');
const expOptions = document.getElementById('expOptions');
const expAmount = document.getElementById('expAmount');
const expUnit = document.getElementById('expUnit');
const expDate = document.getElementById('expDate');
const expPreview = document.getElementById('expPreview');
const copyBtn = document.getElementById('copy');

const lenNum = document.getElementById('lenNum');

len.oninput = () => {
  lenNum.value = len.value;
};

lenNum.oninput = () => {
  const v = Math.max(32, Math.min(128, +lenNum.value || 32));
  len.value = v;
};

expSelect.onchange = () => {
  expOptions.classList.toggle('visible', expSelect.value === 'custom');
  if (expSelect.value === 'custom') updateExpPreview();
};

document.getElementById('expModeAbsolute').onchange = () => {
  if (!expDate.value) expDate.value = new Date(Date.now() + 36e5).toISOString().slice(0, 16);
  updateExpPreview();
};

expOptions.addEventListener('input', updateExpPreview);
expOptions.addEventListener('change', updateExpPreview);

const unitMs = {
  minutes: 60e3,
  hours: 36e5,
  days: 864e5,
  weeks: 6048e5
};

const presetMs = {
  '10m': 600e3,
  '1h': 36e5,
  '24h': 864e5,
  '1w': 6048e5
};

function humanDuration(ms) {
  const min = Math.floor(ms / 6e4);
  const hr = Math.floor(min / 60);
  const day = Math.floor(hr / 24);
  if (day >= 1) return day + 'd ' + (hr % 24) + 'h';
  if (hr >= 1) return hr + 'h ' + (min % 60) + 'm';
  return min + 'm';
}

function getExpiration() {
  const val = expSelect.value;
  if (!val) return null;
  if (val === 'custom') {
    const mode = document.querySelector('input[name="expMode"]:checked').value;
    if (mode === 'relative') {
      const amount = +expAmount.value;
      if (!amount || amount < 1) return null;
      return new Date(Date.now() + amount * unitMs[expUnit.value]).toISOString();
    }
    const d = expDate.value;
    if (!d) return null;
    const date = new Date(d);
    return isNaN(date.getTime()) ? null : date.toISOString();
  }
  if (presetMs[val]) {
    return new Date(Date.now() + presetMs[val]).toISOString();
  }
  return null;
}

function updateExpPreview() {
  if (expSelect.value !== 'custom') return;
  const exp = getExpiration();
  if (!exp) {
    expPreview.textContent = '';
    return;
  }
  const d = new Date(exp);
  if (d <= new Date()) {
    expPreview.textContent = 'Expiry is in the past';
    expPreview.classList.add('error');
    return;
  }
  expPreview.classList.remove('error');
  expPreview.textContent = 'Expires in ' + humanDuration(d - Date.now()) + ' (' + d.toLocaleString() + ')';
}

function setMessage(text, type) {
  msg.textContent = text;
  msg.className = 'message';
  void msg.offsetWidth;
  msg.className = 'message ' + (type || '');
}

async function fetchTokens() {
  try {
    const res = await fetch('/tokens');
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    renderTokenList(data);
  } catch (e) {
    console.error('Failed to fetch tokens:', e);
  }
}

function formatExpiry(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  if (d <= new Date()) return { text: 'Expired', level: 'expired' };
  const diff = d - Date.now();
  const text = humanDuration(diff) + ' left';
  const level = diff < 36e5 ? 'critical' : diff < 864e5 ? 'warning' : 'ok';
  return { text: text, level: level };
}

function renderTokenList(tokens) {
  tokenList.innerHTML = '';
  for (const t of tokens) {
    const name = typeof t === 'string' ? t : t.name;
    const li = document.createElement('li');
    const nameSpan = document.createElement('span');
    nameSpan.className = 'token-name';
    nameSpan.textContent = name;
    nameSpan.title = name;
    li.appendChild(nameSpan);

    if (typeof t === 'object' && t.expires) {
      const info = formatExpiry(t.expires);
      if (info) {
        li.classList.add('exp-' + info.level);
        const expSpan = document.createElement('span');
        expSpan.className = 'token-exp ' + info.level;
        expSpan.textContent = info.text;
        li.appendChild(expSpan);
      }
    }

    const revokeBtn = document.createElement('button');
    revokeBtn.className = 'danger';
    revokeBtn.textContent = 'Revoke';
    li.appendChild(revokeBtn);
    tokenList.appendChild(li);
  }
}

let revokeTimer;
tokenList.addEventListener('click', (e) => {
  const btn = e.target.closest('.danger');
  if (!btn) return;
  const name = btn.closest('li').querySelector('.token-name').textContent;
  if (!btn.classList.contains('confirm')) {
    btn.classList.add('confirm');
    btn.textContent = 'Confirm?';
    revokeTimer = setTimeout(() => {
      btn.classList.remove('confirm');
      btn.textContent = 'Revoke';
    }, 3000);
    return;
  }
  clearTimeout(revokeTimer);
  doRevoke(name);
});

async function doRevoke(name) {
  try {
    const res = await fetch('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name })
    });
    if (res.ok) {
      setMessage('Token "' + name + '" revoked', 'success');
      fetchTokens();
    } else {
      setMessage(await res.text(), 'error');
    }
  } catch (e) {
    setMessage(e.message, 'error');
  }
}

document.getElementById('gen').onclick = () => {
  const n = +len.value;
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  const chars = 'abcdef0123456789';
  let t = '';
  for (let i = 0; i < n; i++) {
    t += chars[bytes[i] % chars.length];
  }
  tokenEl.value = t;
};

copyBtn.onclick = async () => {
  const token = tokenEl.value;
  if (!token) {
    setMessage('No token generated', 'error');
    return;
  }
  await navigator.clipboard.writeText(token);
  const orig = copyBtn.textContent;
  copyBtn.textContent = 'Copied!';
  setTimeout(() => { copyBtn.textContent = orig; }, 1500);
};

document.getElementById('register').onclick = async () => {
  const name = nameEl.value.trim();
  const token = tokenEl.value;

  if (!name) {
    setMessage('Please enter a token name', 'error');
    return;
  }
  if (!token) {
    setMessage('Please generate a token first', 'error');
    return;
  }

  const expires = getExpiration();
  if (expSelect.value && !expires) {
    setMessage('Invalid expiration value', 'error');
    return;
  }

  const body = { name: name, token: token };
  if (expires) {
    body.expires = expires;
  }

  try {
    const res = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (res.ok) {
      setMessage('Token "' + name + '" registered successfully', 'success');
      nameEl.value = '';
      tokenEl.value = '';
      expSelect.value = '';
      expOptions.classList.remove('visible');
      expPreview.textContent = '';
      fetchTokens();
    } else {
      setMessage(await res.text(), 'error');
    }
  } catch (e) {
    setMessage(e.message, 'error');
  }
};

document.getElementById('domain').textContent = location.hostname;
fetchTokens();
