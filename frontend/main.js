const state = {
  confirmed: false,
  samples: [],
};

function $(sel) { return document.querySelector(sel); }
function el(tag, attrs = {}, text = "") {
  const e = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
  if (text) e.textContent = text;
  return e;
}

function setPage(pageId) {
  document.querySelectorAll('.page').forEach(sec => sec.classList.add('hidden'));
  document.getElementById(pageId).classList.remove('hidden');
}

function setButtonsEnabled(enabled) {
  document.getElementById('compileDropper').disabled = !enabled;
  const elfBtn = document.getElementById('compileElfMimic');
  if (elfBtn) elfBtn.disabled = !enabled;
  document.getElementById('downloadArtifacts').disabled = !enabled;
  document.getElementById('startSink').disabled = !enabled;
  document.getElementById('runNetClient').disabled = !enabled;
  document.querySelectorAll('.runBtn').forEach(btn => btn.disabled = !enabled);
  const dynIds = ['runPacker','runPersistence','runObfuscated'];
  dynIds.forEach(id => { const b = document.getElementById(id); if (b) b.disabled = !enabled; });
}

async function fetchSamples() {
  const res = await fetch('/api/samples');
  const data = await res.json();
  state.samples = data.samples || [];
  renderSamples();
  renderStaticOptions();
  renderArtifacts(data.artifacts, data.sandbox_output_contents);
}

function renderSamples() {
  const container = document.getElementById('samplesList');
  container.innerHTML = '';
  state.samples.forEach(s => {
    const row = el('div', { class: 'row' });
    row.appendChild(el('code', {}, `${s.name} (${s.type})${s.exists ? '' : ' [missing]'}`));
    if (s.name === 'sim_print.py' || s.name === 'compiled/sim_dropper' || s.name === 'sim_c2_mimic.py' || s.name === 'compiled/sim_elf_mimic') {
      const btn = el('button', { class: 'runBtn' }, 'Run');
      btn.disabled = !state.confirmed || !s.exists;
      btn.addEventListener('click', () => runSample(s.name));
      row.appendChild(btn);
    }
    container.appendChild(row);
  });
}

function renderArtifacts(art, contents) {
  const merged = { ...(art || {}) };
  if (contents && typeof contents === 'object') {
    merged.sandbox_output_contents = contents;
  }
  document.getElementById('artifacts').textContent = JSON.stringify(merged, null, 2);
}

function renderStaticOptions() {
  const sel = document.getElementById('staticSample');
  sel.innerHTML = '';
  state.samples.forEach(s => {
    const o = el('option', { value: s.name }, s.name);
    sel.appendChild(o);
  });
  const dsel = document.getElementById('deepSample');
  if (dsel) {
    dsel.innerHTML = '';
    state.samples.forEach(s => {
      const o = el('option', { value: s.name }, s.name);
      dsel.appendChild(o);
    });
  }
}

async function runSample(name) {
  const res = await fetch('/api/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample: name })
  });
  const data = await res.json();
  const filtered = {
    sample: data.sample,
    returncode: data.returncode,
    stdout: data.stdout,
    stderr: data.stderr
  };
  document.getElementById('runOutput').textContent = JSON.stringify(filtered, null, 2);
  fetchSamples();
}

document.getElementById('compileDropper').addEventListener('click', async () => {
  const res = await fetch('/api/compile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample: 'sim_dropper.c' })
  });
  const data = await res.json();
  const filtered = {
    action: 'compile sim_dropper.c',
    returncode: data.returncode,
    stdout: data.stdout,
    stderr: data.stderr
  };
  document.getElementById('runOutput').textContent = JSON.stringify(filtered, null, 2);
  fetchSamples();
});

document.getElementById('downloadArtifacts').addEventListener('click', () => {
  window.location.href = '/api/artifacts';
});

document.getElementById('compileElfMimic').addEventListener('click', async () => {
  const res = await fetch('/api/compile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample: 'sim_elf_mimic.c' })
  });
  const data = await res.json();
  const filtered = {
    action: 'compile sim_elf_mimic.c',
    returncode: data.returncode,
    stdout: data.stdout,
    stderr: data.stderr
  };
  document.getElementById('runOutput').textContent = JSON.stringify(filtered, null, 2);
  fetchSamples();
});

document.getElementById('runStatic').addEventListener('click', async () => {
  const name = document.getElementById('staticSample').value;
  const res = await fetch(`/api/static?sample=${encodeURIComponent(name)}`);
  const data = await res.json();
  document.getElementById('staticOut').textContent = JSON.stringify(data, null, 2);
});

document.getElementById('uploadBtn').addEventListener('click', async () => {
  const f = document.getElementById('uploadFile').files[0];
  if (!f) { alert('Pick a file first'); return; }
  const form = new FormData();
  form.append('file', f);
  const res = await fetch('/api/upload', { method: 'POST', body: form });
  const data = await res.json();
  alert('Uploaded: ' + (data.saved_as || 'unknown'));
  fetchSamples();
});

document.getElementById('createReport').addEventListener('click', async () => {
  const name = document.getElementById('staticSample').value;
  const format = (document.getElementById('reportFormat')?.value) || 'html';
  const res = await fetch('/api/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample: name, kind: 'static', format })
  });
  const data = await res.json();
  if (data.download) {
    const a = document.createElement('a');
    a.href = data.download;
    a.download = '';
    a.click();
  }
});

document.getElementById('runDeepStatic').addEventListener('click', async () => {
  const name = document.getElementById('deepSample').value;
  const res = await fetch(`/api/deep_static?sample=${encodeURIComponent(name)}`);
  const data = await res.json();
  document.getElementById('deepStaticOut').textContent = JSON.stringify(data, null, 2);
});

document.getElementById('startSink').addEventListener('click', async () => {
  const res = await fetch('/api/sink/start', { method: 'POST' });
  const data = await res.json();
  alert('Sink: ' + data.status);
});

document.getElementById('runNetClient').addEventListener('click', async () => {
  const res = await fetch('/api/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample: 'sim_netclient.py' })
  });
  const data = await res.json();
  document.getElementById('netLog').textContent = 'Client output:\n' + JSON.stringify(data, null, 2);
});

document.getElementById('refreshLog').addEventListener('click', async () => {
  const res = await fetch('/api/logs');
  const data = await res.json();
  document.getElementById('netLog').textContent = data.log || data.note || '';
});

document.getElementById('runYara').addEventListener('click', async () => {
  const res = await fetch('/api/yara', { method: 'POST' });
  const data = await res.json();
  document.getElementById('yaraOut').textContent = JSON.stringify(data, null, 2);
});

document.getElementById('confirmIsolation').addEventListener('change', (e) => {
  state.confirmed = e.target.checked;
  setButtonsEnabled(state.confirmed);
  renderSamples();
});

async function runDynamic(name, outId) {
  const res = await fetch('/api/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample: name })
  });
  const data = await res.json();
  document.getElementById(outId).textContent = JSON.stringify(data, null, 2);
}

document.getElementById('runPacker').addEventListener('click', () => runDynamic('sim_packer.py','dynamicOut'));
document.getElementById('runPersistence').addEventListener('click', () => runDynamic('sim_persistence.py','dynamicOut'));
document.getElementById('runObfuscated').addEventListener('click', () => runDynamic('sim_obfuscated.py','dynamicOut'));

document.getElementById('refreshReports').addEventListener('click', async () => {
  const res = await fetch('/api/reports');
  const data = await res.json();
  const ul = document.getElementById('reportsList');
  ul.innerHTML = '';
  (data.reports || []).forEach(r => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '/' + r.path;
    a.textContent = r.name;
    a.download = '';
    li.appendChild(a);
    ul.appendChild(li);
  });
});

document.querySelectorAll('nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.page;
    if (target) {
      location.hash = target;
    }
  });
});

function setFromHash() {
  const id = (location.hash || '#home').slice(1);
  const valid = ['home','samples','static','dynamic','network','yara','reports','deepstatic'];
  setPage(valid.includes(id) ? id : 'home');
}

window.addEventListener('hashchange', setFromHash);

setFromHash();
fetchSamples();


