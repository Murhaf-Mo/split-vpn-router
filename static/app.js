'use strict';
const $ = (id) => document.getElementById(id);
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('token')) {
  sessionStorage.setItem('vpn-router-token', fragment.get('token'));
  history.replaceState(null, '', location.pathname);
}
const token = sessionStorage.getItem('vpn-router-token') || '';
let busy = false;
let refreshing = false;
let renderedLists = '';

async function api(path, body) {
  const response = await fetch('/api/' + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(response.status === 401 ? 'Open this dashboard with vpn dashboard to authorize it.' : error.error);
  }
  return response.headers.get('Content-Type')?.includes('application/json') ? response.json() : response.text();
}

function showError(error) { $('error').textContent = error?.message || ''; }
async function action(fn) {
  if (busy) return;
  busy = true;
  showError(null);
  try { await fn(); await refresh(); } catch (error) { showError(error); }
  finally { busy = false; }
}

function renderList(which, values) {
  const list = $(which + '-list');
  list.replaceChildren();
  for (const value of values) {
    const row = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = value;
    const remove = document.createElement('button');
    remove.className = 'remove';
    remove.textContent = 'Remove';
    remove.setAttribute('aria-label', 'Remove ' + value);
    remove.addEventListener('click', () => action(() => api('lists/' + which, { remove: [value] })));
    row.append(label, remove);
    list.append(row);
  }
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const status = await api('status');
    $('status').textContent = status.connection_state === 'connected' && !status.router_active ? 'Router inactive' : status.connection_state;
    $('status').dataset.connected = String(status.connection_state === 'connected' && status.router_active);
    $('connection').textContent = status.connection_state === 'connected'
      ? status.router_active ? 'VPN and Windows routing are connected.' : 'VPN is connected, but Windows routing is inactive. Run vpn up to restore routing.'
      : status.connection_state === 'connecting' ? 'Waiting for VPN authentication…' : 'VPN disconnected. Choose Connect when you are ready.';
    $('connect').disabled = status.connection_state !== 'disconnected' || !status.router_active;
    $('disconnect').disabled = status.connection_state === 'disconnected';
    if (status.error) $('error').textContent = status.error;
    else if (status.router_error) $('error').textContent = status.router_error;
    if (document.activeElement !== $('mode')) $('mode').value = status.mode;
    const [vpn, direct] = await Promise.all([api('lists/vpn'), api('lists/direct')]);
    const signature = JSON.stringify([vpn.entries, direct.entries]);
    if (signature !== renderedLists) {
      renderList('vpn', vpn.entries); renderList('direct', direct.entries);
      renderedLists = signature;
    }
  } catch (error) {
    $('status').textContent = 'Unavailable';
    $('status').dataset.connected = 'false';
    $('connect').disabled = true;
    $('disconnect').disabled = true;
    showError(error);
  } finally { refreshing = false; }
}

for (const which of ['vpn', 'direct']) {
  $(which + '-form').addEventListener('submit', (event) => {
    event.preventDefault();
    action(async () => { await api('lists/' + which, { add: [$(which + '-entry').value] }); $(which + '-entry').value = ''; });
  });
}
$('connect').addEventListener('click', () => action(() => api('connect', {})));
$('disconnect').addEventListener('click', () => action(() => api('disconnect', {})));
$('refresh').addEventListener('click', () => action(refresh));
$('mode').addEventListener('change', () => action(() => api('mode', { mode: $('mode').value })));
$('settings').addEventListener('submit', (event) => {
  event.preventDefault();
  action(async () => {
    await api('config', { vpn: { host: $('host').value, user: $('user').value, password: $('password').value,
      group: $('group').value, dns_server: $('dns').value, auto_reconnect: $('reconnect').checked } });
    $('password').value = '';
  });
});
for (const button of document.querySelectorAll('[data-log]')) {
  button.addEventListener('click', () => action(async () => { $('logs').textContent = await api('logs/' + button.dataset.log); }));
}
async function initialize() {
  try {
    const cfg = await api('config');
    $('host').value = cfg.vpn.host; $('user').value = cfg.vpn.user; $('group').value = cfg.vpn.group;
    $('dns').value = cfg.vpn.dns_server; $('reconnect').checked = cfg.vpn.auto_reconnect === true;
  } catch (error) { showError(error); }
  await refresh();
  setInterval(() => { if (!busy && !document.hidden) refresh(); }, 3000);
}
initialize();
