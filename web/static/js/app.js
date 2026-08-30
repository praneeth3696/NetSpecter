/**
 * NetSpecter Cyber Terminal Application (Mr. Robot Theme)
 * WebSocket client, telemetry renderer, audio synth, and forensic dissector.
 */

(function () {
    'use strict';

    // --- Web Audio Synthesizer (Zero External Dependencies) ---
    class AudioSynth {
        constructor() {
            this.enabled = true;
            this.ctx = null;
        }

        initContext() {
            if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
                const AudioContextClass = window.AudioContext || window.webkitAudioContext;
                this.ctx = new AudioContextClass();
            }
        }

        playClick() {
            if (!this.enabled) return;
            try {
                this.initContext();
                if (!this.ctx) return;
                const osc = this.ctx.createOscillator();
                const gain = this.ctx.createGain();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(800, this.ctx.currentTime);
                osc.frequency.exponentialRampToValueAtTime(300, this.ctx.currentTime + 0.03);
                gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
                gain.gain.linearRampToValueAtTime(0.001, this.ctx.currentTime + 0.03);
                osc.connect(gain);
                gain.connect(this.ctx.destination);
                osc.start();
                osc.stop(this.ctx.currentTime + 0.03);
            } catch (e) {}
        }

        playAlert() {
            if (!this.enabled) return;
            try {
                this.initContext();
                if (!this.ctx) return;
                const osc = this.ctx.createOscillator();
                const gain = this.ctx.createGain();
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(440, this.ctx.currentTime);
                osc.frequency.setValueAtTime(880, this.ctx.currentTime + 0.06);
                osc.frequency.setValueAtTime(1760, this.ctx.currentTime + 0.12);
                gain.gain.setValueAtTime(0.08, this.ctx.currentTime);
                gain.gain.linearRampToValueAtTime(0.001, this.ctx.currentTime + 0.22);
                osc.connect(gain);
                gain.connect(this.ctx.destination);
                osc.start();
                osc.stop(this.ctx.currentTime + 0.22);
            } catch (e) {}
        }
    }

    const synth = new AudioSynth();

    // --- State ---
    const state = {
        ws: null,
        isCapturing: false,
        activeIface: '',
        bpfFilter: '',
        maskSecrets: true,
        crtEnabled: true,
        activeTab: 'tabLive',
        filterProto: 'ALL',
        searchQuery: '',
        detections: [],
        flows: [],
        stats: {
            packets_inspected: 0,
            alerts_count: 0,
            active_flows: 0,
            elapsed_seconds: 0,
            packets_per_sec: 0.0,
            protocols: {},
            severities: { critical: 0, high: 0, medium: 0 }
        }
    };

    // --- DOM Elements ---
    const el = {
        systemBeacon: document.getElementById('systemBeacon'),
        statusLabel: document.getElementById('statusLabel'),
        ifaceSelect: document.getElementById('ifaceSelect'),
        bpfInput: document.getElementById('bpfInput'),
        btnToggleCapture: document.getElementById('btnToggleCapture'),
        btnSimulateModal: document.getElementById('btnSimulateModal'),
        btnAudioToggle: document.getElementById('btnAudioToggle'),
        btnMaskToggle: document.getElementById('btnMaskToggle'),
        btnCrtToggle: document.getElementById('btnCrtToggle'),
        
        hudPackets: document.getElementById('hudPackets'),
        hudThroughput: document.getElementById('hudThroughput'),
        hudLeaks: document.getElementById('hudLeaks'),
        hudCriticals: document.getElementById('hudCriticals'),
        hudFlows: document.getElementById('hudFlows'),
        hudStatus: document.getElementById('hudStatus'),
        hudRuntime: document.getElementById('hudRuntime'),
        badgeLiveCount: document.getElementById('badgeLiveCount'),

        incidentFeed: document.getElementById('incidentFeed'),
        emptyFeedMsg: document.getElementById('emptyFeedMsg'),
        liveSearchInput: document.getElementById('liveSearchInput'),
        btnClearFeed: document.getElementById('btnClearFeed'),

        // PCAP
        pcapDropZone: document.getElementById('pcapDropZone'),
        pcapFileInput: document.getElementById('pcapFileInput'),
        pcapResultsContainer: document.getElementById('pcapResultsContainer'),
        pcapSummaryBar: document.getElementById('pcapSummaryBar'),
        pcapTableBody: document.getElementById('pcapTableBody'),

        // Flows
        flowsTableBody: document.getElementById('flowsTableBody'),
        flowCountLabel: document.getElementById('flowCountLabel'),

        // Drawer
        payloadDrawer: document.getElementById('payloadDrawer'),
        btnCloseDrawer: document.getElementById('btnCloseDrawer'),
        drawerBadge: document.getElementById('drawerBadge'),
        drSrc: document.getElementById('drSrc'),
        drDst: document.getElementById('drDst'),
        drType: document.getElementById('drType'),
        drSeverity: document.getElementById('drSeverity'),
        drUser: document.getElementById('drUser'),
        drSecret: document.getElementById('drSecret'),
        drRawSnippet: document.getElementById('drRawSnippet'),
        drHexDump: document.getElementById('drHexDump'),
        drRemediation: document.getElementById('drRemediation'),

        // WebSocket Indicator
        wsConnDot: document.getElementById('wsConnDot'),
        wsConnLabel: document.getElementById('wsConnLabel')
    };

    // --- WebSocket Connection ---
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/live`;

        state.ws = new WebSocket(wsUrl);

        state.ws.onopen = () => {
            el.wsConnDot.className = 'conn-dot connected';
            el.wsConnLabel.textContent = 'LIVE WEBSOCKET ATTACHED';
        };

        state.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleWsMessage(data);
            } catch (e) {
                console.error('WS Parse Error:', e);
            }
        };

        state.ws.onclose = () => {
            el.wsConnDot.className = 'conn-dot';
            el.wsConnLabel.textContent = 'RECONNECTING...';
            setTimeout(connectWebSocket, 2000);
        };

        state.ws.onerror = () => {
            state.ws.close();
        };
    }

    function handleWsMessage(data) {
        if (data.type === 'init') {
            state.isCapturing = data.is_capturing;
            state.activeIface = data.active_iface;
            state.bpfFilter = data.bpf_filter || el.bpfInput.value;
            if (data.stats) updateStats(data.stats);
            if (data.detections && data.detections.length) {
                data.detections.forEach(d => addDetection(d, false));
            }
            if (data.flows) renderFlows(data.flows);
            updateCaptureUiState();
        } else if (data.type === 'packet_beat') {
            if (data.stats) updateStats(data.stats);
        } else if (data.type === 'leak_detected') {
            addDetection(data.leak, true);
            if (data.stats) updateStats(data.stats);
            synth.playAlert();
        } else if (data.type === 'capture_status') {
            state.isCapturing = data.is_capturing;
            if (data.iface) state.activeIface = data.iface;
            if (data.filter) state.bpfFilter = data.filter;
            if (data.stats) updateStats(data.stats);
            updateCaptureUiState();
        }
    }

    // --- Telemetry & Stats Updates ---
    function updateStats(stats) {
        state.stats = stats;
        el.hudPackets.textContent = (stats.packets_inspected || 0).toLocaleString();
        el.hudThroughput.textContent = `${stats.packets_per_sec || 0.0} pkts/sec`;
        el.hudLeaks.textContent = (stats.alerts_count || 0).toLocaleString();
        
        const critCount = (stats.severities && stats.severities.critical) || 0;
        el.hudCriticals.textContent = `${critCount} Critical Incident${critCount === 1 ? '' : 's'}`;
        el.hudFlows.textContent = stats.active_flows || 0;
        
        const elapsed = stats.elapsed_seconds || 0;
        const hrs = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const mins = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const secs = String(elapsed % 60).padStart(2, '0');
        el.hudRuntime.textContent = `Elapsed: ${hrs}:${mins}:${secs}`;

        el.badgeLiveCount.textContent = state.detections.length;

        // Analytics bars
        const protos = stats.protocols || {};
        const maxP = Math.max(1, ...Object.values(protos));
        ['HTTP', 'FTP', 'REDIS', 'MAIL', 'TOKEN'].forEach(p => {
            const count = protos[p] || 0;
            const bar = document.getElementById(`bar${p}`);
            const lbl = document.getElementById(`count${p}`);
            if (bar) bar.style.width = `${Math.min(100, (count / maxP) * 100)}%`;
            if (lbl) lbl.textContent = count;
        });

        // Severity breakdown
        if (stats.severities) {
            const sC = document.getElementById('statCrit');
            const sH = document.getElementById('statHigh');
            const sM = document.getElementById('statMed');
            if (sC) sC.textContent = stats.severities.critical || 0;
            if (sH) sH.textContent = stats.severities.high || 0;
            if (sM) sM.textContent = stats.severities.medium || 0;
        }
    }

    function updateCaptureUiState() {
        if (state.isCapturing) {
            el.systemBeacon.className = 'system-beacon scanning';
            el.statusLabel.textContent = 'SCANNING // ACTIVE';
            el.hudStatus.textContent = 'CAPTURING';
            el.hudStatus.className = 'hud-value hud-text-status text-green';
            el.btnToggleCapture.className = 'cyber-btn btn-primary btn-stop';
            el.btnToggleCapture.innerHTML = '<span class="btn-icon">■</span><span class="btn-text">STOP SCAN</span>';
        } else {
            el.systemBeacon.className = 'system-beacon';
            el.statusLabel.textContent = 'SYSTEM IDLE';
            el.hudStatus.textContent = 'READY';
            el.hudStatus.className = 'hud-value hud-text-status';
            el.btnToggleCapture.className = 'cyber-btn btn-primary';
            el.btnToggleCapture.innerHTML = '<span class="btn-icon">▶</span><span class="btn-text">START SCAN</span>';
        }
    }

    // --- Detection Feed Management ---
    function addDetection(leak, isNew = false) {
        state.detections.unshift(leak);
        el.badgeLiveCount.textContent = state.detections.length;

        if (el.emptyFeedMsg) {
            el.emptyFeedMsg.style.display = 'none';
        }

        const card = createIncidentCard(leak);
        if (isNew) {
            card.style.animation = 'pulseSymbol 0.5s ease-out';
        }
        el.incidentFeed.insertBefore(card, el.incidentFeed.firstChild);

        filterFeed();
    }

    function createIncidentCard(leak) {
        const div = document.createElement('div');
        div.className = 'incident-card';
        div.dataset.id = leak.id;
        div.dataset.proto = (leak.protocol || '').toUpperCase();
        div.dataset.content = `${leak.src} ${leak.dst} ${leak.username} ${leak.password} ${leak.token} ${leak.protocol}`.toLowerCase();

        const pClass = `badge-${(leak.protocol || 'http').toLowerCase()}`;
        const sClass = `badge-${(leak.severity || 'high').toLowerCase()}`;
        const secretVal = state.maskSecrets ? leak.masked_secret : (leak.password || leak.token);

        div.innerHTML = `
            <div class="card-time">${leak.time_str || '–'}</div>
            <div><span class="badge ${pClass}">${leak.protocol}</span></div>
            <div class="card-endpoint" title="${leak.src}">SRC: ${leak.src}</div>
            <div class="card-endpoint" title="${leak.dst}">DST: ${leak.dst}</div>
            <div class="card-secret-box">
                ${leak.username ? `<span class="card-user">${leak.username}</span>:` : ''}
                <span class="card-pass">${secretVal}</span>
            </div>
            <div><span class="badge ${sClass}">${leak.severity}</span></div>
            <div><button class="card-btn">INSPECT</button></div>
        `;

        div.addEventListener('click', () => openDrawer(leak));
        return div;
    }

    function filterFeed() {
        const cards = el.incidentFeed.querySelectorAll('.incident-card');
        const q = state.searchQuery.toLowerCase();
        let visibleCount = 0;

        cards.forEach(c => {
            const protoMatch = (state.filterProto === 'ALL' || c.dataset.proto === state.filterProto);
            const searchMatch = (!q || c.dataset.content.includes(q));
            if (protoMatch && searchMatch) {
                c.style.display = 'grid';
                visibleCount++;
            } else {
                c.style.display = 'none';
            }
        });

        if (el.emptyFeedMsg) {
            el.emptyFeedMsg.style.display = (visibleCount === 0 && state.detections.length === 0) ? 'flex' : 'none';
        }
    }

    // --- Drawer / Payload Inspection ---
    function openDrawer(leak) {
        synth.playClick();
        el.drawerBadge.textContent = leak.protocol;
        el.drawerBadge.className = `badge badge-${(leak.protocol || 'http').toLowerCase()}`;
        
        el.drSrc.textContent = leak.src;
        el.drDst.textContent = leak.dst;
        el.drType.textContent = leak.type;
        el.drSeverity.textContent = leak.severity;
        el.drSeverity.className = `meta-v text-${leak.severity === 'CRITICAL' ? 'red' : 'amber'}`;
        el.drUser.textContent = leak.username || 'N/A';
        el.drSecret.textContent = state.maskSecrets ? leak.masked_secret : (leak.password || leak.token);

        el.drRawSnippet.textContent = leak.raw_snippet || 'No raw snippet captured.';
        el.drHexDump.textContent = leak.hex_dump || 'No hex dump available for this stream.';

        el.drRemediation.innerHTML = getRemediationHtml(leak);

        el.payloadDrawer.classList.add('open');
    }

    function closeDrawer() {
        el.payloadDrawer.classList.remove('open');
    }

    function getRemediationHtml(leak) {
        const proto = (leak.protocol || '').toUpperCase();
        if (proto === 'HTTP') {
            return `
                <h4 class="text-cyan" style="margin-bottom: 6px;">Remediation: Enforce TLS & HSTS</h4>
                <p>This service transmitted authentication credentials over plaintext HTTP. Migrate the endpoint to <strong>HTTPS (TLS 1.3)</strong> and configure the <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code> response header to prevent SSL stripping attacks.</p>
            `;
        } else if (proto === 'FTP') {
            return `
                <h4 class="text-amber" style="margin-bottom: 6px;">Remediation: Upgrade to SFTP / FTPS</h4>
                <p>Cleartext FTP transmits USER and PASS commands in unencrypted ASCII. Replace legacy FTP daemon with <strong>SFTP (SSH File Transfer Protocol)</strong> on port 22 or enforce FTPS with mandatory TLS wrapping.</p>
            `;
        } else if (proto === 'REDIS') {
            return `
                <h4 class="text-red" style="margin-bottom: 6px;">Remediation: Enable Redis TLS & Network Isolation</h4>
                <p>Redis AUTH password was intercepted in unencrypted RESP format. Configure <code>tls-port</code> in <code>redis.conf</code> and ensure Redis instances are bound strictly to private VPC/localhost interfaces (e.g. <code>bind 127.0.0.1</code>).</p>
            `;
        } else if (proto === 'TOKEN' || proto === 'JWT') {
            return `
                <h4 class="text-purple" style="margin-bottom: 6px;">Remediation: Revoke Token & Restrict Scopes</h4>
                <p>A cloud API key or Bearer token was exposed. Immediately <strong>revoke and rotate</strong> this token. Ensure all API clients communicate exclusively over secure HTTPS channels.</p>
            `;
        }
        return `<p>Enforce end-to-end TLS encryption across all network communication channels.</p>`;
    }

    // --- Flows Table ---
    function renderFlows(flows) {
        state.flows = flows;
        el.flowCountLabel.textContent = `${flows.length} active session${flows.length === 1 ? '' : 's'}`;

        if (!flows.length) {
            el.flowsTableBody.innerHTML = '<tr><td colspan="5" class="text-center dim">No active TCP flows being reassembled.</td></tr>';
            return;
        }

        el.flowsTableBody.innerHTML = flows.map(f => `
            <tr>
                <td><code>${f.src} ➔ ${f.dst}</code></td>
                <td><span class="badge badge-http">${f.proto}</span></td>
                <td>${f.buffered_bytes.toLocaleString()} bytes</td>
                <td>${f.last_active}s ago</td>
                <td><span class="text-green">REASSEMBLING</span></td>
            </tr>
        `).join('');
    }

    // --- Interfaces List ---
    async function loadInterfaces() {
        try {
            const res = await fetch('/api/interfaces');
            const data = await res.json();
            if (data && data.interfaces) {
                el.ifaceSelect.innerHTML = '<option value="">Auto-Detect Default</option>';
                data.interfaces.forEach(i => {
                    const opt = document.createElement('option');
                    opt.value = i.name;
                    opt.textContent = `${i.name} [${i.ip || 'no-ip'}] - ${i.description}`;
                    el.ifaceSelect.appendChild(opt);
                });
            }
        } catch (e) {
            console.error('Failed to load interfaces:', e);
        }
    }

    // --- PCAP Upload ---
    async function uploadPcapFile(file) {
        if (!file) return;
        synth.playClick();

        const formData = new FormData();
        formData.append('file', file);

        el.pcapSummaryBar.innerHTML = `<span class="terminal-loader"><span class="cursor-blink">█</span> DISSECTING PCAP FORENSICS: ${file.name}...</span>`;
        el.pcapResultsContainer.style.display = 'block';

        try {
            const res = await fetch('/api/pcap/upload', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (data.success) {
                synth.playAlert();
                el.pcapSummaryBar.innerHTML = `
                    <span>File: <strong>${data.filename}</strong></span>
                    <span>Packets: <strong>${data.packets_count.toLocaleString()}</strong></span>
                    <span class="text-red">Leaks Discovered: <strong>${data.leaks_count}</strong></span>
                `;

                if (data.leaks && data.leaks.length) {
                    el.pcapTableBody.innerHTML = data.leaks.map((leak, idx) => `
                        <tr>
                            <td>#${idx + 1}</td>
                            <td><span class="badge badge-${(leak.protocol || 'http').toLowerCase()}">${leak.protocol}</span></td>
                            <td><span class="badge badge-${(leak.severity || 'high').toLowerCase()}">${leak.severity}</span></td>
                            <td><code>${leak.src}</code></td>
                            <td><code>${leak.dst}</code></td>
                            <td><strong>${leak.username || '–'}</strong></td>
                            <td><code class="text-red">${state.maskSecrets ? leak.masked_secret : (leak.password || leak.token)}</code></td>
                            <td>${leak.confidence}</td>
                            <td><button class="card-btn" onclick='window.NetSpecterApp.openDrawerById("${leak.id}")'>INSPECT</button></td>
                        </tr>
                    `).join('');
                } else {
                    el.pcapTableBody.innerHTML = '<tr><td colspan="9" class="text-center text-green">✔ No cleartext credentials found in this capture.</td></tr>';
                }
            } else {
                el.pcapSummaryBar.innerHTML = `<span class="text-red">Error parsing PCAP: ${data.detail || 'Unknown error'}</span>`;
            }
        } catch (e) {
            el.pcapSummaryBar.innerHTML = `<span class="text-red">Upload failed: ${e.message}</span>`;
        }
    }

    // --- Leak Simulation ---
    async function simulateLeak(scenario) {
        synth.playClick();
        try {
            const res = await fetch('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario: scenario })
            });
            const data = await res.json();
            if (data.success) {
                // Switch to live feed tab to view it
                switchTab('tabLive');
            }
        } catch (e) {
            console.error('Simulation error:', e);
        }
    }

    // --- Event Listeners ---
    function setupEvents() {
        // Tab Switcher
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                synth.playClick();
                switchTab(tab.dataset.tab);
            });
        });

        // Drawer Tabs
        document.querySelectorAll('.dtab').forEach(btn => {
            btn.addEventListener('click', () => {
                synth.playClick();
                document.querySelectorAll('.dtab').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.dview-content').forEach(v => v.classList.remove('active'));
                btn.classList.add('active');
                const vId = 'dview' + btn.dataset.dview.charAt(0).toUpperCase() + btn.dataset.dview.slice(1);
                const targetView = document.getElementById(vId);
                if (targetView) targetView.classList.add('active');
            });
        });

        el.btnCloseDrawer.addEventListener('click', closeDrawer);

        // Capture Toggle
        el.btnToggleCapture.addEventListener('click', async () => {
            synth.playClick();
            if (state.isCapturing) {
                await fetch('/api/scan/stop', { method: 'POST' });
            } else {
                const iface = el.ifaceSelect.value || null;
                const bpf = el.bpfInput.value || null;
                await fetch('/api/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ iface: iface, bpf: bpf })
                });
            }
        });

        // Toggles
        el.btnAudioToggle.addEventListener('click', () => {
            synth.enabled = !synth.enabled;
            el.btnAudioToggle.classList.toggle('active', synth.enabled);
            synth.playClick();
        });

        el.btnMaskToggle.addEventListener('click', () => {
            synth.playClick();
            state.maskSecrets = !state.maskSecrets;
            el.btnMaskToggle.classList.toggle('active', state.maskSecrets);
            // Refresh feed
            el.incidentFeed.innerHTML = '';
            state.detections.forEach(d => el.incidentFeed.appendChild(createIncidentCard(d)));
            filterFeed();
        });

        el.btnCrtToggle.addEventListener('click', () => {
            synth.playClick();
            state.crtEnabled = !state.crtEnabled;
            document.body.classList.toggle('crt-enabled', state.crtEnabled);
            el.btnCrtToggle.classList.toggle('active', state.crtEnabled);
        });

        // Filter Pills
        document.querySelectorAll('.filter-pill').forEach(btn => {
            btn.addEventListener('click', () => {
                synth.playClick();
                document.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.filterProto = btn.dataset.proto;
                filterFeed();
            });
        });

        el.liveSearchInput.addEventListener('input', (e) => {
            state.searchQuery = e.target.value;
            filterFeed();
        });

        el.btnClearFeed.addEventListener('click', () => {
            synth.playClick();
            state.detections = [];
            el.incidentFeed.innerHTML = '';
            if (el.emptyFeedMsg) el.emptyFeedMsg.style.display = 'flex';
            el.badgeLiveCount.textContent = '0';
        });

        // PCAP Drag & Drop
        el.pcapDropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            el.pcapDropZone.style.borderColor = 'var(--cyan)';
        });
        el.pcapDropZone.addEventListener('dragleave', () => {
            el.pcapDropZone.style.borderColor = 'var(--border-bright)';
        });
        el.pcapDropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            el.pcapDropZone.style.borderColor = 'var(--border-bright)';
            if (e.dataTransfer.files.length) {
                uploadPcapFile(e.dataTransfer.files[0]);
            }
        });
        el.pcapFileInput.addEventListener('change', (e) => {
            if (e.target.files.length) {
                uploadPcapFile(e.target.files[0]);
            }
        });
    }

    function switchTab(tabId) {
        state.activeTab = tabId;
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === tabId));
    }

    // --- Global Public API ---
    window.NetSpecterApp = {
        simulateLeak: simulateLeak,
        openDrawerById: (id) => {
            const d = state.detections.find(x => x.id === id);
            if (d) openDrawer(d);
        }
    };

    // --- Init ---
    document.addEventListener('DOMContentLoaded', () => {
        loadInterfaces();
        connectWebSocket();
        setupEvents();
    });

})();
