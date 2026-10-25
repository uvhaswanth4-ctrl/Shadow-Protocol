/**
 * Shadow Protocol - Client Application Logic
 * Cyber Hackathon 2026 | C-DAC Patna & CCSU Bihar Police
 */

let currentScanResult = null;

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initDropzone();
    initPresets();
    initMLStudio();
    loadHistory();
    
    // Auto-load Cerberus sample on first launch to showcase dashboard immediately!
    loadPreset("cerberus_banking_trojan.apk");
});

// 1. Tab Switching
function initTabs() {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            
            tab.classList.add("active");
            const targetId = tab.getAttribute("data-tab");
            const targetContent = document.getElementById(targetId);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });
}

function switchTab(tabId) {
    const tabBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    if (tabBtn) {
        tabBtn.click();
    }
}

// 2. File Upload & Drag-and-Drop
function initDropzone() {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    showLoading(`Analyzing binary structure & static attributes of ${file.name}...`);
    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            body: formData
        });
        if (!response.ok) throw new Error("Server error during scan");
        const data = await response.json();
        renderScanResult(data);
        loadHistory();
        switchTab("tab-triage");
    } catch (err) {
        alert("Scan Failed: " + err.message);
    } finally {
        hideLoading();
    }
}

// 3. Preset Samples
function initPresets() {
    document.querySelectorAll(".preset-card").forEach(card => {
        card.addEventListener("click", () => {
            const preset = card.getAttribute("data-preset");
            loadPreset(preset);
        });
    });
}

async function loadPreset(presetName) {
    showLoading(`Loading and inspecting preset: ${presetName}...`);
    const formData = new FormData();
    formData.append("preset_name", presetName);

    try {
        const response = await fetch("/api/scan-preset", {
            method: "POST",
            body: formData
        });
        if (!response.ok) throw new Error("Preset analysis failed");
        const data = await response.json();
        renderScanResult(data);
        loadHistory();
    } catch (err) {
        console.error(err);
    } finally {
        hideLoading();
    }
}

// 4. Render Master Results across all tabs
function renderScanResult(data) {
    currentScanResult = data;
    
    // --- Header Sample Tag ---
    const activeSampleTag = document.getElementById("activeSampleTag");
    if (activeSampleTag) {
        activeSampleTag.textContent = `${data.file_name} (${data.file_type}) · Risk: ${data.verdict}`;
    }

    // --- Executive Triage (Tab 2) ---
    const scoreNum = document.getElementById("scoreNum");
    const scoreCircle = document.getElementById("scoreCircle");
    const verdictBadge = document.getElementById("verdictBadge");
    const verdictDesc = document.getElementById("verdictDesc");
    const confidenceText = document.getElementById("confidenceText");

    scoreNum.textContent = data.risk_score;
    verdictBadge.textContent = data.verdict;
    verdictBadge.className = `verdict-badge verdict-${data.verdict}`;
    verdictDesc.textContent = data.risk_level;
    confidenceText.textContent = `Model Confidence: ${data.confidence}% (Explainable Static Verdict)`;

    // Color score circle
    if (data.verdict === "CRITICAL") {
        scoreCircle.style.background = "#fef2f2";
        scoreCircle.style.border = "3px solid #dc2626";
        scoreNum.style.color = "#dc2626";
    } else if (data.verdict === "HIGH") {
        scoreCircle.style.background = "#fff7ed";
        scoreCircle.style.border = "3px solid #ea580c";
        scoreNum.style.color = "#ea580c";
    } else if (data.verdict === "MEDIUM") {
        scoreCircle.style.background = "#fffbeb";
        scoreCircle.style.border = "3px solid #d97706";
        scoreNum.style.color = "#d97706";
    } else {
        scoreCircle.style.background = "#f0fdf4";
        scoreCircle.style.border = "3px solid #16a34a";
        scoreNum.style.color = "#16a34a";
    }

    // KPIs
    document.getElementById("kpiEntropy").textContent = `${data.entropy} / 8.0`;
    document.getElementById("kpiPermissions").textContent = data.summary.total_permissions || (data.details.sections ? data.details.sections.length : 0);
    document.getElementById("kpiApis").textContent = data.summary.suspicious_apis_count || data.summary.suspicious_imports_count || 0;
    document.getElementById("kpiIocs").textContent = (data.iocs || []).length;

    // Technical Justifications
    const justList = document.getElementById("justificationList");
    justList.innerHTML = "";
    (data.summary.justifications || []).forEach(j => {
        const li = document.createElement("li");
        li.className = data.verdict === "CRITICAL" ? "justification-item danger" : "justification-item warning";
        li.innerHTML = `<strong>⚠️ Finding:</strong> ${j}`;
        justList.appendChild(li);
    });

    // --- APK & Manifest Deep Dive (Tab 3) ---
    document.getElementById("metaFileName").textContent = data.file_name;
    document.getElementById("metaFileSize").textContent = `${(data.file_size / 1024).toFixed(1)} KB`;
    document.getElementById("metaMd5").textContent = data.md5;
    document.getElementById("metaSha1").textContent = data.sha1;
    document.getElementById("metaSha256").textContent = data.sha256;
    document.getElementById("metaPackage").textContent = data.summary.package_name || "N/A (PE Binary)";
    document.getElementById("metaMinSdk").textContent = data.summary.min_sdk || "N/A";
    document.getElementById("metaTargetSdk").textContent = data.summary.target_sdk || "N/A";

    // Permissions Table
    const permTbody = document.getElementById("permissionsTbody");
    permTbody.innerHTML = "";
    const allPerms = [];
    if (data.details.permissions) {
        (data.details.permissions.SUSPICIOUS || []).forEach(p => allPerms.push({ ...p, level: "SUSPICIOUS" }));
        (data.details.permissions.DANGEROUS || []).forEach(p => allPerms.push({ ...p, level: "DANGEROUS" }));
        (data.details.permissions.NORMAL || []).forEach(p => allPerms.push({ ...p, level: "NORMAL" }));
    }

    if (allPerms.length === 0) {
        permTbody.innerHTML = `<tr><td colspan="3" class="text-muted" style="text-align:center;">No Android permissions declared (PE / Native Executable).</td></tr>`;
    } else {
        allPerms.forEach(p => {
            const tr = document.createElement("tr");
            let badgeClass = p.level === "SUSPICIOUS" ? "pill-danger" : (p.level === "DANGEROUS" ? "pill-warning" : "pill-info");
            tr.innerHTML = `
                <td><code>${p.permission}</code></td>
                <td><span class="pill ${badgeClass}">${p.level}</span></td>
                <td>${p.description}</td>
            `;
            permTbody.appendChild(tr);
        });
    }

    // Android Manifest Components
    const compBox = document.getElementById("manifestComponentsBox");
    let compHtml = "";
    if (data.details.activities && data.details.activities.length > 0) {
        compHtml += `<p style="font-size: 0.85rem; margin-bottom: 8px;"><strong>Activities (${data.details.activities.length}):</strong> ${data.details.activities.map(a => `<code>${a}</code>`).join(", ")}</p>`;
    }
    if (data.details.services && data.details.services.length > 0) {
        compHtml += `<p style="font-size: 0.85rem; margin-bottom: 8px;"><strong>Services (${data.details.services.length}):</strong> ${data.details.services.map(s => `<code>${s}</code>`).join(", ")}</p>`;
    }
    if (data.details.receivers && data.details.receivers.length > 0) {
        compHtml += `<p style="font-size: 0.85rem; margin-bottom: 8px;"><strong>Broadcast Receivers (${data.details.receivers.length}):</strong> ${data.details.receivers.map(r => `<code>${r}</code>`).join(", ")}</p>`;
    }
    if (data.details.exported_components && data.details.exported_components.length > 0) {
        compHtml += `<p style="font-size: 0.85rem; margin-top: 8px;"><strong style="color: #dc2626;">Exported Attack Surfaces (${data.details.exported_components.length}):</strong> ${data.details.exported_components.map(e => `<code>${e.component}</code>`).join(", ")}</p>`;
    }
    if (!compHtml) {
        compHtml = `<p class="text-muted" style="font-size: 0.85rem;">No declared Android activities/services. (Windows PE binary sections present).</p>`;
    }
    compBox.innerHTML = compHtml;

    // --- Suspicious Code & APIs (Tab 4) ---
    const apisTbody = document.getElementById("suspiciousApisTbody");
    apisTbody.innerHTML = "";
    const apiList = data.details.suspicious_apis || data.details.suspicious_imports || [];
    if (apiList.length === 0) {
        apisTbody.innerHTML = `<tr><td colspan="4" class="text-muted" style="text-align:center;">No suspicious API calls identified.</td></tr>`;
    } else {
        apiList.forEach(api => {
            const tr = document.createElement("tr");
            const name = api.name || api.function;
            const cat = api.category || api.dll || "System";
            const sev = api.severity;
            const desc = api.description;
            const pillClass = sev === "CRITICAL" ? "pill-danger" : (sev === "HIGH" ? "pill-warning" : "pill-info");
            tr.innerHTML = `
                <td><code>${name}</code></td>
                <td>${cat}</td>
                <td><span class="pill ${pillClass}">${sev}</span></td>
                <td>${desc}</td>
            `;
            apisTbody.appendChild(tr);
        });
    }

    // High-Risk Modules (Accessibility, SMS, Overlay, Device Admin)
    renderRiskModule("modAccessibility", data.details.accessibility_analysis);
    renderRiskModule("modSms", data.details.sms_otp_analysis);
    renderRiskModule("modOverlay", data.details.overlay_analysis);
    renderRiskModule("modDeviceAdmin", data.details.device_admin_analysis);

    // --- Secrets & IOCs (Tab 5) ---
    const secretsTbody = document.getElementById("secretsTbody");
    secretsTbody.innerHTML = "";
    const secrets = data.details.hardcoded_secrets || [];
    if (secrets.length === 0) {
        secretsTbody.innerHTML = `<tr><td colspan="3" class="text-muted" style="text-align:center;">No hardcoded credentials, API keys, or tokens identified.</td></tr>`;
    } else {
        secrets.forEach(s => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${s.name}</strong></td>
                <td><code>${s.match}</code></td>
                <td><span class="pill ${s.severity === 'CRITICAL' ? 'pill-danger' : 'pill-warning'}">${s.severity}</span></td>
            `;
            secretsTbody.appendChild(tr);
        });
    }

    // Network IOCs Table
    const iocTbody = document.getElementById("iocTbody");
    iocTbody.innerHTML = "";
    (data.iocs || []).forEach(ioc => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><span class="pill pill-info">${ioc.type}</span></td>
            <td><code>${ioc.value}</code></td>
            <td>${ioc.description}</td>
        `;
        iocTbody.appendChild(tr);
    });

    // --- MITRE ATT&CK Matrix (Tab 6) ---
    const mitreGrid = document.getElementById("mitreGrid");
    mitreGrid.innerHTML = "";
    const mitreList = data.mitre || [];
    if (mitreList.length === 0) {
        mitreGrid.innerHTML = `<div class="card" style="grid-column: 1 / -1; text-align: center; color: #64748b;">No adverse MITRE ATT&CK Mobile techniques detected in this sample.</div>`;
    } else {
        mitreList.forEach(m => {
            const card = document.createElement("div");
            card.className = "mitre-card";
            card.innerHTML = `
                <span class="mitre-id">${m.id}</span>
                <h4>${m.name}</h4>
                <div class="mitre-tactic">${m.tactic}</div>
                <div class="mitre-desc">${m.description}</div>
            `;
            mitreGrid.appendChild(card);
        });
    }

    // --- ML Explainability (Tab 7) ---
    renderMLExplainability(data.ml_analysis);

    // --- Investigation Report (Tab 8) ---
    renderForensicReport(data);
}

function renderRiskModule(elementId, moduleData) {
    const el = document.getElementById(elementId);
    if (!el || !moduleData) return;
    const isDangerous = moduleData.requested || moduleData.capable;
    el.className = isDangerous ? "card" : "card";
    el.style.borderLeft = isDangerous ? "4px solid #dc2626" : "4px solid #16a34a";
    el.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <h4 style="font-size: 0.95rem; font-weight: 600;">${el.getAttribute("data-title")}</h4>
            <span class="pill ${isDangerous ? 'pill-danger' : 'pill-success'}">${moduleData.status}</span>
        </div>
        <p style="font-size: 0.85rem; color: #475569;">${moduleData.details}</p>
    `;
}

function renderMLExplainability(mlData) {
    if (!mlData) return;
    document.getElementById("mlVerdictBadge").textContent = `ML Predicted: ${mlData.ml_verdict} (${mlData.confidence}% Confidence)`;
    const container = document.getElementById("mlFeatureContributions");
    container.innerHTML = "";

    (mlData.feature_contributions || []).forEach(f => {
        const div = document.createElement("div");
        div.className = "feature-bar-container";
        div.innerHTML = `
            <div class="feature-bar-header">
                <span>${f.feature} (${f.impact})</span>
                <span>Weight: ${f.importance_pct}%</span>
            </div>
            <div class="feature-track">
                <div class="feature-fill" style="width: ${Math.min(f.importance_pct * 3.5, 100)}%;"></div>
            </div>
        `;
        container.appendChild(div);
    });
}

// 5. ML Studio & Training
async function initMLStudio() {
    try {
        const res = await fetch("/api/ml-info");
        const meta = await res.json();
        updateMLMetricsDisplay(meta);
    } catch (e) {
        console.error(e);
    }

    const retrainBtn = document.getElementById("retrainBtn");
    if (retrainBtn) {
        retrainBtn.addEventListener("click", async () => {
            showLoading("Retraining LightGBM / Random Forest model on EMBER & Drebin benchmark dataset...");
            try {
                const res = await fetch("/api/train", { method: "POST" });
                const json = await res.json();
                updateMLMetricsDisplay(json.metadata);
                alert("Model re-trained successfully! New accuracy: " + json.metadata.metrics.accuracy + "%");
            } catch (err) {
                alert("Training failed: " + err.message);
            } finally {
                hideLoading();
            }
        });
    }
}

function updateMLMetricsDisplay(meta) {
    if (!meta || !meta.metrics) return;
    document.getElementById("mlAccVal").textContent = `${meta.metrics.accuracy}%`;
    document.getElementById("mlAucVal").textContent = `${meta.metrics.roc_auc}%`;
    document.getElementById("mlPrecVal").textContent = `${meta.metrics.precision}%`;
    document.getElementById("mlRecallVal").textContent = `${meta.metrics.recall}%`;

    const cm = meta.confusion_matrix;
    if (cm) {
        document.getElementById("cmTN").textContent = cm.true_negative;
        document.getElementById("cmFP").textContent = cm.false_positive;
        document.getElementById("cmFN").textContent = cm.false_negative;
        document.getElementById("cmTP").textContent = cm.true_positive;
    }
}

// 6. Report Generator (Task 25)
function renderForensicReport(data) {
    const reportBox = document.getElementById("reportContent");
    if (!reportBox) return;

    reportBox.innerHTML = `
        <div style="border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <h2 style="font-size: 1.4rem; font-weight: 800; color: #0f172a;">STATIC FORENSIC INVESTIGATION REPORT</h2>
                    <p style="font-size: 0.85rem; color: #475569;">Cyber Hackathon 2026 · Organised by C-DAC Patna and CCSU Bihar Police</p>
                    <p style="font-size: 0.85rem; color: #475569;">Investigation Team: Jeeva Shree · Jaya Priya · Pugazhenthi P · U.V. Haswanth</p>
                </div>
                <div style="text-align: right;">
                    <span class="verdict-badge verdict-${data.verdict}">${data.verdict} (${data.risk_score}/100)</span>
                    <p style="font-size: 0.78rem; color: #64748b; margin-top: 4px;">Ref: ${data.sample_id}</p>
                </div>
            </div>
        </div>

        <div style="margin-bottom: 20px;">
            <h4 style="font-size: 1rem; font-weight: 700; margin-bottom: 8px;">1. Executive Summary & Verdict</h4>
            <p style="font-size: 0.88rem; color: #334155; line-height: 1.6;">
                Static examination of sample <strong>${data.file_name}</strong> (${(data.file_size / 1024).toFixed(1)} KB) classifies it as 
                <strong>${data.risk_level}</strong> with an overall threat score of <strong>${data.risk_score} / 100</strong>. 
                Entropy calculation yielded <strong>${data.entropy} / 8.0</strong>. The sample is strictly triaged via static inspection without binary execution, guaranteeing zero host infection risk.
            </p>
        </div>

        <div style="margin-bottom: 20px;">
            <h4 style="font-size: 1rem; font-weight: 700; margin-bottom: 8px;">2. Cryptographic Hashes & File Attributes</h4>
            <table class="data-table" style="font-size: 0.82rem;">
                <tr><td style="width: 140px;"><strong>MD5</strong></td><td><code>${data.md5}</code></td></tr>
                <tr><td><strong>SHA-1</strong></td><td><code>${data.sha1}</code></td></tr>
                <tr><td><strong>SHA-256</strong></td><td><code>${data.sha256}</code></td></tr>
                <tr><td><strong>Package / Type</strong></td><td>${data.summary.package_name || data.file_type}</td></tr>
            </table>
        </div>

        <div style="margin-bottom: 20px;">
            <h4 style="font-size: 1rem; font-weight: 700; margin-bottom: 8px;">3. Key Adverse Findings & Technical Justifications</h4>
            <ul style="padding-left: 20px; font-size: 0.88rem; color: #334155; line-height: 1.6;">
                ${(data.summary.justifications || []).map(j => `<li>${j}</li>`).join("")}
            </ul>
        </div>

        <div style="margin-bottom: 20px;">
            <h4 style="font-size: 1rem; font-weight: 700; margin-bottom: 8px;">4. Extracted Indicators of Compromise (IOCs)</h4>
            <table class="data-table" style="font-size: 0.82rem;">
                <thead><tr><th>Type</th><th>Indicator Value</th><th>Description</th></tr></thead>
                <tbody>
                    ${(data.iocs || []).map(i => `<tr><td><strong>${i.type}</strong></td><td><code>${i.value}</code></td><td>${i.description}</td></tr>`).join("")}
                </tbody>
            </table>
        </div>

        <div style="margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 0.78rem; color: #64748b; text-align: center;">
            Report compiled by Shadow Protocol Automated Static Malware & APK Triage Engine · C-DAC Patna & CCSU Bihar Police Hackathon 2026.
        </div>
    `;
}

// 7. Scan History
async function loadHistory() {
    try {
        const res = await fetch("/api/scans");
        const list = await res.json();
        const tbody = document.getElementById("historyTbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        
        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-muted" style="text-align: center;">No scans recorded yet.</td></tr>`;
            return;
        }

        list.forEach(item => {
            const tr = document.createElement("tr");
            tr.style.cursor = "pointer";
            tr.innerHTML = `
                <td><code>${item.sample_id}</code></td>
                <td><strong>${item.file_name}</strong></td>
                <td>${item.file_type}</td>
                <td><span class="verdict-badge verdict-${item.verdict}" style="font-size:0.75rem; padding: 2px 8px;">${item.verdict} (${item.risk_score})</span></td>
                <td>${new Date(item.created_at).toLocaleTimeString()}</td>
                <td><button class="btn-load-preset" style="padding: 2px 10px;">View</button></td>
            `;
            tr.addEventListener("click", async () => {
                const detRes = await fetch(`/api/scans/${item.sample_id}`);
                const fullData = await detRes.json();
                renderScanResult(fullData);
                switchTab("tab-triage");
            });
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error(e);
    }
}

// Loading Spinner Helpers
function showLoading(msg = "Analyzing...") {
    let overlay = document.getElementById("loadingOverlay");
    if (!overlay) {
        overlay = document.createElement("div");
        overlay.id = "loadingOverlay";
        overlay.style.position = "fixed";
        overlay.style.top = "0";
        overlay.style.left = "0";
        overlay.style.width = "100%";
        overlay.style.height = "100%";
        overlay.style.backgroundColor = "rgba(255, 255, 255, 0.85)";
        overlay.style.backdropFilter = "blur(3px)";
        overlay.style.display = "flex";
        overlay.style.flexDirection = "column";
        overlay.style.alignItems = "center";
        overlay.style.justifyContent = "center";
        overlay.style.zIndex = "9999";
        overlay.innerHTML = `
            <div style="width: 48px; height: 48px; border: 4px solid #e2e8f0; border-top-color: #2563eb; border-radius: 50%; animation: spin 0.8s linear infinite;"></div>
            <p id="loadingMsg" style="margin-top: 16px; font-weight: 600; color: #0f172a; font-size: 0.95rem;"></p>
            <style>@keyframes spin { to { transform: rotate(360deg); } }</style>
        `;
        document.body.appendChild(overlay);
    }
    document.getElementById("loadingMsg").textContent = msg;
    overlay.style.display = "flex";
}

function hideLoading() {
    const overlay = document.getElementById("loadingOverlay");
    if (overlay) overlay.style.display = "none";
}
