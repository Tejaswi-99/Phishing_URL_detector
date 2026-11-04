/**
 * CyberShield PhishGuard - Frontend Application Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const urlForm = document.getElementById("urlForm");
  const urlInput = document.getElementById("urlInput");
  const clearBtn = document.getElementById("clearBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const btnText = analyzeBtn.querySelector(".btn-text");
  const btnSpinner = analyzeBtn.querySelector(".btn-spinner");
  const errorAlert = document.getElementById("errorAlert");
  const errorMessage = document.getElementById("errorMessage");
  const resultsContainer = document.getElementById("resultsContainer");

  // Gauge Elements
  const gaugeProgress = document.getElementById("gaugeProgress");
  const gaugeValue = document.getElementById("gaugeValue");
  const verdictBadge = document.getElementById("verdictBadge");
  const riskLevelText = document.getElementById("riskLevelText");
  const verdictHeading = document.getElementById("verdictHeading");
  const analyzedUrl = document.getElementById("analyzedUrl");
  const copyUrlBtn = document.getElementById("copyUrlBtn");
  const downloadReportBtn = document.getElementById("downloadReportBtn");
  const exportHistoryBtn = document.getElementById("exportHistoryBtn");

  // Metrics
  const metricMlProb = document.getElementById("metricMlProb");
  const metricHeuristic = document.getElementById("metricHeuristic");
  const metricThreatCount = document.getElementById("metricThreatCount");
  const metricTrustCount = document.getElementById("metricTrustCount");

  // Tabs & Lists
  const threatBadgeCount = document.getElementById("threatBadgeCount");
  const trustBadgeCount = document.getElementById("trustBadgeCount");
  const threatList = document.getElementById("threatList");
  const trustList = document.getElementById("trustList");
  const anatomyGrid = document.getElementById("anatomyGrid");
  const featuresTableBody = document.getElementById("featuresTableBody");
  const featureFilter = document.getElementById("featureFilter");
  const recommendationsList = document.getElementById("recommendationsList");
  const historyTableBody = document.getElementById("historyTableBody");
  const clearHistoryBtn = document.getElementById("clearHistoryBtn");

  // Navigation
  const navBtns = document.querySelectorAll(".nav-btn[data-view]");
  const viewSections = document.querySelectorAll(".view-section");

  // Batch Elements
  const batchForm = document.getElementById("batchForm");
  const batchInput = document.getElementById("batchInput");
  const batchSubmitBtn = document.getElementById("batchSubmitBtn");
  const loadSampleBatchBtn = document.getElementById("loadSampleBatchBtn");
  const batchResultsContainer = document.getElementById("batchResultsContainer");
  const batchCount = document.getElementById("batchCount");
  const batchTableBody = document.getElementById("batchTableBody");

  // Modal Elements
  const modelModal = document.getElementById("modelModal");
  const navModelInfo = document.getElementById("navModelInfo");
  const modelModalBody = document.getElementById("modelModalBody");
  const modalCloseBtns = document.querySelectorAll(".modal-close");

  // State
  let currentFeatures = {};
  let lastAnalysisData = null;
  const GAUGE_CIRCUMFERENCE = 515.22; // 2 * PI * 82

  // --- Feature Explanations Glossary ---
  const FEATURE_METADATA = {
    url_length: { type: "Length", desc: "Total character count of the full URL" },
    hostname_length: { type: "Length", desc: "Character length of the hostname / domain component" },
    path_length: { type: "Length", desc: "Character length of the URL path" },
    query_length: { type: "Length", desc: "Character length of parameters after '?'" },
    num_dots: { type: "Count", desc: "Total count of period (.) characters in URL" },
    num_hyphens: { type: "Count", desc: "Count of hyphens (-) used in the full URL" },
    num_hyphens_hostname: { type: "Count", desc: "Hyphens in hostname (common in domain brand spoofing)" },
    num_dots_hostname: { type: "Count", desc: "Periods in hostname denoting subdomain hierarchy" },
    num_subdomains: { type: "Count", desc: "Total number of nested subdomain levels" },
    num_digits: { type: "Count", desc: "Total numeric digit characters in URL" },
    num_digits_hostname: { type: "Count", desc: "Numeric digits in domain name" },
    num_slashes: { type: "Count", desc: "Forward slashes (/) denoting directory depth" },
    num_questionmarks: { type: "Count", desc: "Question marks (?) initiating query parameters" },
    num_equals: { type: "Count", desc: "Equal signs (=) within parameters" },
    num_at: { type: "Security", desc: "'@' symbol used to hijack browser credentials/redirection" },
    num_percent: { type: "Obfuscation", desc: "Percent (%) symbols indicating URL hex encoding" },
    num_ampersands: { type: "Count", desc: "Ampersands (&) joining query key-value pairs" },
    num_underscores: { type: "Count", desc: "Underscore (_) characters" },
    digit_ratio_url: { type: "Ratio", desc: "Ratio of numeric digits to total URL length" },
    digit_ratio_hostname: { type: "Ratio", desc: "Ratio of numeric digits to hostname length" },
    vowel_ratio_domain: { type: "Linguistic", desc: "Ratio of vowels in domain (low in DGA strings)" },
    domain_entropy: { type: "Statistical", desc: "Shannon randomness entropy of domain name" },
    url_entropy: { type: "Statistical", desc: "Shannon randomness entropy across entire URL" },
    is_ip_address: { type: "Security", desc: "Whether hostname is a direct IPv4/IPv6 address" },
    has_port: { type: "Network", desc: "Non-standard web port specified (e.g. :8080)" },
    is_https: { type: "Security", desc: "Protocol uses TLS/SSL encrypted HTTPS" },
    has_double_slash_in_path: { type: "Security", desc: "Presence of '//' in path for open-redirect tricks" },
    is_punycode: { type: "Homograph", desc: "Contains 'xn--' Punycode representation" },
    is_shortened: { type: "Anonymity", desc: "Uses a known URL shortening provider (e.g. bit.ly)" },
    is_suspicious_tld: { type: "Domain", desc: "Uses top-level domain with documented abuse rates" },
    has_hex: { type: "Obfuscation", desc: "Contains hexadecimal encoded characters (%20, etc.)" },
    consecutive_hyphens: { type: "Pattern", desc: "Contains '--' sequence often seen in spoofing" },
    brand_spoofed: { type: "Heuristic", desc: "Recognized brand name located in non-brand domain" },
    keyword_count: { type: "Linguistic", desc: "Count of sensitive terms (login, verify, bank)" },
    has_suspicious_ext: { type: "Malware", desc: "Target path links to executable or archive file" }
  };

  // --- Initial Setup ---
  loadScanHistory();

  // Input Clear Button visibility
  urlInput.addEventListener("input", () => {
    clearBtn.style.display = urlInput.value.trim() ? "block" : "none";
    hideError();
  });

  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    clearBtn.style.display = "none";
    urlInput.focus();
    hideError();
  });

  // Sample Chips
  document.querySelectorAll(".sample-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const sampleUrl = chip.dataset.url;
      urlInput.value = sampleUrl;
      clearBtn.style.display = "block";
      analyzeUrl(sampleUrl);
    });
  });

  // URL Form Submission
  urlForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      showError("Please enter a website URL to analyze.");
      return;
    }
    analyzeUrl(url);
  });

  // Navigation View Switching
  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const view = btn.dataset.view;
      if (!view) return;

      navBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      viewSections.forEach(sec => sec.classList.remove("active"));
      const targetSec = document.getElementById(view === "single" ? "viewSingle" : "viewBatch");
      if (targetSec) targetSec.classList.add("active");
    });
  });

  // Tabs Switching
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetContent = document.getElementById(btn.dataset.tab);
      if (targetContent) targetContent.classList.add("active");
    });
  });

  // Feature Search Filter
  featureFilter.addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    const rows = featuresTableBody.querySelectorAll("tr");
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(term) ? "" : "none";
    });
  });

  // Copy URL Button
  copyUrlBtn.addEventListener("click", () => {
    const text = analyzedUrl.textContent;
    navigator.clipboard.writeText(text).then(() => {
      copyUrlBtn.title = "Copied!";
      setTimeout(() => { copyUrlBtn.title = "Copy URL"; }, 2000);
    });
  });

  // Download Single Analysis Report as JSON
  if (downloadReportBtn) {
    downloadReportBtn.addEventListener("click", () => {
      if (!lastAnalysisData) return;
      const jsonStr = JSON.stringify(lastAnalysisData, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const hostPart = (lastAnalysisData.components.hostname || "report").replace(/[^a-z0-9_.-]/gi, "_");
      a.href = url;
      a.download = `phishguard-report-${hostPart}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  // Export Entire Session History as JSON
  if (exportHistoryBtn) {
    exportHistoryBtn.addEventListener("click", () => {
      const raw = localStorage.getItem("phishguard_history");
      const history = raw ? JSON.parse(raw) : [];
      if (!history.length) {
        alert("No scan history recorded in this session to export.");
        return;
      }
      const jsonStr = JSON.stringify(history, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phishguard-history-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  // Clear History
  clearHistoryBtn.addEventListener("click", () => {
    localStorage.removeItem("phishguard_history");
    renderHistory([]);
  });

  // --- API Analysis Request ---
  async function analyzeUrl(url) {
    setLoading(true);
    hideError();

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      const data = await response.json();

      if (!response.ok || data.status === "error") {
        throw new Error(data.message || "Failed to analyze URL.");
      }

      displayResults(data);
      saveToHistory(data);
    } catch (err) {
      showError(err.message || "Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  // --- Display Results ---
  function displayResults(data) {
    lastAnalysisData = data;
    const assessment = data.assessment;
    const components = data.components;
    const threats = data.threats;
    const trustSignals = data.trust_signals;
    const recommendations = data.recommendations;
    currentFeatures = data.all_features;

    // 1. Reveal container
    resultsContainer.style.display = "flex";

    // 2. Animate Circular Gauge
    animateGauge(assessment.risk_score, assessment.badge_color);

    // 3. Verdict Headers
    verdictBadge.textContent = assessment.verdict;
    verdictBadge.className = `verdict-badge badge-${assessment.badge_color}`;
    riskLevelText.textContent = `${assessment.risk_level} Risk Profile`;
    analyzedUrl.textContent = data.normalized_url;

    if (assessment.badge_color === "danger") {
      verdictHeading.textContent = "High Risk Warning: Phishing Indicators Detected";
      verdictHeading.style.color = "var(--color-danger)";
    } else if (assessment.badge_color === "warning") {
      verdictHeading.textContent = "Caution Advised: Suspicious Patterns Detected";
      verdictHeading.style.color = "var(--color-warning)";
    } else {
      verdictHeading.textContent = "URL Appears Legitimate & Authentic";
      verdictHeading.style.color = "var(--color-safe)";
    }

    // 4. Metrics Strip
    metricMlProb.textContent = `${assessment.ml_probability}%`;
    metricHeuristic.textContent = `${assessment.heuristic_score} / 100`;
    metricThreatCount.textContent = threats.length;
    metricTrustCount.textContent = trustSignals.length;

    // 5. Threats List
    threatBadgeCount.textContent = threats.length;
    if (threats.length === 0) {
      threatList.innerHTML = `<div class="empty-state">No suspicious anomalies or security threat patterns were detected for this URL.</div>`;
    } else {
      threatList.innerHTML = threats.map(t => `
        <div class="threat-card ${t.severity}">
          <div class="threat-header">
            <span class="threat-title">${escapeHtml(t.title)}</span>
            <span class="threat-badge ${t.severity}">${t.severity}</span>
          </div>
          <p class="threat-desc">${escapeHtml(t.description)}</p>
        </div>
      `).join("");
    }

    // 6. Trust Signals List
    trustBadgeCount.textContent = trustSignals.length;
    if (trustSignals.length === 0) {
      trustList.innerHTML = `<div class="empty-state">No positive reputation or security signals verified.</div>`;
    } else {
      trustList.innerHTML = trustSignals.map(s => `
        <div class="trust-card">
          <h5 class="trust-title">✓ ${escapeHtml(s.title)}</h5>
          <p class="trust-desc">${escapeHtml(s.description)}</p>
        </div>
      `).join("");
    }

    // 7. URL Anatomy Grid
    const anatomyItems = [
      { key: "Scheme / Protocol", val: components.scheme, desc: "Network protocol used" },
      { key: "Hostname", val: components.hostname, desc: "Target server host" },
      { key: "Root Domain", val: components.root_domain, desc: "Registered public domain" },
      { key: "Subdomain", val: components.subdomain, desc: "Prefix subdomain levels" },
      { key: "Top-Level Domain", val: `.${components.tld}`, desc: "Domain extension (TLD)" },
      { key: "Target Path", val: components.path, desc: "Server resource route" },
      { key: "Query String", val: components.query, desc: "URL parameter payloads" },
      { key: "Server Port", val: components.port, desc: "Destination connection port" }
    ];

    anatomyGrid.innerHTML = anatomyItems.map(item => `
      <div class="anatomy-card">
        <div class="anatomy-header">
          <span class="anatomy-key">${item.key}</span>
          <span class="anatomy-desc">${item.desc}</span>
        </div>
        <div class="anatomy-val">${escapeHtml(String(item.val))}</div>
      </div>
    `).join("");

    // 8. ML Features Table
    renderFeaturesTable(currentFeatures);

    // 9. Recommendations
    recommendationsList.innerHTML = recommendations.map(rec => `
      <div class="advice-item">
        <svg class="advice-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="9 11 12 14 22 4"/>
          <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
        </svg>
        <span class="advice-text">${escapeHtml(rec)}</span>
      </div>
    `).join("");

    // Scroll smoothly to results
    resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // --- Gauge Animation ---
  function animateGauge(targetScore, badgeColor) {
    let start = 0;
    const duration = 900;
    const startTime = performance.now();

    // Set stroke color
    let strokeColor = "var(--color-safe)";
    if (badgeColor === "warning") strokeColor = "var(--color-warning)";
    if (badgeColor === "danger") strokeColor = "var(--color-danger)";
    gaugeProgress.style.stroke = strokeColor;

    // Calculate offset
    const targetOffset = GAUGE_CIRCUMFERENCE - (targetScore / 100) * GAUGE_CIRCUMFERENCE;
    gaugeProgress.style.strokeDashoffset = targetOffset;

    function step(timestamp) {
      const elapsed = timestamp - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // easeOutCubic
      const ease = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(start + (targetScore - start) * ease);
      gaugeValue.textContent = current;

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        gaugeValue.textContent = targetScore;
      }
    }
    requestAnimationFrame(step);
  }

  // --- Render Features Table ---
  function renderFeaturesTable(features) {
    const keys = Object.keys(features).sort();
    featuresTableBody.innerHTML = keys.map(k => {
      const meta = FEATURE_METADATA[k] || { type: "General", desc: "Numerical feature" };
      const val = features[k];
      let displayVal = val;
      if (typeof val === "number" && !Number.isInteger(val)) {
        displayVal = val.toFixed(4);
      }

      return `
        <tr>
          <td><code class="feature-code">${k}</code></td>
          <td><span class="threat-badge info">${meta.type}</span></td>
          <td class="feature-val">${displayVal}</td>
          <td>${meta.desc}</td>
        </tr>
      `;
    }).join("");
  }

  // --- Batch Scanner Logic ---
  batchForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const raw = batchInput.value.trim();
    if (!raw) return;

    const urls = raw.split("\n").map(u => u.trim()).filter(Boolean);
    if (!urls.length) return;

    batchSubmitBtn.disabled = true;
    batchSubmitBtn.querySelector(".btn-text").textContent = "Analyzing Batch...";
    batchSubmitBtn.querySelector(".btn-spinner").style.display = "inline-block";

    try {
      const res = await fetch("/api/batch-analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls })
      });
      const data = await res.json();

      if (!res.ok || data.status === "error") {
        throw new Error(data.message || "Batch scan failed");
      }

      renderBatchResults(data.results);
    } catch (err) {
      alert("Batch Scan Error: " + err.message);
    } finally {
      batchSubmitBtn.disabled = false;
      batchSubmitBtn.querySelector(".btn-text").textContent = "Run Batch Analysis";
      batchSubmitBtn.querySelector(".btn-spinner").style.display = "none";
    }
  });

  loadSampleBatchBtn.addEventListener("click", () => {
    const sampleBatch = [
      "https://www.google.com",
      "https://github.com/torvalds/linux",
      "http://192.168.1.100/paypal/login.php",
      "http://paypal.com.verify-account.xyz/signin",
      "https://wikipedia.org/wiki/Computer_security",
      "http://www.apple.com@phishing-server.com/auth",
      "http://bit.ly/3xY8a9b",
      "http://xn--gogle-qra.com/login"
    ].join("\n");
    batchInput.value = sampleBatch;
  });

  function renderBatchResults(results) {
    batchResultsContainer.style.display = "block";
    batchCount.textContent = results.length;

    batchTableBody.innerHTML = results.map((r, idx) => {
      if (r.status === "error") {
        return `
          <tr>
            <td>${idx + 1}</td>
            <td><code class="feature-code">${escapeHtml(r.url)}</code></td>
            <td colspan="3" style="color: var(--color-danger); font-style: italic;">Error: ${escapeHtml(r.message)}</td>
            <td>-</td>
          </tr>
        `;
      }

      return `
        <tr>
          <td>${idx + 1}</td>
          <td><code class="feature-code">${escapeHtml(r.url)}</code></td>
          <td style="font-weight: 700;">${r.risk_score}%</td>
          <td><span class="verdict-badge badge-${r.badge_color}">${r.verdict}</span></td>
          <td>${r.threat_count} Flags</td>
          <td>
            <button class="table-rescan-btn" onclick="triggerScanFromTable('${encodeURIComponent(r.url)}')">Inspect</button>
          </td>
        </tr>
      `;
    }).join("");
  }

  // --- Modal Logic (ML Insights) ---
  navModelInfo.addEventListener("click", async () => {
    modelModal.classList.add("active");
    try {
      const res = await fetch("/api/model-info");
      const data = await res.json();
      const metrics = data.metrics || {};
      const topFeatures = metrics.top_features || [];

      modelModalBody.innerHTML = `
        <div class="modal-stat-grid">
          <div class="modal-stat-box">
            <span class="stat-label">Model Accuracy</span>
            <span class="stat-value">${(metrics.accuracy * 100).toFixed(1)}%</span>
          </div>
          <div class="modal-stat-box">
            <span class="stat-label">F1-Score</span>
            <span class="stat-value">${(metrics.f1_score * 100).toFixed(1)}%</span>
          </div>
          <div class="modal-stat-box">
            <span class="stat-label">Precision / Recall</span>
            <span class="stat-value">${(metrics.precision * 100).toFixed(1)}% / ${(metrics.recall * 100).toFixed(1)}%</span>
          </div>
          <div class="modal-stat-box">
            <span class="stat-label">Total Extracted Features</span>
            <span class="stat-value">${data.total_features}</span>
          </div>
        </div>

        <h4 class="section-title">Top 10 Feature Weights (Random Forest)</h4>
        <div class="history-table-wrapper" style="margin-top: 0.5rem;">
          <table class="features-table">
            <thead>
              <tr>
                <th>Feature Name</th>
                <th>Importance</th>
                <th>Category</th>
              </tr>
            </thead>
            <tbody>
              ${topFeatures.map(f => {
                const meta = FEATURE_METADATA[f.feature] || { type: "General" };
                const pct = (f.importance * 100).toFixed(2);
                return `
                  <tr>
                    <td><code class="feature-code">${f.feature}</code></td>
                    <td>
                      <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <div style="flex: 1; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; width: 80px;">
                          <div style="width: ${pct * 3}%; height: 100%; background: var(--accent-cyan); border-radius: 3px;"></div>
                        </div>
                        <span style="font-family: var(--font-mono); font-size: 0.8rem;">${pct}%</span>
                      </div>
                    </td>
                    <td><span class="threat-badge info">${meta.type}</span></td>
                  </tr>
                `;
              }).join("")}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      modelModalBody.innerHTML = `<div class="alert-box alert-error">Failed to load model telemetry: ${err.message}</div>`;
    }
  });

  modalCloseBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      modelModal.classList.remove("active");
    });
  });

  window.addEventListener("click", (e) => {
    if (e.target === modelModal) modelModal.classList.remove("active");
  });

  // --- Scan History Management ---
  function loadScanHistory() {
    const raw = localStorage.getItem("phishguard_history");
    const history = raw ? JSON.parse(raw) : [];
    renderHistory(history);
  }

  function saveToHistory(data) {
    let history = [];
    try {
      history = JSON.parse(localStorage.getItem("phishguard_history")) || [];
    } catch (e) { history = []; }

    // Avoid consecutive duplicates
    if (history.length > 0 && history[0].url === data.input_url) {
      return;
    }

    const item = {
      url: data.input_url,
      verdict: data.assessment.verdict,
      risk_score: data.assessment.risk_score,
      badge_color: data.assessment.badge_color,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    history.unshift(item);
    if (history.length > 15) history.pop();
    localStorage.setItem("phishguard_history", JSON.stringify(history));
    renderHistory(history);
  }

  function renderHistory(history) {
    if (!history.length) {
      historyTableBody.innerHTML = `<tr class="empty-row"><td colspan="5">No scans recorded yet in this session.</td></tr>`;
      return;
    }

    historyTableBody.innerHTML = history.map(item => `
      <tr>
        <td style="color: var(--text-muted); font-size: 0.8rem;">${item.time}</td>
        <td><code class="feature-code" title="${escapeHtml(item.url)}">${truncate(item.url, 45)}</code></td>
        <td><span class="verdict-badge badge-${item.badge_color}">${item.verdict}</span></td>
        <td style="font-weight: 700;">${item.risk_score}%</td>
        <td>
          <button class="table-rescan-btn" onclick="triggerScanFromTable('${encodeURIComponent(item.url)}')">Re-scan</button>
        </td>
      </tr>
    `).join("");
  }

  // Helper function on window for table re-scans
  window.triggerScanFromTable = (encodedUrl) => {
    const url = decodeURIComponent(encodedUrl);
    // Switch to single scan view if not active
    navBtns[0].click();
    urlInput.value = url;
    clearBtn.style.display = "block";
    analyzeUrl(url);
  };

  // --- UI Helpers ---
  function setLoading(isLoading) {
    analyzeBtn.disabled = isLoading;
    if (isLoading) {
      btnText.textContent = "Analyzing...";
      btnSpinner.style.display = "inline-block";
    } else {
      btnText.textContent = "Analyze URL";
      btnSpinner.style.display = "none";
    }
  }

  function showError(msg) {
    errorMessage.textContent = msg;
    errorAlert.style.display = "flex";
  }

  function hideError() {
    errorAlert.style.display = "none";
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function truncate(str, max) {
    if (!str) return "";
    return str.length > max ? str.substring(0, max) + "..." : str;
  }
});
