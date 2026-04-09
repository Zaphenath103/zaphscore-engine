"""ZaphScore — Full Product Frontend. Served at GET /."""

import os

# Payment links from env (with fallback to direct links)
_STRIPE_PRO = os.environ.get(
    "STRIPE_PAYMENT_LINK_PRO",
    "https://buy.stripe.com/aFa28q8hL1tD8d66QxeAg09",
)
_STRIPE_ENT = os.environ.get(
    "STRIPE_PAYMENT_LINK_ENT",
    "https://buy.stripe.com/3cIaEW2Xr3BL3WQ3EleAg0a",
)

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZaphScore — 12-Layer Security Scan in 4 Seconds</title>
<meta name="description" content="Run a free 12-layer security scan on any GitHub repository. Dependencies, SAST, secrets, IaC, containers, SBOM, and more. Upgrade to Pro for continuous monitoring.">
<meta property="og:title" content="ZaphScore — 12-Layer Security Scan in 4 Seconds">
<meta property="og:description" content="Free security scanning for GitHub repos. 12 layers. 4 seconds. Upgrade to Pro for continuous monitoring.">
<meta property="og:url" content="https://zaphscore.zaphenath.app">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<link rel="canonical" href="https://zaphscore.zaphenath.app">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#x1f6e1;</text></svg>">
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#F8F7F4;--surface:#FFFFFF;--border:#D1CFC9;--border-strong:#A09D97;
    --text:#1A1917;--text-muted:#6B6860;--text-faint:#9B9890;
    --red:#C41C1C;--red-bg:#FEF2F2;--red-border:#FECACA;
    --amber:#B45309;--amber-bg:#FFFBEB;--amber-border:#FDE68A;
    --green:#166534;--green-bg:#F0FDF4;--green-border:#BBF7D0;
    --blue:#1D4ED8;--blue-bg:#EFF6FF;
    --dark:#0F0F0E;--mono:'JetBrains Mono','Courier New',monospace;
  }
  html{font-size:13px;scroll-behavior:smooth}
  body{font-family:var(--mono);background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
  .header{background:var(--dark);color:#F8F7F4;padding:10px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:3px solid var(--red);position:sticky;top:0;z-index:100}
  .header-left{display:flex;align-items:center;gap:16px}
  .brand{font-size:16px;font-weight:800;letter-spacing:0.1em;text-transform:uppercase}
  .brand .z{color:var(--red)}.brand .s{color:#F8F7F4}
  .divider{width:1px;height:28px;background:#333;flex-shrink:0}
  .subtitle{font-size:9px;color:#6B6860;letter-spacing:0.08em;text-transform:uppercase}
  .live-badge{display:flex;align-items:center;gap:6px;background:var(--green);color:white;padding:3px 10px;font-size:9px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase}
  .live-dot{width:6px;height:6px;background:white;border-radius:50%;animation:pulse 1.5s infinite}
  .header-right{display:flex;align-items:center;gap:12px;font-size:10px;color:#9B9890}
  .header-time{color:#F8F7F4;font-weight:600}
  .nav-links{display:flex;gap:12px}
  .nav-links a{color:#9B9890;text-decoration:none;font-size:10px;transition:color .2s}
  .nav-links a:hover{color:#F8F7F4}
  .main{max-width:1100px;margin:0 auto;padding:32px 24px}
  .section-label{font-size:9px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:var(--text-faint);margin-bottom:10px;margin-top:32px;display:flex;align-items:center;gap:8px}
  .section-label::after{content:'';flex:1;height:1px;background:var(--border)}
  .hero{text-align:center;margin-bottom:32px}
  h1.hero-title{font-size:32px;font-weight:800;line-height:1.1;margin-bottom:8px}
  h1.hero-title .accent{color:var(--red)}
  .hero-sub{font-size:12px;color:var(--text-muted);max-width:560px;margin:0 auto;line-height:1.6}
  .scan-box{background:var(--dark);border:1px solid #333;padding:32px;margin-bottom:24px}
  .scan-label{font-size:9px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#6B6860;margin-bottom:12px}
  .scan-input-row{display:flex;gap:8px;margin-bottom:4px}
  .scan-input{flex:1;padding:14px 16px;background:#1A1917;border:1px solid #333;color:#F8F7F4;font-family:var(--mono);font-size:13px;outline:none;transition:border-color .2s}
  .scan-input:focus{border-color:var(--red)}
  .scan-input::placeholder{color:#6B6860}
  .scan-input.input-error{border-color:var(--red)}
  .scan-btn{padding:14px 28px;background:var(--red);color:white;border:none;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;transition:background .2s;white-space:nowrap}
  .scan-btn:hover{background:#A11919}
  .scan-btn:disabled{background:#333;color:#6B6860;cursor:not-allowed}
  .input-feedback{font-size:10px;color:var(--red);min-height:18px;margin-bottom:4px;padding-left:2px}
  .scan-hint{font-size:9px;color:#6B6860;letter-spacing:0.06em}
  .scan-hint a{color:#9B9890;text-decoration:none}
  .try-these{margin-top:14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .try-label{font-size:9px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#6B6860}
  .try-chip{padding:4px 12px;border:1px solid #333;color:#9B9890;font-size:10px;font-family:var(--mono);cursor:pointer;transition:all .2s;background:transparent}
  .try-chip:hover{border-color:var(--red);color:#F8F7F4}
  .layers{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-top:16px}
  .layer{display:flex;align-items:center;gap:6px;padding:4px 8px;border:1px solid #333;font-size:9px;color:#9B9890}
  .layer-dot{width:5px;height:5px;border-radius:50%;background:var(--green);flex-shrink:0}
  .progress-box{display:none;background:var(--surface);border:1px solid var(--border);padding:20px;margin-bottom:24px}
  .progress-box.active{display:block}
  .progress-title{font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  .progress-status{font-size:9px;font-weight:700;padding:2px 8px;letter-spacing:0.08em;text-transform:uppercase}
  .status-queued{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}
  .status-running{background:var(--blue-bg);color:var(--blue);border:1px solid #BFDBFE}
  .status-complete{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
  .status-failed{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
  .progress-bar-wrap{height:8px;background:#F3F2EF;margin-bottom:12px;overflow:hidden}
  .progress-bar{height:100%;background:var(--blue);transition:width .5s ease;width:0}
  .progress-bar.done{background:var(--green)}.progress-bar.fail{background:var(--red)}
  .progress-log{font-size:10px;color:var(--text-muted);line-height:1.8;max-height:160px;overflow-y:auto}
  .log-line{display:flex;gap:8px}.log-time{color:var(--text-faint);flex-shrink:0;font-size:9px;min-width:60px}
  .results-box{display:none;background:var(--surface);border:1px solid var(--border);margin-bottom:24px}
  .results-box.active{display:block}
  .results-header{padding:20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  .results-repo{font-size:13px;font-weight:600}
  .results-meta{font-size:10px;color:var(--text-muted);margin-top:2px}
  .results-score-wrap{text-align:center}
  .results-score{font-size:48px;font-weight:800;line-height:1}
  .results-score-label{font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.1em}
  .results-summary{display:grid;grid-template-columns:repeat(5,1fr);border-bottom:1px solid var(--border)}
  .summary-cell{padding:14px;text-align:center;border-right:1px solid var(--border)}
  .summary-cell:last-child{border-right:none}
  .summary-count{font-size:22px;font-weight:700;line-height:1}
  .summary-label{font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
  .count-critical{color:var(--red)}.count-high{color:#D97706}.count-medium{color:var(--amber)}.count-low{color:var(--blue)}.count-info{color:var(--text-faint)}
  .fearscore-bar{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px}
  .fearscore-label{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-muted);flex-shrink:0}
  .fearscore-track{flex:1;height:12px;background:#F3F2EF;position:relative;overflow:hidden}
  .fearscore-fill{height:100%;transition:width .8s ease}
  .fearscore-value{font-size:18px;font-weight:800;flex-shrink:0;min-width:50px;text-align:right}
  .fearscore-msg{font-size:10px;color:var(--text-muted);padding:0 20px 12px;border-bottom:1px solid var(--border)}
  .findings-list{padding:16px 20px;max-height:400px;overflow-y:auto}
  .finding-item{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:11px}
  .finding-item:last-child{border-bottom:none}
  .finding-sev{font-size:8px;font-weight:700;padding:2px 6px;text-transform:uppercase;letter-spacing:.06em;flex-shrink:0;margin-top:2px}
  .sev-critical{background:var(--red);color:white}.sev-high{background:#D97706;color:white}
  .sev-medium{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}
  .sev-low{background:var(--blue-bg);color:var(--blue);border:1px solid #BFDBFE}
  .sev-info{background:#F3F2EF;color:var(--text-muted);border:1px solid var(--border)}
  .finding-body{flex:1}.finding-title{font-weight:600}.finding-desc{font-size:10px;color:var(--text-muted);margin-top:2px}
  .finding-file{font-size:9px;color:var(--text-faint);margin-top:2px}
  .upgrade-cta{padding:20px;background:var(--dark);color:#F8F7F4;text-align:center}
  .upgrade-cta-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#9B9890;margin-bottom:8px}
  .upgrade-cta-text{font-size:12px;margin-bottom:14px;color:#F8F7F4;line-height:1.5}
  .upgrade-cta-text strong{color:var(--red)}
  .upgrade-cta-btn{display:inline-block;padding:10px 24px;background:var(--red);color:white;text-decoration:none;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;transition:background .2s}
  .upgrade-cta-btn:hover{background:#A11919}
  .pricing-toggle{text-align:center;margin-bottom:20px}
  .toggle-wrap{display:inline-flex;align-items:center;gap:10px;font-size:11px;color:var(--text-muted)}
  .toggle-switch{position:relative;width:44px;height:22px;background:var(--border);border-radius:11px;cursor:pointer;transition:background .3s}
  .toggle-switch.active{background:var(--green)}
  .toggle-knob{position:absolute;top:2px;left:2px;width:18px;height:18px;background:white;border-radius:50%;transition:left .3s}
  .toggle-switch.active .toggle-knob{left:24px}
  .toggle-label{font-weight:600;cursor:pointer}
  .toggle-label.active{color:var(--text)}
  .save-badge{font-size:9px;font-weight:700;background:var(--green-bg);color:var(--green);border:1px solid var(--green-border);padding:1px 6px;letter-spacing:.06em;text-transform:uppercase}
  .pricing-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
  .price-card{background:var(--surface);border:1px solid var(--border);padding:24px;position:relative;display:flex;flex-direction:column}
  .price-card.featured{border-color:var(--red);border-width:2px}
  .price-card.featured::before{content:'MOST POPULAR';position:absolute;top:-11px;left:50%;transform:translateX(-50%);background:var(--red);color:white;font-size:8px;font-weight:700;padding:2px 10px;letter-spacing:.12em;text-transform:uppercase}
  .price-name{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-muted);margin-bottom:12px}
  .price-amount{font-size:36px;font-weight:800;line-height:1;margin-bottom:4px}
  .price-amount .currency{font-size:18px;vertical-align:top;color:var(--text-muted)}
  .price-amount .period{font-size:12px;font-weight:400;color:var(--text-muted)}
  .price-original{font-size:11px;color:var(--text-faint);text-decoration:line-through;height:16px;margin-bottom:8px}
  .price-desc{font-size:10px;color:var(--text-muted);margin-bottom:16px;line-height:1.5}
  .price-features{list-style:none;margin-bottom:20px;flex:1}
  .price-features li{font-size:10px;padding:4px 0;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px}
  .price-features li:last-child{border-bottom:none}
  .feat-check{color:var(--green);font-weight:700;flex-shrink:0}
  .feat-x{color:var(--border);flex-shrink:0}
  .price-btn{display:block;padding:12px;text-align:center;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;text-decoration:none;transition:all .2s;border:none;cursor:pointer;width:100%}
  .btn-free{background:var(--surface);color:var(--text);border:1px solid var(--border)}
  .btn-free:hover{background:#F3F2EF}
  .btn-pro{background:var(--red);color:white}
  .btn-pro:hover{background:#A11919}
  .btn-ent{background:var(--dark);color:#F8F7F4}
  .btn-ent:hover{background:#1A1917}
  .proof-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px}
  .proof-card{background:var(--surface);border:1px solid var(--border);padding:16px;text-align:center}
  .proof-value{font-size:24px;font-weight:700;line-height:1}
  .proof-label{font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
  .footer{text-align:center;padding:24px;font-size:10px;color:var(--text-faint);border-top:1px solid var(--border);margin-top:16px}
  .footer a{color:var(--text-muted);text-decoration:none}.footer a:hover{color:var(--text)}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  @keyframes scan-sweep{0%{background-position:200% 0}100%{background-position:-200% 0}}
  .scanning .progress-bar{background:linear-gradient(90deg,var(--blue) 0%,#60A5FA 50%,var(--blue) 100%);background-size:200% 100%;animation:scan-sweep 1.5s ease-in-out infinite}
  @keyframes shimmer{0%{background-position:-400px 0}100%{background-position:400px 0}}
  .shimmer-box{display:none;background:var(--surface);border:1px solid var(--border);padding:24px;margin-bottom:24px}
  .shimmer-box.active{display:block}
  .shimmer-line{height:14px;margin-bottom:12px;background:linear-gradient(90deg,#F3F2EF 25%,#E8E7E3 37%,#F3F2EF 63%);background-size:800px 100%;animation:shimmer 1.6s ease-in-out infinite;border-radius:2px}
  .shimmer-line.w60{width:60%}.shimmer-line.w80{width:80%}.shimmer-line.w40{width:40%}.shimmer-line.w70{width:70%}
  .shimmer-score{width:80px;height:80px;margin:0 auto 16px;background:linear-gradient(90deg,#F3F2EF 25%,#E8E7E3 37%,#F3F2EF 63%);background-size:800px 100%;animation:shimmer 1.6s ease-in-out infinite;border-radius:4px}
  .shimmer-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-top:16px}
  .shimmer-cell{height:50px;background:linear-gradient(90deg,#F3F2EF 25%,#E8E7E3 37%,#F3F2EF 63%);background-size:800px 100%;animation:shimmer 1.6s ease-in-out infinite;border-radius:2px}
  @media(max-width:1024px){.pricing-grid{grid-template-columns:1fr}.proof-row{grid-template-columns:repeat(2,1fr)}}
  @media(max-width:768px){.layers{grid-template-columns:repeat(2,1fr)}.results-summary{grid-template-columns:repeat(3,1fr)}.hero-title{font-size:22px}.scan-input-row{flex-direction:column}.header{flex-direction:column;gap:8px;align-items:flex-start}.proof-row{grid-template-columns:1fr 1fr}.shimmer-grid{grid-template-columns:repeat(3,1fr)}}
  @media(max-width:480px){.layers{grid-template-columns:1fr 1fr}.results-summary{grid-template-columns:1fr 1fr}.pricing-grid{grid-template-columns:1fr}.price-amount{font-size:28px}.shimmer-grid{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <div class="brand"><span class="z">ZAPH</span><span class="s">SCORE</span></div>
    <div class="divider"></div>
    <div class="subtitle">Security Intelligence Engine</div>
    <div class="divider"></div>
    <div class="live-badge"><div class="live-dot"></div> LIVE</div>
  </div>
  <div class="header-right">
    <div class="nav-links"><a href="#scan">Scan</a><a href="#pricing">Pricing</a><a href="/docs">API</a></div>
    <div class="divider"></div>
    <div class="header-time" id="clock">--:--:-- UTC</div>
    <div class="divider"></div>
    <a href="https://zaphenath.app" style="color:#9B9890;text-decoration:none;font-size:10px;">zaphenath.app</a>
  </div>
</div>
<div class="main">
  <div class="hero" id="scan">
    <h1 class="hero-title">Know Your <span class="accent">Score</span> Before They Do</h1>
    <div class="hero-sub">12-layer security scan on any GitHub repository. Dependencies, SAST, secrets, IaC, containers, SBOM, and more. Free tier forever. Results in seconds.</div>
  </div>
  <div class="scan-box">
    <div class="scan-label">Enter a GitHub Repository URL or owner/repo</div>
    <div class="scan-input-row">
      <input type="text" class="scan-input" id="repoInput" placeholder="https://github.com/owner/repo  or  owner/repo" autocomplete="off" spellcheck="false">
      <button class="scan-btn" id="scanBtn" onclick="startScan()">&#9654; SCAN FREE</button>
    </div>
    <div class="input-feedback" id="inputFeedback"></div>
    <div class="scan-hint">Accepts any public GitHub repository — paste the full URL or type <strong>owner/repo</strong> &middot; Free tier: 3 scans/day &middot; <a href="/docs" target="_blank">API Docs</a></div>
    <div class="try-these">
      <span class="try-label">Try these:</span>
      <span class="try-chip" onclick="fillRepo('facebook/react')">facebook/react</span>
      <span class="try-chip" onclick="fillRepo('vercel/next.js')">vercel/next.js</span>
      <span class="try-chip" onclick="fillRepo('expressjs/express')">expressjs/express</span>
    </div>
    <div class="layers">
      <div class="layer"><div class="layer-dot"></div> Dependencies</div>
      <div class="layer"><div class="layer-dot"></div> SAST Analysis</div>
      <div class="layer"><div class="layer-dot"></div> Secret Detection</div>
      <div class="layer"><div class="layer-dot"></div> IaC Config</div>
      <div class="layer"><div class="layer-dot"></div> Containers</div>
      <div class="layer"><div class="layer-dot"></div> SBOM Generation</div>
      <div class="layer"><div class="layer-dot"></div> License Audit</div>
      <div class="layer"><div class="layer-dot"></div> Code Quality</div>
      <div class="layer"><div class="layer-dot"></div> Fix Suggestions</div>
      <div class="layer"><div class="layer-dot"></div> CVE Matching</div>
      <div class="layer"><div class="layer-dot"></div> Supply Chain</div>
      <div class="layer"><div class="layer-dot"></div> Risk Score</div>
    </div>
  </div>
  <div class="progress-box" id="progressBox">
    <div class="progress-title"><span>Scanning <span id="progressRepo">...</span></span><span class="progress-status status-queued" id="progressStatus">QUEUED</span></div>
    <div class="progress-bar-wrap"><div class="progress-bar" id="progressBar"></div></div>
    <div class="progress-log" id="progressLog"></div>
  </div>
  <div class="shimmer-box" id="shimmerBox">
    <div class="shimmer-score"></div>
    <div class="shimmer-line w80"></div>
    <div class="shimmer-line w60"></div>
    <div class="shimmer-line w70"></div>
    <div class="shimmer-grid">
      <div class="shimmer-cell"></div>
      <div class="shimmer-cell"></div>
      <div class="shimmer-cell"></div>
      <div class="shimmer-cell"></div>
      <div class="shimmer-cell"></div>
    </div>
    <div class="shimmer-line w40" style="margin-top:16px"></div>
    <div class="shimmer-line w80"></div>
    <div class="shimmer-line w60"></div>
  </div>
  <div class="results-box" id="resultsBox">
    <div class="results-header">
      <div><div class="results-repo" id="resultsRepo">owner/repo</div><div class="results-meta" id="resultsBranch">branch: main</div></div>
      <div class="results-score-wrap"><div class="results-score" id="resultsScore">--</div><div class="results-score-label">ZaphScore</div></div>
    </div>
    <div class="fearscore-bar" id="fearscoreBar" style="display:none">
      <div class="fearscore-label">FearScore</div>
      <div class="fearscore-track"><div class="fearscore-fill" id="fearscoreFill"></div></div>
      <div class="fearscore-value" id="fearscoreValue">--</div>
    </div>
    <div class="fearscore-msg" id="fearscoreMsg" style="display:none"></div>
    <div class="results-summary" id="resultsSummary"></div>
    <div class="findings-list" id="findingsList"></div>
    <div class="upgrade-cta" id="upgradeCta" style="display:none">
      <div class="upgrade-cta-title">Unlock Continuous Protection</div>
      <div class="upgrade-cta-text">Your repo has vulnerabilities. Free scans show the problem — <strong>Pro monitoring fixes it</strong>. Get daily scans, Slack alerts, fix PRs, and priority support.</div>
      <a href="{{STRIPE_PRO}}" class="upgrade-cta-btn" target="_blank">&#9654; Upgrade to Pro — $19/mo</a>
    </div>
  </div>
  <div class="proof-row">
    <div class="proof-card"><div class="proof-value" style="color:var(--red)">12</div><div class="proof-label">Security Layers</div></div>
    <div class="proof-card"><div class="proof-value" style="color:var(--green)">&lt;4s</div><div class="proof-label">Avg Scan Time</div></div>
    <div class="proof-card"><div class="proof-value">47</div><div class="proof-label">Avg Findings/Repo</div></div>
    <div class="proof-card"><div class="proof-value" style="color:var(--red)">194d</div><div class="proof-label">Avg Time to Discover</div></div>
  </div>
  <div class="section-label" id="pricing">Pricing — Choose Your Security Posture</div>
  <div class="pricing-toggle">
    <div class="toggle-wrap">
      <span class="toggle-label active" id="monthlyLabel" onclick="setPricing('monthly')">Monthly</span>
      <div class="toggle-switch" id="pricingToggle" onclick="togglePricing()"><div class="toggle-knob"></div></div>
      <span class="toggle-label" id="yearlyLabel" onclick="setPricing('yearly')">Yearly</span>
      <span class="save-badge">SAVE 10%</span>
    </div>
  </div>
  <div class="pricing-grid">
    <div class="price-card">
      <div class="price-name">Free</div>
      <div class="price-amount"><span class="currency">$</span>0<span class="period">/forever</span></div>
      <div class="price-original">&nbsp;</div>
      <div class="price-desc">Get started with basic security scanning. See what is in your repos before attackers do.</div>
      <ul class="price-features">
        <li><span class="feat-check">&#10003;</span> 3 scans per day</li>
        <li><span class="feat-check">&#10003;</span> 12-layer analysis</li>
        <li><span class="feat-check">&#10003;</span> ZaphScore rating</li>
        <li><span class="feat-check">&#10003;</span> FearScore assessment</li>
        <li><span class="feat-check">&#10003;</span> Basic findings report</li>
        <li><span class="feat-x">—</span> <span style="color:var(--text-faint)">Continuous monitoring</span></li>
        <li><span class="feat-x">—</span> <span style="color:var(--text-faint)">Slack/webhook alerts</span></li>
        <li><span class="feat-x">—</span> <span style="color:var(--text-faint)">Auto-fix PRs</span></li>
      </ul>
      <a href="#scan" class="price-btn btn-free">&#9654; Scan Free Now</a>
    </div>
    <div class="price-card featured">
      <div class="price-name">Pro</div>
      <div class="price-amount" id="proPrice"><span class="currency">$</span>19<span class="period">/mo</span></div>
      <div class="price-original" id="proOriginal">&nbsp;</div>
      <div class="price-desc">Continuous security monitoring for teams that ship fast. Daily scans, instant alerts, and auto-fix suggestions.</div>
      <ul class="price-features">
        <li><span class="feat-check">&#10003;</span> Unlimited scans</li>
        <li><span class="feat-check">&#10003;</span> 12-layer deep analysis</li>
        <li><span class="feat-check">&#10003;</span> ZaphScore + FearScore</li>
        <li><span class="feat-check">&#10003;</span> Daily automated scans</li>
        <li><span class="feat-check">&#10003;</span> Slack + webhook alerts</li>
        <li><span class="feat-check">&#10003;</span> Fix suggestion PRs</li>
        <li><span class="feat-check">&#10003;</span> Priority scan queue</li>
        <li><span class="feat-x">—</span> <span style="color:var(--text-faint)">Custom policies</span></li>
      </ul>
      <a href="{{STRIPE_PRO}}" class="price-btn btn-pro" id="proCta" target="_blank">&#9654; Start Pro</a>
    </div>
    <div class="price-card">
      <div class="price-name">Enterprise</div>
      <div class="price-amount" id="entPrice"><span class="currency">$</span>49<span class="period">/mo</span></div>
      <div class="price-original" id="entOriginal">&nbsp;</div>
      <div class="price-desc">Full security posture management. Custom policies, compliance reports, team dashboards, and dedicated support.</div>
      <ul class="price-features">
        <li><span class="feat-check">&#10003;</span> Everything in Pro</li>
        <li><span class="feat-check">&#10003;</span> Unlimited repos</li>
        <li><span class="feat-check">&#10003;</span> Custom security policies</li>
        <li><span class="feat-check">&#10003;</span> Compliance reports (SOC2)</li>
        <li><span class="feat-check">&#10003;</span> Team dashboard</li>
        <li><span class="feat-check">&#10003;</span> SBOM export</li>
        <li><span class="feat-check">&#10003;</span> API access (unlimited)</li>
        <li><span class="feat-check">&#10003;</span> Dedicated support</li>
      </ul>
      <a href="{{STRIPE_ENT}}" class="price-btn btn-ent" id="entCta" target="_blank">&#9654; Start Enterprise</a>
    </div>
  </div>
</div>
<div class="footer">
  ZaphScore &middot; A <a href="https://zaphenath.app">Zaphenath</a> Security Product &middot; <span id="yr">2026</span>
  <br><a href="/docs">API Docs</a> &middot; <a href="/health">Status</a> &middot; <a href="https://zaphenath.app/privacy">Privacy</a> &middot; <a href="https://zaphenath.app/terms">Terms</a>
</div>
<script>
function tick(){var n=new Date(),h=String(n.getUTCHours()).padStart(2,'0'),m=String(n.getUTCMinutes()).padStart(2,'0'),s=String(n.getUTCSeconds()).padStart(2,'0');document.getElementById('clock').textContent=h+':'+m+':'+s+' UTC'}
tick();setInterval(tick,1000);
document.getElementById('yr').textContent=new Date().getFullYear();
var isYearly=false;
var STRIPE_PRO='{{STRIPE_PRO}}';
var STRIPE_ENT='{{STRIPE_ENT}}';
function togglePricing(){isYearly=!isYearly;renderPricing()}
function setPricing(mode){isYearly=(mode==='yearly');renderPricing()}
function renderPricing(){
  var t=document.getElementById('pricingToggle'),ml=document.getElementById('monthlyLabel'),yl=document.getElementById('yearlyLabel');
  if(isYearly){t.classList.add('active');yl.classList.add('active');ml.classList.remove('active')}
  else{t.classList.remove('active');ml.classList.add('active');yl.classList.remove('active')}
  if(isYearly){
    document.getElementById('proPrice').innerHTML='<span class="currency">$</span>17<span class="period">/mo</span>';
    document.getElementById('proOriginal').innerHTML='$205/yr billed annually (save $23)';
    document.getElementById('entPrice').innerHTML='<span class="currency">$</span>44<span class="period">/mo</span>';
    document.getElementById('entOriginal').innerHTML='$529/yr billed annually (save $59)';
  }else{
    document.getElementById('proPrice').innerHTML='<span class="currency">$</span>19<span class="period">/mo</span>';
    document.getElementById('proOriginal').innerHTML='&nbsp;';
    document.getElementById('entPrice').innerHTML='<span class="currency">$</span>49<span class="period">/mo</span>';
    document.getElementById('entOriginal').innerHTML='&nbsp;';
  }
}
function fillRepo(repo){
  document.getElementById('repoInput').value=repo;
  clearFeedback();
  document.getElementById('repoInput').focus();
}
function clearFeedback(){
  document.getElementById('inputFeedback').textContent='';
  document.getElementById('repoInput').classList.remove('input-error');
}
function showFeedback(msg){
  document.getElementById('inputFeedback').textContent=msg;
  document.getElementById('repoInput').classList.add('input-error');
}
function validateInput(val){
  if(!val||!val.trim()){showFeedback('Enter a GitHub repository to scan');return false}
  val=val.trim();
  // Strip protocol and github.com prefix for validation
  var cleaned=val.replace(/^https?:\/\/(www\.)?github\.com\//,'').replace(/\/+$/,'').replace(/\.git$/,'');
  // If it looks like a full URL to something else, let it through
  if(val.startsWith('http')&&!val.match(/github\.com/)){showFeedback('Only GitHub repositories are supported');return false}
  // Check for invalid characters
  if(cleaned.match(/[^a-zA-Z0-9_.\/\-]/)){showFeedback('Invalid repository format');return false}
  // Just a username, no slash
  if(cleaned.match(/^[a-zA-Z0-9_.\-]+$/)&&!cleaned.includes('/')){showFeedback('Enter owner/repo format (e.g. '+cleaned+'/repo-name)');return false}
  clearFeedback();
  return true;
}
function friendlyError(msg){
  if(!msg)return'Something went wrong. Please check the repo URL and try again.';
  var lower=msg.toLowerCase();
  if(lower.indexOf('clone')!==-1||lower.indexOf('clone failed')!==-1)return'Could not access this repository. Make sure it is a public GitHub repo in owner/repo format.';
  if(lower.indexOf('500')!==-1||lower.indexOf('internal server')!==-1)return'Our scanning engine is warming up. Please try again in a moment.';
  if(lower.indexOf('rate limit')!==-1||lower.indexOf('rate_limit')!==-1||lower.indexOf('429')!==-1)return'You have used your free scans for today. Upgrade to Pro for unlimited scans.';
  if(lower.indexOf('not found')!==-1||lower.indexOf('404')!==-1)return'Repository not found. Make sure the repo exists and is public.';
  if(lower.indexOf('timeout')!==-1)return'The scan timed out. This repo may be very large. Try again or upgrade to Pro for priority scanning.';
  return'Something went wrong. Please check the repo URL and try again.';
}
document.getElementById('repoInput').addEventListener('keydown',function(e){if(e.key==='Enter')startScan()});
document.getElementById('repoInput').addEventListener('input',function(){clearFeedback()});
function normalizeRepo(input){
  input=input.trim().replace(/\/+$/,'').replace(/\.git$/,'');
  // Strip protocol and github.com prefix if present
  input=input.replace(/^https?:\/\/(www\.)?github\.com\//,'');
  // Now input should be "owner/repo" or just "owner"
  // Validate it's owner/repo format
  if(/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(input))return'https://github.com/'+input;
  // If just "owner" (no slash), show helpful error
  if(/^[a-zA-Z0-9_.-]+$/.test(input)){showFeedback('Enter owner/repo format (e.g. '+input+'/repo-name)');return null}
  // If it's already a full URL to something else, pass through
  if(input.startsWith('http'))return input;
  return'https://github.com/'+input;
}
var currentScanId=null;
function log(msg){var el=document.getElementById('progressLog'),now=new Date(),ts=String(now.getUTCHours()).padStart(2,'0')+':'+String(now.getUTCMinutes()).padStart(2,'0')+':'+String(now.getUTCSeconds()).padStart(2,'0');el.innerHTML+='<div class="log-line"><span class="log-time">'+ts+'</span><span class="log-msg">'+msg+'</span></div>';el.scrollTop=el.scrollHeight}
function setStatus(s){var el=document.getElementById('progressStatus');el.textContent=s.toUpperCase();el.className='progress-status status-'+s}
function calcFearScore(s){if(!s)return 0;var c=s.critical||0,h=s.high||0,m=s.medium||0,l=s.low||0,raw=c*10+h*6+m*3+l;var score=Math.min(10,Math.round(raw/5*10)/10);if(score<1&&(c+h+m+l)>0)score=1;return score}
function fearColor(s){return s>=8?'var(--red)':s>=5?'var(--amber)':s>=3?'#D97706':'var(--green)'}
function fearMsg(s){if(s>=9)return'CRITICAL EXPOSURE — Your repository is actively dangerous. Immediate remediation required. Attackers with AI tools will find these in minutes.';if(s>=7)return'HIGH RISK — Significant vulnerabilities detected. Your security posture is weaker than 80% of scanned repos. Upgrade to Pro for continuous monitoring.';if(s>=5)return'MODERATE RISK — Several issues found. Daily scanning would catch these before they escalate.';if(s>=3)return'LOW RISK — Minor issues detected. Your repo is in better shape than most.';return'MINIMAL RISK — Clean scan. Keep it that way with continuous monitoring.'}
function showShimmer(){document.getElementById('shimmerBox').className='shimmer-box active'}
function hideShimmer(){document.getElementById('shimmerBox').className='shimmer-box'}
function startScan(){
  var input=document.getElementById('repoInput').value;
  if(!validateInput(input)){document.getElementById('repoInput').focus();return}
  var url=normalizeRepo(input);if(!url){return}
  var btn=document.getElementById('scanBtn');btn.disabled=true;btn.textContent='SCANNING...';
  document.getElementById('progressBox').className='progress-box active';document.getElementById('resultsBox').className='results-box';
  document.getElementById('progressLog').innerHTML='';document.getElementById('progressBar').style.width='0';
  document.getElementById('progressBar').className='progress-bar';document.getElementById('progressBox').classList.remove('scanning');
  document.getElementById('progressRepo').textContent=url.replace('https://github.com/','');
  document.getElementById('fearscoreBar').style.display='none';document.getElementById('fearscoreMsg').style.display='none';
  document.getElementById('upgradeCta').style.display='none';setStatus('queued');
  showShimmer();
  log('Submitting scan for '+url+'...');
  fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repo_url:url})})
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()})
  .then(function(d){currentScanId=d.scan_id;log('Scan queued: '+d.scan_id.substring(0,8)+'...');log('Initializing 12-layer analysis pipeline...');document.getElementById('progressBar').style.width='10%';document.getElementById('progressBox').classList.add('scanning');pollScan()})
  .catch(function(e){log(friendlyError(e.message));setStatus('failed');hideShimmer();btn.disabled=false;btn.textContent='\u25B6 SCAN FREE'})
}
function pollScan(){
  if(!currentScanId)return;
  fetch('/api/scans/'+currentScanId).then(function(r){return r.json()}).then(function(d){
    setStatus(d.status);
    if(d.status==='running'){document.getElementById('progressBar').style.width='50%';log('Analyzing: dependencies, SAST, secrets, IaC, containers...');setTimeout(pollScan,2000)}
    else if(d.status==='complete'){document.getElementById('progressBox').classList.remove('scanning');document.getElementById('progressBar').style.width='100%';document.getElementById('progressBar').classList.add('done');log('Scan complete!');hideShimmer();showResults(d);document.getElementById('scanBtn').disabled=false;document.getElementById('scanBtn').textContent='\u25B6 SCAN FREE'}
    else if(d.status==='failed'){document.getElementById('progressBox').classList.remove('scanning');document.getElementById('progressBar').style.width='100%';document.getElementById('progressBar').classList.add('fail');log(friendlyError(d.error||''));hideShimmer();document.getElementById('scanBtn').disabled=false;document.getElementById('scanBtn').textContent='\u25B6 SCAN FREE'}
    else{document.getElementById('progressBar').style.width='15%';setTimeout(pollScan,2000)}
  }).catch(function(e){log('Poll error: '+e.message);setTimeout(pollScan,3000)})
}
function showResults(d){
  document.getElementById('resultsBox').className='results-box active';
  document.getElementById('resultsRepo').textContent=d.repo_url.replace('https://github.com/','');
  document.getElementById('resultsBranch').textContent='branch: '+(d.branch||'main');
  var score=d.score||0,se=document.getElementById('resultsScore');se.textContent=score;
  se.style.color=score>=80?'var(--green)':score>=50?'var(--amber)':'var(--red)';
  var s=d.summary||{},fear=calcFearScore(s);
  document.getElementById('fearscoreBar').style.display='flex';
  document.getElementById('fearscoreFill').style.width=(fear*10)+'%';
  document.getElementById('fearscoreFill').style.background=fearColor(fear);
  document.getElementById('fearscoreValue').textContent=fear+'/10';
  document.getElementById('fearscoreValue').style.color=fearColor(fear);
  document.getElementById('fearscoreMsg').style.display='block';
  document.getElementById('fearscoreMsg').textContent=fearMsg(fear);
  document.getElementById('resultsSummary').innerHTML='<div class="summary-cell"><div class="summary-count count-critical">'+(s.critical||0)+'</div><div class="summary-label">Critical</div></div><div class="summary-cell"><div class="summary-count count-high">'+(s.high||0)+'</div><div class="summary-label">High</div></div><div class="summary-cell"><div class="summary-count count-medium">'+(s.medium||0)+'</div><div class="summary-label">Medium</div></div><div class="summary-cell"><div class="summary-count count-low">'+(s.low||0)+'</div><div class="summary-label">Low</div></div><div class="summary-cell"><div class="summary-count count-info">'+(s.total_findings||0)+'</div><div class="summary-label">Total</div></div>';
  var fl=d.findings||[],fEl=document.getElementById('findingsList');
  if(fl.length===0){fEl.innerHTML='<div style="padding:16px;text-align:center;color:var(--text-muted);font-size:11px">'+(s.total_findings||0)+' findings detected. <a href="/api/scans/'+d.scan_id+'" style="color:var(--blue)" target="_blank">View full report &#8594;</a></div>'}
  else{var h='';fl.slice(0,50).forEach(function(f){h+='<div class="finding-item"><span class="finding-sev sev-'+(f.severity||'info').toLowerCase()+'">'+(f.severity||'INFO')+'</span><div class="finding-body"><div class="finding-title">'+(f.title||'Untitled')+'</div>'+(f.description?'<div class="finding-desc">'+f.description+'</div>':'')+(f.file_path?'<div class="finding-file">'+f.file_path+(f.line?':'+f.line:'')+'</div>':'')+'</div></div>'});fEl.innerHTML=h}
  if((s.total_findings||0)>0)document.getElementById('upgradeCta').style.display='block';
  document.getElementById('resultsBox').scrollIntoView({behavior:'smooth',block:'start'})
}
</script>
</body>
</html>"""

SCAN_PAGE_HTML = (
    _TEMPLATE
    .replace("{{STRIPE_PRO}}", _STRIPE_PRO)
    .replace("{{STRIPE_ENT}}", _STRIPE_ENT)
)
