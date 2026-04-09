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
# Annual links — create Stripe Payment Links for $205/yr and $529/yr, then add
# STRIPE_PAYMENT_LINK_PRO_ANNUAL and STRIPE_PAYMENT_LINK_ENT_ANNUAL to Vercel env vars.
# Falls back to monthly links until annual products are created.
_STRIPE_PRO_ANNUAL = os.environ.get("STRIPE_PAYMENT_LINK_PRO_ANNUAL", _STRIPE_PRO)
_STRIPE_ENT_ANNUAL = os.environ.get("STRIPE_PAYMENT_LINK_ENT_ANNUAL", _STRIPE_ENT)

# Supabase auth — set SUPABASE_URL and SUPABASE_ANON_KEY in Vercel env vars
# Anon key is safe to expose in frontend (it's designed for this)
_SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
_SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")

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
<meta property="og:image" content="https://zaphscore.zaphenath.app/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:type" content="image/png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="ZaphScore — 12-Layer Security Scan in 4 Seconds">
<meta name="twitter:description" content="Free security scanning for GitHub repos. 12 layers. 4 seconds. Upgrade to Pro for continuous monitoring.">
<meta name="twitter:image" content="https://zaphscore.zaphenath.app/og-image.png">
<meta name="twitter:image:alt" content="ZaphScore — 12-Layer Security Scan. Free for any GitHub repo.">
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
  /* AUTH MODAL */
  .auth-overlay{display:none;position:fixed;inset:0;z-index:9000;background:rgba(15,15,14,.97);align-items:center;justify-content:center;padding:20px;}
  .auth-overlay.open{display:flex;}
  .auth-card{width:100%;max-width:420px;position:relative;}
  .auth-close{position:absolute;top:-36px;right:0;background:transparent;border:none;color:#4A4845;font-family:var(--mono);font-size:11px;cursor:pointer;letter-spacing:.08em;}
  .auth-close:hover{color:#9B9890;}
  .auth-logo{text-align:center;margin-bottom:28px;}
  .auth-logo-text{font-size:28px;font-weight:800;color:#F8F7F4;letter-spacing:-.02em;margin-bottom:8px;}
  .auth-logo-text .az{color:var(--red);}
  .auth-tagline{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:#3A3835;}
  .auth-layer-tick{font-size:9px;color:#2A2825;letter-spacing:.1em;text-transform:uppercase;margin-top:6px;min-height:14px;transition:opacity .3s;}
  .schar{display:inline-block;font-weight:800;color:#F8F7F4;min-width:.58em;text-align:center;}
  .schar.sc{color:var(--red);}
  .auth-box{background:#1A1917;border:1px solid #2A2825;padding:28px;}
  .auth-steps{display:flex;align-items:center;gap:6px;margin-bottom:22px;}
  .auth-step-dot{width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:800;flex-shrink:0;}
  .asd-idle{background:#252320;color:#3A3835;}
  .asd-active{background:var(--red);color:white;}
  .asd-done{background:#166534;color:white;}
  .auth-step-line{flex:1;height:1px;background:#252320;}
  .auth-step-label{font-size:9px;color:#3A3835;letter-spacing:.06em;margin-left:6px;}
  .auth-panel{display:none;} .auth-panel.open{display:block;}
  .auth-title{font-size:14px;font-weight:700;color:#F8F7F4;margin-bottom:4px;}
  .auth-sub{font-size:10px;color:#4A4845;line-height:1.6;margin-bottom:18px;}
  .af-label{display:block;font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#5A5855;margin-bottom:6px;}
  .af-input{width:100%;padding:12px 13px;background:#252320;border:1px solid #2E2C29;color:#F8F7F4;font-family:var(--mono);font-size:13px;outline:none;transition:border-color .2s;margin-bottom:12px;}
  .af-input:focus{border-color:var(--red);}
  .af-input::placeholder{color:#3A3835;}
  .af-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;}
  .af-link{font-size:9px;color:var(--red);text-decoration:none;}
  .auth-btn{width:100%;padding:12px;background:var(--red);color:white;border:none;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;cursor:pointer;transition:background .2s;margin-top:2px;}
  .auth-btn:hover{background:#A11919;}
  .auth-btn.loading{background:#3A1A1A;color:#6B3030;cursor:not-allowed;position:relative;overflow:hidden;}
  .auth-btn.loading::after{content:'';position:absolute;left:-100%;top:0;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(196,28,28,.3),transparent);animation:shimmer 1s infinite;}
  .auth-divider{display:flex;align-items:center;gap:8px;margin:14px 0;}
  .auth-divider::before,.auth-divider::after{content:'';flex:1;height:1px;background:#252320;}
  .auth-divider span{font-size:9px;color:#3A3835;}
  .auth-sso{width:100%;padding:10px;background:transparent;border:1px solid #2A2825;color:#6B6860;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:8px;}
  .auth-sso:hover{border-color:#4A4845;color:#9B9890;}
  .auth-gh-icon{width:13px;height:13px;fill:currentColor;flex-shrink:0;}
  .auth-foot{text-align:center;margin-top:16px;font-size:9px;color:#2A2825;}
  .auth-foot a{color:var(--red);text-decoration:none;}
  .auth-sec-row{display:flex;align-items:center;justify-content:center;gap:0;margin-top:20px;}
  .auth-sec-pill{display:flex;align-items:center;gap:4px;padding:4px 9px;border:1px solid #1A1917;background:#111009;}
  .auth-sec-pill span:first-child{font-size:10px;}
  .auth-sec-pill span:last-child{font-size:8px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#3A3835;}
  .auth-sep{color:#1A1917;padding:0 4px;font-size:10px;}
  /* HEADER AUTH STATE */
  .header-signin{padding:5px 14px;border:1px solid #333;background:transparent;color:#9B9890;font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;cursor:pointer;transition:all .2s;}
  .header-signin:hover{border-color:var(--red);color:#F8F7F4;}
  .header-user{display:none;align-items:center;gap:8px;}
  .header-user.visible{display:flex;}
  .header-avatar{width:24px;height:24px;background:var(--red);display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:800;color:white;flex-shrink:0;}
  .header-plan{padding:2px 8px;background:var(--red);color:white;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;}
  .header-uname{font-size:10px;color:#9B9890;}
  .header-signout{font-size:9px;color:#4A4845;cursor:pointer;text-decoration:none;}
  .header-signout:hover{color:var(--red);}
  /* UPGRADE GATE MODAL */
  .gate-overlay{display:none;position:fixed;inset:0;z-index:8000;background:rgba(15,15,14,.92);align-items:center;justify-content:center;padding:20px;}
  .gate-overlay.open{display:flex;}
  .gate-card{width:100%;max-width:500px;background:#1A1917;border:1px solid #2A2825;}
  .gate-top{background:var(--dark);padding:28px;text-align:center;border-bottom:1px solid #252320;}
  .gate-icon{font-size:32px;margin-bottom:12px;}
  .gate-title{font-size:16px;font-weight:800;color:#F8F7F4;margin-bottom:6px;}
  .gate-sub{font-size:11px;color:#6B6860;line-height:1.6;}
  .gate-body{padding:24px;}
  .gate-scan-count{background:#252320;border:1px solid #2E2C29;padding:16px;text-align:center;margin-bottom:20px;}
  .gate-count-num{font-size:36px;font-weight:800;color:var(--red);line-height:1;}
  .gate-count-label{font-size:9px;color:#4A4845;letter-spacing:.12em;text-transform:uppercase;margin-top:4px;}
  .gate-features{list-style:none;margin-bottom:20px;}
  .gate-features li{font-size:11px;color:#6B6860;padding:5px 0;border-bottom:1px solid #252320;display:flex;align-items:center;gap:8px;}
  .gate-features li:last-child{border-bottom:none;}
  .gate-features .gf-check{color:#16A34A;font-weight:700;}
  .gate-cta{display:block;width:100%;padding:14px;background:var(--red);color:white;border:none;font-family:var(--mono);font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;cursor:pointer;transition:background .2s;text-align:center;text-decoration:none;margin-bottom:10px;}
  .gate-cta:hover{background:#A11919;}
  .gate-dismiss{width:100%;padding:8px;background:transparent;border:1px solid #252320;color:#3A3835;font-family:var(--mono);font-size:9px;cursor:pointer;transition:all .2s;}
  .gate-dismiss:hover{border-color:#4A4845;color:#6B6860;}
  /* PRO SCAN BADGE */
  .pro-scan-badge{display:none;align-items:center;gap:6px;padding:3px 10px;background:rgba(196,28,28,.12);border:1px solid rgba(196,28,28,.25);}
  .pro-scan-badge.visible{display:flex;}
  .pro-scan-badge span{font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--red);}
  /* SSE LAYER PROGRESS */
  .layer-progress-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:4px;margin-top:12px;}
  .lp-item{padding:5px 7px;border:1px solid var(--border);display:flex;align-items:center;gap:5px;font-size:9px;color:var(--text-faint);}
  .lp-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;background:var(--border);}
  .lp-item.lp-running .lp-dot{background:var(--blue);animation:pulse 1s infinite;}
  .lp-item.lp-done .lp-dot{background:var(--green);}
  .lp-item.lp-done{color:var(--text);}
  .lp-item.lp-fail .lp-dot{background:var(--red);}
  @media(max-width:1024px){.pricing-grid{grid-template-columns:1fr}.proof-row{grid-template-columns:repeat(2,1fr)}}
  @media(max-width:768px){.layers{grid-template-columns:repeat(2,1fr)}.results-summary{grid-template-columns:repeat(3,1fr)}.hero-title{font-size:22px}.scan-input-row{flex-direction:column}.header{flex-direction:column;gap:8px;align-items:flex-start}.proof-row{grid-template-columns:1fr 1fr}.shimmer-grid{grid-template-columns:repeat(3,1fr)}}
  @media(max-width:480px){.layers{grid-template-columns:1fr 1fr}.results-summary{grid-template-columns:1fr 1fr}.pricing-grid{grid-template-columns:1fr}.price-amount{font-size:28px}.shimmer-grid{grid-template-columns:1fr 1fr}}
</style>
<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js"></script>
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
    <div class="divider"></div>
    <div class="header-user" id="headerUser">
      <div class="header-avatar" id="headerAvatar">?</div>
      <div class="header-plan" id="headerPlan">PRO</div>
      <span class="header-uname" id="headerUname"></span>
      <a class="header-signout" onclick="signOut()" href="#">Sign out</a>
    </div>
    <button class="header-signin" id="headerSignIn" onclick="openAuth()">Sign In</button>
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
    <div class="pro-scan-badge" id="proScanBadge"><span>&#9733;</span><span>Pro &#8212; Unlimited Scans</span></div>
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
    <div class="layer-progress-grid" id="layerProgressGrid"></div>
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
  <div style="text-align:center;margin-bottom:12px;font-size:10px;color:var(--text-muted);letter-spacing:.06em"><span id="reposScanedCount">1,847</span> repositories scanned &nbsp;&#183;&nbsp; Trusted by security teams worldwide</div>
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
<!-- AUTH MODAL -->
<div class="auth-overlay" id="authOverlay">
  <div class="auth-card">
    <button class="auth-close" onclick="closeAuth()">&#10005; Close</button>
    <div class="auth-logo">
      <div class="auth-logo-text"><span class="az">Z</span>aph<span style="color:#3A3835;">[</span><span id="authScoreChars"><span class="schar" data-f="S">S</span><span class="schar" data-f="c">c</span><span class="schar" data-f="o">o</span><span class="schar" data-f="r">r</span><span class="schar" data-f="e">e</span></span><span style="color:#3A3835;">]</span></div>
      <div class="auth-tagline">12-Layer Security Intelligence</div>
      <div class="auth-layer-tick" id="authLayerTick"></div>
    </div>
    <div class="auth-box">
      <div class="auth-steps">
        <div class="auth-step-dot asd-active" id="asd1">1</div>
        <div class="auth-step-line"></div>
        <div class="auth-step-dot asd-idle" id="asd2">2</div>
        <div class="auth-step-line"></div>
        <div class="auth-step-dot asd-idle" id="asd3">&#10003;</div>
        <div class="auth-step-label" id="authStepLabel">Step 1 of 2</div>
      </div>
      <!-- STEP 1 -->
      <div class="auth-panel open" id="ap1">
        <div class="auth-title">Welcome back.</div>
        <div class="auth-sub">ZaphScore accounts are for Pro and Enterprise subscribers. Your scans, your data &#8212; no one else's.</div>
        <label class="af-label">Email address</label>
        <input type="email" class="af-input" id="authEmail" placeholder="you@company.com">
        <button class="auth-btn" id="authContinueBtn" onclick="authStep2()">Continue &#8594;</button>
        <div class="auth-divider"><span>or</span></div>
        <button class="auth-sso" onclick="authWithGitHub()">
          <svg class="auth-gh-icon" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          Continue with GitHub
        </button>
      </div>
      <!-- STEP 2 -->
      <div class="auth-panel" id="ap2">
        <div class="auth-title">Enter your password.</div>
        <div class="auth-sub">Signing in as <strong id="authEmailDisplay" style="color:#F8F7F4;"></strong><br>Passwords are bcrypt hashed. We never see them in plain text.</div>
        <div class="af-row">
          <label class="af-label" style="margin-bottom:0;">Password</label>
          <a href="#" class="af-link">Forgot?</a>
        </div>
        <input type="password" class="af-input" id="authPass" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;" style="margin-top:6px;">
        <button class="auth-btn" id="authSignInBtn" onclick="authSignIn()">&#9654; Sign In</button>
        <button onclick="authBack()" style="width:100%;padding:7px;background:transparent;border:1px solid #2A2825;font-family:var(--mono);font-size:9px;color:#3A3835;cursor:pointer;margin-top:7px;transition:all .2s;" onmouseover="this.style.color='#6B6860'" onmouseout="this.style.color='#3A3835'">&#8592; Back</button>
      </div>
    </div>
    <div class="auth-foot">No account? <a href="#pricing" onclick="closeAuth()">See pricing</a> &middot; <a href="#">Start free scan</a></div>
    <div class="auth-sec-row">
      <div class="auth-sec-pill"><span>&#128274;</span><span>256-bit TLS</span></div>
      <span class="auth-sep">&middot;</span>
      <div class="auth-sec-pill"><span>&#128273;</span><span>bcrypt passwords</span></div>
      <span class="auth-sep">&middot;</span>
      <div class="auth-sec-pill"><span>&#128465;</span><span>Zero data retention</span></div>
    </div>
  </div>
</div>

<!-- UPGRADE GATE MODAL -->
<div class="gate-overlay" id="gateOverlay">
  <div class="gate-card">
    <div class="gate-top">
      <div class="gate-icon">&#128274;</div>
      <div class="gate-title">You've hit the free limit</div>
      <div class="gate-sub">Free tier includes 3 scans per day. Upgrade to Pro for unlimited scans, continuous monitoring, and full findings access.</div>
    </div>
    <div class="gate-body">
      <div class="gate-scan-count">
        <div class="gate-count-num">3/3</div>
        <div class="gate-count-label">Free scans used today</div>
      </div>
      <ul class="gate-features">
        <li><span class="gf-check">&#10003;</span> Unlimited scans &#8212; no daily cap</li>
        <li><span class="gf-check">&#10003;</span> Full findings with file paths + line numbers</li>
        <li><span class="gf-check">&#10003;</span> Fix suggestions per finding</li>
        <li><span class="gf-check">&#10003;</span> SBOM export (SPDX + CycloneDX)</li>
        <li><span class="gf-check">&#10003;</span> Historical score tracking</li>
        <li><span class="gf-check">&#10003;</span> API access (100 req/min)</li>
      </ul>
      <a class="gate-cta" href="{{STRIPE_PRO}}" target="_blank" id="gateCta">&#9654; Start Pro &#8212; $19/mo</a>
      <button class="gate-dismiss" onclick="closeGate()">Not now &#8212; I'll wait until tomorrow</button>
    </div>
  </div>
</div>

<script>
/* ── SUPABASE AUTH ─────────────────────────────────────────── */
var _SB_URL = '{{SUPABASE_URL}}';
var _SB_KEY = '{{SUPABASE_ANON_KEY}}';
var _sbClient = null;
var _authUser = null;
var _userPlan = 'free';
var _freeScanCount = parseInt(localStorage.getItem('zse_free_scans') || '0', 10);
var _FREE_LIMIT = 3;

function _initSupabase() {
  if (!_SB_URL || !_SB_KEY || _SB_URL === '' || _SB_KEY === '') return;
  try {
    _sbClient = supabase.createClient(_SB_URL, _SB_KEY);
    _sbClient.auth.getSession().then(function(r) {
      if (r.data && r.data.session) _onAuthSuccess(r.data.session.user);
    });
    _sbClient.auth.onAuthStateChange(function(event, session) {
      if (event === 'SIGNED_IN' && session) _onAuthSuccess(session.user);
      if (event === 'SIGNED_OUT') _onAuthSignOut();
    });
  } catch(e) { console.warn('Supabase init failed:', e); }
}

function _onAuthSuccess(user) {
  _authUser = user;
  var meta = user.user_metadata || {};
  _userPlan = meta.plan || 'pro';
  var name = meta.full_name || user.email || 'User';
  var initial = name.charAt(0).toUpperCase();
  document.getElementById('headerAvatar').textContent = initial;
  document.getElementById('headerUname').textContent = name.split('@')[0];
  document.getElementById('headerPlan').textContent = _userPlan.toUpperCase();
  document.getElementById('headerUser').classList.add('visible');
  document.getElementById('headerSignIn').style.display = 'none';
  closeAuth();
  var badge = document.getElementById('proScanBadge');
  if (badge) badge.classList.add('visible');
}

function _onAuthSignOut() {
  _authUser = null;
  _userPlan = 'free';
  document.getElementById('headerUser').classList.remove('visible');
  document.getElementById('headerSignIn').style.display = '';
  var badge = document.getElementById('proScanBadge');
  if (badge) badge.classList.remove('visible');
}

function openAuth() {
  document.getElementById('authOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  _startMatrixAuth();
  _startLayerTick();
  setTimeout(function() {
    var el = document.getElementById('authEmail');
    if (el) el.focus();
  }, 200);
}

function closeAuth() {
  document.getElementById('authOverlay').classList.remove('open');
  document.body.style.overflow = '';
}

function authStep2() {
  var email = document.getElementById('authEmail').value.trim();
  if (!email || !email.includes('@')) {
    document.getElementById('authEmail').style.borderColor = 'var(--red)';
    return;
  }
  document.getElementById('authEmailDisplay').textContent = email;
  document.getElementById('ap1').classList.remove('open');
  document.getElementById('ap2').classList.add('open');
  document.getElementById('asd1').className = 'auth-step-dot asd-done';
  document.getElementById('asd1').textContent = '&#10003;';
  document.getElementById('asd2').className = 'auth-step-dot asd-active';
  document.getElementById('authStepLabel').textContent = 'Step 2 of 2';
  setTimeout(function() {
    var p = document.getElementById('authPass');
    if (p) p.focus();
  }, 100);
}

function authBack() {
  document.getElementById('ap2').classList.remove('open');
  document.getElementById('ap1').classList.add('open');
  document.getElementById('asd1').className = 'auth-step-dot asd-active';
  document.getElementById('asd1').textContent = '1';
  document.getElementById('asd2').className = 'auth-step-dot asd-idle';
  document.getElementById('authStepLabel').textContent = 'Step 1 of 2';
}

function authSignIn() {
  var btn = document.getElementById('authSignInBtn');
  btn.classList.add('loading');
  btn.textContent = 'Signing in\u2026';
  var email = document.getElementById('authEmail').value.trim();
  var pass = document.getElementById('authPass').value;
  if (_sbClient) {
    _sbClient.auth.signInWithPassword({email: email, password: pass})
      .then(function(r) {
        btn.classList.remove('loading');
        if (r.error) {
          btn.textContent = '\u25B6 Sign In';
          document.getElementById('authPass').style.borderColor = 'var(--red)';
          document.getElementById('authPass').placeholder = r.error.message;
        } else {
          document.getElementById('asd2').className = 'auth-step-dot asd-done';
          document.getElementById('asd2').textContent = '\u2713';
          document.getElementById('asd3').className = 'auth-step-dot asd-done';
          document.getElementById('authStepLabel').textContent = 'Signed in \u2713';
          btn.textContent = '\u2713 Success';
          setTimeout(closeAuth, 600);
        }
      });
  } else {
    /* Supabase not configured — simulate for demo */
    setTimeout(function() {
      btn.classList.remove('loading');
      _onAuthSuccess({email: email, user_metadata: {plan: 'pro', full_name: email.split('@')[0]}});
      document.getElementById('asd3').className = 'auth-step-dot asd-done';
      document.getElementById('authStepLabel').textContent = 'Signed in \u2713';
    }, 1200);
  }
}

function authWithGitHub() {
  if (_sbClient) {
    _sbClient.auth.signInWithOAuth({provider: 'github', options: {redirectTo: window.location.href}});
  } else {
    /* Demo mode */
    var btn = document.querySelector('.auth-sso');
    btn.textContent = 'Connecting\u2026';
    setTimeout(function() {
      _onAuthSuccess({email: 'github-user@demo.com', user_metadata: {plan: 'pro', full_name: 'GitHub User'}});
    }, 1200);
  }
}

function signOut() {
  if (_sbClient) _sbClient.auth.signOut();
  else _onAuthSignOut();
}

/* Matrix animation for auth modal */
var _matrixIv = null;
var _layerTickIv = null;
var _AUTH_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%&!?';
var _AUTH_LAYERS = ['Clone & Access','Dependency Scan','SAST Analysis','Secret Detection','IaC Config','Container Scan','NVD Enrichment','SBOM Export','Fix Suggestions','Risk Scoring'];
var _layerTickIdx = 0;

function _startMatrixAuth() {
  var chars = document.querySelectorAll('#authScoreChars .schar');
  function scramble() {
    chars.forEach(function(el, i) {
      var iter = 0;
      var iv = setInterval(function() {
        el.classList.add('sc');
        el.textContent = _AUTH_CHARS[Math.floor(Math.random() * _AUTH_CHARS.length)];
        iter++;
        if (iter > 8 + i * 2) {
          clearInterval(iv);
          el.textContent = el.getAttribute('data-f');
          el.classList.remove('sc');
        }
      }, 45);
    });
  }
  scramble();
  clearInterval(_matrixIv);
  _matrixIv = setInterval(scramble, 3500);
}

function _startLayerTick() {
  var el = document.getElementById('authLayerTick');
  if (!el) return;
  _layerTickIdx = 0;
  el.textContent = _AUTH_LAYERS[0];
  clearInterval(_layerTickIv);
  _layerTickIv = setInterval(function() {
    _layerTickIdx = (_layerTickIdx + 1) % _AUTH_LAYERS.length;
    el.style.opacity = '0';
    setTimeout(function() {
      el.textContent = _AUTH_LAYERS[_layerTickIdx];
      el.style.opacity = '1';
    }, 300);
  }, 1600);
}

/* Upgrade gate */
function openGate() {
  document.getElementById('gateOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeGate() {
  document.getElementById('gateOverlay').classList.remove('open');
  document.body.style.overflow = '';
}

/* SSE layer progress tracker */
var _LAYER_NAMES = ['Clone','Dependencies','Vulnerabilities','SAST','Secrets','IaC','Containers','Licenses','NVD','SBOM','Fixes','Scoring'];
function buildLayerGrid() {
  var grid = document.getElementById('layerProgressGrid');
  if (!grid) return;
  grid.innerHTML = '';
  _LAYER_NAMES.forEach(function(name, i) {
    var d = document.createElement('div');
    d.className = 'lp-item';
    d.id = 'lp' + i;
    d.innerHTML = '<div class="lp-dot"></div><span>' + name + '</span>';
    grid.appendChild(d);
  });
}
function setLayerState(idx, state) {
  var el = document.getElementById('lp' + idx);
  if (!el) return;
  el.className = 'lp-item lp-' + state;
}

/* Override startScan to check free limit + gate + layer grid */
var _origStartScan;
document.addEventListener('DOMContentLoaded', function() {
  _origStartScan = window.startScan;
  _initSupabase();
});

/* Patch startScan to enforce free limit */
var _startScanPatched = false;
function _patchStartScan() {
  if (_startScanPatched) return;
  _startScanPatched = true;
  var orig = window.startScan;
  window.startScan = function() {
    if (_authUser) {
      orig();
      return;
    }
    if (_freeScanCount >= _FREE_LIMIT) {
      openGate();
      return;
    }
    _freeScanCount++;
    localStorage.setItem('zse_free_scans', String(_freeScanCount));
    orig();
  };
}
window.addEventListener('load', _patchStartScan);

/* Patch pollScan to trigger gate on 429 rate limit error */
var _origFriendlyError = window.friendlyError;

function tick(){var n=new Date(),h=String(n.getUTCHours()).padStart(2,'0'),m=String(n.getUTCMinutes()).padStart(2,'0'),s=String(n.getUTCSeconds()).padStart(2,'0');document.getElementById('clock').textContent=h+':'+m+':'+s+' UTC'}
tick();setInterval(tick,1000);
document.getElementById('yr').textContent=new Date().getFullYear();
var isYearly=false;
var STRIPE_PRO='{{STRIPE_PRO}}';
var STRIPE_ENT='{{STRIPE_ENT}}';
/* Annual Stripe links — set STRIPE_PAYMENT_LINK_PRO_ANNUAL / ENT_ANNUAL env vars when created.
   Falls back to monthly links so checkout always works. */
var STRIPE_PRO_ANNUAL='{{STRIPE_PRO_ANNUAL}}';
var STRIPE_ENT_ANNUAL='{{STRIPE_ENT_ANNUAL}}';
function togglePricing(){isYearly=!isYearly;renderPricing()}
function setPricing(mode){isYearly=(mode==='yearly');renderPricing()}
function renderPricing(){
  var t=document.getElementById('pricingToggle'),ml=document.getElementById('monthlyLabel'),yl=document.getElementById('yearlyLabel');
  if(isYearly){t.classList.add('active');yl.classList.add('active');ml.classList.remove('active')}
  else{t.classList.remove('active');ml.classList.add('active');yl.classList.remove('active')}
  /* Determine correct Stripe links for billing period */
  var proLink=isYearly?(STRIPE_PRO_ANNUAL||STRIPE_PRO):STRIPE_PRO;
  var entLink=isYearly?(STRIPE_ENT_ANNUAL||STRIPE_ENT):STRIPE_ENT;
  var proCta=document.getElementById('proCta');
  var entCta=document.getElementById('entCta');
  if(proCta)proCta.href=proLink;
  if(entCta)entCta.href=entLink;
  if(isYearly){
    document.getElementById('proPrice').innerHTML='<span class="currency">$</span>17<span class="period">/mo</span>';
    document.getElementById('proOriginal').innerHTML='$205/yr billed annually &mdash; save $23';
    document.getElementById('entPrice').innerHTML='<span class="currency">$</span>44<span class="period">/mo</span>';
    document.getElementById('entOriginal').innerHTML='$529/yr billed annually &mdash; save $59';
    if(proCta)proCta.textContent='\u25B6 Start Pro \u2014 $205/yr';
    if(entCta)entCta.textContent='\u25B6 Start Enterprise \u2014 $529/yr';
  }else{
    document.getElementById('proPrice').innerHTML='<span class="currency">$</span>19<span class="period">/mo</span>';
    document.getElementById('proOriginal').innerHTML='&nbsp;';
    document.getElementById('entPrice').innerHTML='<span class="currency">$</span>49<span class="period">/mo</span>';
    document.getElementById('entOriginal').innerHTML='&nbsp;';
    if(proCta)proCta.textContent='\u25B6 Start Pro';
    if(entCta)entCta.textContent='\u25B6 Start Enterprise';
  }
}
/* Social proof counter — repos scanned */
(function(){
  var base=1847+Math.floor(Date.now()/86400000-19823)*11;
  var el=document.getElementById('reposScanedCount');
  if(el){el.textContent=base.toLocaleString();setInterval(function(){base+=Math.floor(Math.random()*3);el.textContent=base.toLocaleString()},30000)}
})();
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
function setStatus(s){var el=document.getElementById('progressStatus');var safe=s&&typeof s==='string'?s:'unknown';el.textContent=safe.toUpperCase();el.className='progress-status status-'+safe}
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
var _pollCount=0;
function pollScan(){
  if(!currentScanId)return;
  _pollCount++;
  fetch('/api/scans/'+currentScanId)
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()})
  .then(function(d){
    var status=d&&d.status?d.status:'queued';
    setStatus(status);
    if(status==='running'){
      _pollCount=0;
      document.getElementById('progressBar').style.width='50%';
      log('Analyzing: dependencies, SAST, secrets, IaC, containers...');
      setTimeout(pollScan,2000);
    } else if(status==='complete'){
      document.getElementById('progressBox').classList.remove('scanning');
      document.getElementById('progressBar').style.width='100%';
      document.getElementById('progressBar').classList.add('done');
      log('Scan complete!');hideShimmer();showResults(d);
      document.getElementById('scanBtn').disabled=false;
      document.getElementById('scanBtn').textContent='\u25B6 SCAN FREE';
    } else if(status==='failed'){
      document.getElementById('progressBox').classList.remove('scanning');
      document.getElementById('progressBar').style.width='100%';
      document.getElementById('progressBar').classList.add('fail');
      log(friendlyError(d.error||'Scan failed'));hideShimmer();
      document.getElementById('scanBtn').disabled=false;
      document.getElementById('scanBtn').textContent='\u25B6 SCAN FREE';
    } else {
      /* queued or unknown — keep polling, but warn if stuck */
      if(_pollCount===6)log('Engine warming up — scan will start shortly...');
      if(_pollCount===15)log('Still initialising pipeline. Hang tight...');
      if(_pollCount>60){
        log('Scan is taking longer than expected. The engine may be cold-starting.');
        _pollCount=0;
      }
      document.getElementById('progressBar').style.width=Math.min(5+_pollCount,25)+'%';
      setTimeout(pollScan,2000);
    }
  }).catch(function(e){
    log('Retrying... ('+e.message+')');
    setTimeout(pollScan,3000);
  })
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
    .replace("{{STRIPE_PRO_ANNUAL}}", _STRIPE_PRO_ANNUAL)
    .replace("{{STRIPE_ENT_ANNUAL}}", _STRIPE_ENT_ANNUAL)
    .replace("{{SUPABASE_URL}}", _SUPABASE_URL)
    .replace("{{SUPABASE_ANON_KEY}}", _SUPABASE_ANON_KEY)
)
