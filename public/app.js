let report = null;
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function scoreLabel(n){return n>=90?"Excellent":n>=75?"Good":n>=55?"Needs attention":"At risk";}
function setProgress(n,text){$("#progressBar").style.width=n+"%";$("#progressText").textContent=text;}

async function analyze(url){
  $("#errorBox").classList.add("hidden"); $("#results").classList.add("hidden");
  $("#progress").classList.remove("hidden"); $("#scanBtn").disabled=true;
  setProgress(10,"Validating target…");
  const steps=[[25,"Resolving DNS…"],[40,"Fetching public response…"],[55,"Parsing HTML and resources…"],[70,"Evaluating security posture…"],[84,"Checking safe same-origin links…"],[96,"Building report…"]];
  let i=0; const timer=setInterval(()=>{if(i<steps.length)setProgress(...steps[i++]);},850);
  try{
    const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
    const data=await r.json(); if(!r.ok) throw new Error(data.error||"Analysis failed.");
    report=data; renderReport(); loadHistory();
    setProgress(100,"Analysis complete.");
  }catch(e){$("#errorBox").textContent=e.message;$("#errorBox").classList.remove("hidden");}
  finally{clearInterval(timer);setTimeout(()=>$("#progress").classList.add("hidden"),700);$("#scanBtn").disabled=false;}
}
function renderReport(){
  $("#results").classList.remove("hidden");
  $("#resultUrl").textContent=report.finalUrl;
  $("#scanMeta").textContent=`${report.overview.status} ${report.overview.statusText} • ${report.timing.totalMs} ms • ${report.id}`;
  $("#overallScore").textContent=report.overallScore;
  $("#overallLabel").textContent=scoreLabel(report.overallScore);
  $("#securityScore").textContent=report.security.score;
  $("#performanceScore").textContent=report.performance.score;
  $("#seoScore").textContent=report.seo.score;
  $("#securityBar").style.width=report.security.score+"%";
  $("#performanceBar").style.width=report.performance.score+"%";
  $("#seoBar").style.width=report.seo.score+"%";
  $$(".tab").forEach(x=>x.classList.toggle("active",x.dataset.tab==="overview"));
  renderTab("overview");
  window.scrollTo({top:document.querySelector("#results").offsetTop-10,behavior:"smooth"});
}
function panel(title,body){return `<div class="panel"><div class="panel-title"><b>${title}</b></div>${body}</div>`}
function kv(items){return `<div>${items.map(([a,b])=>`<div class="kv"><label>${esc(a)}</label><div>${esc(b)}</div></div>`).join("")}</div>`}
function metric(items){return `<div class="metric-grid">${items.map(([a,b])=>`<div class="metric"><span>${esc(a)}</span><b>${esc(b)}</b></div>`).join("")}</div>`}

function renderTab(tab){
  const c=$("#tabContent");
  if(!report)return;
  if(tab==="overview"){
    c.innerHTML=metric([
      ["HTTP status",`${report.overview.status} ${report.overview.statusText}`],
      ["Response",`${report.timing.totalMs} ms`],
      ["Page size",formatBytes(report.overview.responseBytes)],
      ["Links",report.links.all.length]
    ])+
    `<div class="grid2">${panel("Page identity",kv([
      ["Title",report.overview.title||"Not found"],["Description",report.overview.description||"Not found"],
      ["Language",report.overview.language||"Not found"],["Canonical",report.overview.canonical||"Not found"],
      ["Final URL",report.finalUrl],["Content type",report.overview.contentType]
    ]))}${panel("Network timing",kv([
      ["DNS",fmtMs(report.timing.dnsMs)],["TCP",fmtMs(report.timing.tcpMs)],["TLS",fmtMs(report.timing.tlsMs)],
      ["TLS protocol",report.timing.tlsProtocol||"—"],["Total",fmtMs(report.timing.totalMs)]
    ]))}</div>`+
    panel("Discovery",kv([["Internal links",report.links.internal],["External links",report.links.external],["Broken observations",report.links.broken],["Redirect observations",report.links.redirects],["Robots.txt",report.robots.available?"Available":"Not observed"],["Sitemap.xml",report.sitemap.available?"Available":"Not observed"]]));
  } else if(tab==="security"){
    const rows=report.security.checks.map(x=>`<tr><td>${esc(x.name)}</td><td class="${x.severity}">${esc(x.value)}</td><td>${esc(x.detail)}</td><td>${esc(x.recommendation)}</td></tr>`).join("");
    c.innerHTML=panel(`Security posture • ${report.security.score}/100`, `<div class="table-wrap"><table class="data-table"><thead><tr><th>Check</th><th>Result</th><th>Observation</th><th>Recommendation</th></tr></thead><tbody>${rows}</tbody></table></div>`);
  } else if(tab==="links"){
    const rows=report.links.all.slice(0,250).map(x=>`<tr><td>${esc(x.type)}</td><td title="${esc(x.url)}">${esc(x.text||"—")}</td><td>${esc(x.url)}</td><td>${esc((report.links.checked.find(y=>y.url===x.url)||{}).status??"—")}</td></tr>`).join("");
    c.innerHTML=panel(`Links • ${report.links.all.length}`,`<div class="table-wrap"><table class="data-table"><thead><tr><th>Type</th><th>Anchor</th><th>URL</th><th>Status</th></tr></thead><tbody>${rows||"<tr><td colspan=4>No links found.</td></tr>"}</tbody></table></div>`);
  } else if(tab==="tech"){
    const tech=report.technologies.map(x=>`<div class="tech"><b>${esc(x.name)}</b><small>${esc(x.confidence)} confidence • ${esc(x.evidence)}</small></div>`).join("");
    c.innerHTML=panel(`Detected technologies • ${report.technologies.length}`,`<div class="tech-grid">${tech||"<div class=tech>No strong public fingerprints detected.</div>"}</div>`);
  } else if(tab==="media"){
    const vids=report.videos.map(x=>`<tr><td>${esc(x.kind)}</td><td>${esc(x.url)}</td></tr>`).join("");
    const imgs=report.accessibility.images;
    c.innerHTML=metric([["Videos",report.videos.length],["Images",imgs],["Images with alt",report.accessibility.imagesWithAlt],["Forms",report.forms.length]])+
      panel("Public video references",`<div class="table-wrap"><table class="data-table"><thead><tr><th>Type</th><th>URL</th></tr></thead><tbody>${vids||"<tr><td colspan=2>No video references found.</td></tr>"}</tbody></table></div>`);
  } else if(tab==="resources"){
    const rows=report.resources.map(x=>`<tr><td>${esc(x.kind)}</td><td>${x.sameOrigin?"Internal":"External"}</td><td>${esc(x.url)}</td></tr>`).join("");
    c.innerHTML=panel(`Public resources • ${report.resources.length}`,`<div class="table-wrap"><table class="data-table"><thead><tr><th>Type</th><th>Scope</th><th>URL</th></tr></thead><tbody>${rows||"<tr><td colspan=3>No resources found.</td></tr>"}</tbody></table></div>`);
  }
}
function formatBytes(n){if(!n)return"0 B";const u=["B","KB","MB","GB"];let i=0,x=n;while(x>=1024&&i<u.length-1){x/=1024;i++}return `${x.toFixed(i?1:0)} ${u[i]}`}
function fmtMs(n){return n==null?"—":`${n} ms`}

async function loadHistory(){
  const r=await fetch("/api/history"); const list=await r.json();
  $("#historyList").innerHTML=list.length?list.map(x=>`<div class="history-item"><div><b>${esc(x.url)}</b><small>${new Date(x.scannedAt).toLocaleString()} • ${esc(x.id)}</small></div><strong>${x.overallScore}/100</strong></div>`).join(""):`<div class="content-card"><p>No scans yet.</p></div>`;
}
function download(name,type,text){
  const blob=new Blob([text],{type}); const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}
function htmlReport(){
  const r=report;
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(r.finalUrl)} — WebScope Report</title><style>body{font:14px system-ui;background:#0b1020;color:#eee;padding:30px;max-width:1100px;margin:auto}section{background:#121b2c;padding:20px;margin:15px 0;border-radius:14px}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #293650;text-align:left}small{color:#9aa7bc}</style></head><body><h1>WebScope Pro Report</h1><p>${esc(r.finalUrl)}<br><small>${esc(r.scannedAt)} • ${esc(r.id)}</small></p><section><h2>Scores</h2><h3>Overall ${r.overallScore}/100 • Security ${r.security.score} • Performance ${r.performance.score} • SEO ${r.seo.score}</h3></section><section><h2>Overview</h2><pre>${esc(JSON.stringify(r.overview,null,2))}</pre></section><section><h2>Security</h2><pre>${esc(JSON.stringify(r.security,null,2))}</pre></section><section><h2>Links</h2><pre>${esc(JSON.stringify(r.links,null,2))}</pre></section><section><h2>Technologies</h2><pre>${esc(JSON.stringify(r.technologies,null,2))}</pre></section><section><h2>Resources / Media</h2><pre>${esc(JSON.stringify({resources:r.resources,videos:r.videos},null,2))}</pre></section></body></html>`;
}

$("#scanForm").addEventListener("submit",e=>{e.preventDefault();analyze($("#urlInput").value.trim())});
$$("[data-example]").forEach(b=>b.addEventListener("click",()=>{$("#urlInput").value=b.dataset.example;$("#scanForm").requestSubmit()}));
$("#tabs").addEventListener("click",e=>{const b=e.target.closest(".tab");if(!b)return;$$(".tab").forEach(x=>x.classList.remove("active"));b.classList.add("active");renderTab(b.dataset.tab)});
$("#downloadJson").addEventListener("click",()=>report&&download(`${report.id}.json`,"application/json",JSON.stringify(report,null,2)));
$("#downloadHtml").addEventListener("click",()=>report&&download(`${report.id}.html`,"text/html",htmlReport()));
$("#clearHistory").addEventListener("click",async()=>{if(confirm("Clear local scan history?")){await fetch("/api/history",{method:"DELETE"});loadHistory()}});
$("#themeBtn").addEventListener("click",()=>document.body.classList.toggle("light"));
$$(".nav-item").forEach(b=>b.addEventListener("click",()=>{
  $$(".nav-item").forEach(x=>x.classList.remove("active"));b.classList.add("active");
  $$(".view").forEach(v=>v.classList.remove("active"));$(`#${b.dataset.view}View`).classList.add("active");
  $("#pageTitle").textContent=b.dataset.view==="scan"?"Analyze a website":b.dataset.view==="history"?"Scan history":"About WebScope Pro";
  if(b.dataset.view==="history")loadHistory();
}));
loadHistory();
