const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const dns = require("dns").promises;
const net = require("net");
const tls = require("tls");
const crypto = require("crypto");
const { URL } = require("url");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_HTML_BYTES = Number(process.env.MAX_HTML_BYTES || 3000000);
const MAX_LINKS = Number(process.env.MAX_LINKS || 500);
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 10000);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: "64kb" }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});
app.use("/api/", limiter);

const DATA_DIR = path.join(__dirname, "data");
const HISTORY_FILE = path.join(DATA_DIR, "history.json");
fs.mkdirSync(DATA_DIR, { recursive: true });

function readHistory() {
  try { return JSON.parse(fs.readFileSync(HISTORY_FILE, "utf8")); }
  catch { return []; }
}
function writeHistory(items) {
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(items.slice(0, 100), null, 2));
}
function nowIso() { return new Date().toISOString(); }
function sha(text) { return crypto.createHash("sha256").update(text).digest("hex").slice(0, 12); }

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(Number.isNaN)) return true;
  return p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    p[0] === 0 ||
    p[0] >= 224;
}
function isPrivateIPv6(ip) {
  const s = ip.toLowerCase();
  return s === "::1" || s === "::" || s.startsWith("fc") || s.startsWith("fd") ||
    s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb");
}
function isBlockedAddress(ip) {
  return net.isIP(ip) === 4 ? isPrivateIPv4(ip) : net.isIP(ip) === 6 ? isPrivateIPv6(ip) : true;
}
async function resolveSafe(hostname) {
  const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(a => isBlockedAddress(a.address))) {
    throw new Error("Target resolves to a private/reserved address and was blocked.");
  }
  return addresses;
}
function validateTarget(raw) {
  if (typeof raw !== "string" || raw.length > 2048) throw new Error("Invalid URL.");
  const u = new URL(raw.trim());
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Only HTTP and HTTPS URLs are allowed.");
  if (u.username || u.password) throw new Error("URLs containing credentials are not allowed.");
  if (u.hostname === "localhost" || u.hostname.endsWith(".localhost") || u.hostname.endsWith(".local")) {
    throw new Error("Local hostnames are blocked.");
  }
  return u;
}
async function safeUrl(raw, expectedOrigin = null) {
  const u = validateTarget(raw);
  if (expectedOrigin && u.origin !== expectedOrigin) throw new Error("Cross-origin request blocked.");
  await resolveSafe(u.hostname);
  return u;
}

async function fetchLimited(url, opts = {}) {
  const maxBytes = opts.maxBytes || MAX_HTML_BYTES;
  const timeout = opts.timeout || REQUEST_TIMEOUT_MS;
  const origin = opts.expectedOrigin || null;
  let current = await safeUrl(url, origin);
  let redirects = [];
  for (let i = 0; i < 4; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    let res;
    try {
      res = await fetch(current, {
        method: opts.method || "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "WebScope-Pro/1.0 (passive website analyzer)",
          "Accept": opts.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
      });
    } catch (e) {
      clearTimeout(timer);
      throw new Error(`Request failed: ${e.name === "AbortError" ? "timeout" : e.message}`);
    }
    clearTimeout(timer);
    if ([301,302,303,307,308].includes(res.status)) {
      const loc = res.headers.get("location");
      if (!loc) return { res, body: "", redirects };
      const next = new URL(loc, current);
      if (next.origin !== current.origin) throw new Error("Cross-origin redirect blocked.");
      await safeUrl(next.toString(), current.origin);
      redirects.push(next.toString());
      current = next;
      continue;
    }
    if (opts.method === "HEAD") return { res, body: "", redirects, finalUrl: current.toString() };
    const len = Number(res.headers.get("content-length") || 0);
    if (len > maxBytes) throw new Error("Response is larger than the configured safety limit.");
    const reader = res.body?.getReader();
    if (!reader) return { res, body: "", redirects, finalUrl: current.toString() };
    let total = 0, chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch {}
        throw new Error("Response exceeded the configured safety limit.");
      }
      chunks.push(Buffer.from(value));
    }
    const body = Buffer.concat(chunks).toString("utf8");
    return { res, body, redirects, finalUrl: current.toString() };
  }
  throw new Error("Too many redirects.");
}

function headerObject(headers) {
  const out = {};
  for (const [k,v] of headers.entries()) out[k.toLowerCase()] = v;
  return out;
}
function absolute(base, value) {
  try { return new URL(value, base).toString(); } catch { return null; }
}
function sameOrigin(a,b) {
  try { return new URL(a).origin === new URL(b).origin; } catch { return false; }
}
function normalizeLink(u) {
  try {
    const x = new URL(u);
    x.hash = "";
    return x.toString();
  } catch { return null; }
}
function extractHtml(html, baseUrl) {
  const $ = require("cheerio").load(html, { decodeEntities: true });
  const links = [];
  const resources = [];
  const videos = [];
  const forms = [];
  const metas = [];
  const structured = [];
  const pushUnique = (arr, item) => {
    if (item && !arr.some(x => x.url === item.url)) arr.push(item);
  };

  $("a[href]").each((_, el) => {
    const raw = $(el).attr("href");
    if (!raw || raw.startsWith("#") || /^(javascript:|data:)/i.test(raw)) return;
    const url = absolute(baseUrl, raw);
    const normalized = normalizeLink(url);
    if (!normalized) return;
    links.push({
      url: normalized,
      text: ($(el).text() || "").replace(/\s+/g," ").trim().slice(0,180),
      rel: $(el).attr("rel") || "",
      type: sameOrigin(normalized, baseUrl) ? "internal" : "external"
    });
  });

  const resourceSelectors = [
    ["script[src]","script"], ["link[href]","stylesheet-or-link"],
    ["img[src]","image"], ["source[src]","media-source"],
    ["iframe[src]","iframe"], ["object[data]","object"],
    ["embed[src]","embed"]
  ];
  for (const [selector, kind] of resourceSelectors) {
    $(selector).each((_, el) => {
      const raw = $(el).attr("src") || $(el).attr("href") || $(el).attr("data");
      const url = normalizeLink(absolute(baseUrl, raw));
      if (url) pushUnique(resources, { url, kind, sameOrigin: sameOrigin(url, baseUrl) });
    });
  }
  $("video[src], video source[src]").each((_,el) => {
    const raw = $(el).attr("src");
    const url = normalizeLink(absolute(baseUrl, raw));
    if (url) pushUnique(videos, { url, kind:"video-file" });
  });
  $("iframe[src]").each((_,el) => {
    const raw = $(el).attr("src");
    const url = normalizeLink(absolute(baseUrl, raw));
    if (url && /youtube|youtu\.be|vimeo|dailymotion|wistia|vidyard/i.test(url)) {
      pushUnique(videos, { url, kind:"embedded-video" });
    }
  });
  $("form[action]").each((_,el) => {
    const url = normalizeLink(absolute(baseUrl, $(el).attr("action")));
    if (url) forms.push({ url, method: ($(el).attr("method") || "GET").toUpperCase() });
  });
  $("meta").each((_,el) => {
    const name = $(el).attr("name") || $(el).attr("property") || $(el).attr("http-equiv");
    const content = $(el).attr("content");
    if (name && content) metas.push({ name, content: content.slice(0,500) });
  });
  $('script[type="application/ld+json"]').each((_,el) => {
    try { structured.push(JSON.parse($(el).text())); } catch {}
  });

  const title = $("title").first().text().trim();
  const description = $('meta[name="description"]').attr("content") || "";
  const canonical = $('link[rel="canonical"]').attr("href");
  const lang = $("html").attr("lang") || "";
  const favicon = $('link[rel*="icon"]').attr("href");
  const headings = {
    h1: $("h1").length, h2: $("h2").length, h3: $("h3").length
  };
  const images = $("img").map((_,el)=>({src: normalizeLink(absolute(baseUrl,$(el).attr("src"))), alt: $(el).attr("alt") || ""})).get().filter(x=>x.src);

  return { $, title, description, canonical: canonical ? absolute(baseUrl, canonical) : null, lang, favicon: favicon ? absolute(baseUrl,favicon):null,
    links, resources, videos, forms, metas, structured, headings, images };
}

function detectTechnologies(html, headers, url) {
  const h = Object.keys(headers).join(" ");
  const s = `${html.slice(0,1000000)} ${h}`.toLowerCase();
  const tech = [];
  const add = (name, confidence, evidence) => tech.push({name, confidence, evidence});
  if (/wp-content|wp-includes|wordpress/.test(s)) add("WordPress","high","WordPress asset/path markers");
  if (/shopify|cdn\.shopify\.com/.test(s)) add("Shopify","high","Shopify markers");
  if (/__next_data__|_next\/static|next\.js/.test(s)) add("Next.js","high","Next.js asset markers");
  if (/react(?:\.production|dom)|data-reactroot/.test(s)) add("React","medium","React markers");
  if (/vue(?:\.runtime|\.js)|data-v-[a-f0-9]/.test(s)) add("Vue","medium","Vue markers");
  if (/angular|ng-version/.test(s)) add("Angular","medium","Angular markers");
  if (/jquery(?:[-.]\d|\s)/.test(s)) add("jQuery","medium","jQuery marker");
  if (/bootstrap(?:\.min)?\.css/.test(s)) add("Bootstrap","medium","Bootstrap asset marker");
  if (/tailwind/.test(s)) add("Tailwind CSS","medium","Tailwind marker");
  if (/laravel_session|laravel/.test(s)) add("Laravel","medium","Laravel marker");
  if (/php\//.test(s) || /x-powered-by.*php/i.test(JSON.stringify(headers))) add("PHP","medium","PHP response marker");
  if (/x-powered-by/.test(h)) add("Server-side framework","low","X-Powered-By header");
  if (/cloudflare|cf-ray|cf-cache-status/.test(s)) add("Cloudflare","high","Cloudflare header/asset marker");
  if (/vercel/.test(s)) add("Vercel","medium","Vercel marker");
  if (/netlify/.test(s)) add("Netlify","medium","Netlify marker");
  if (/akamai/.test(s)) add("Akamai","medium","Akamai marker");
  if (/fastly/.test(s)) add("Fastly","medium","Fastly marker");
  if (headers.server) add(`Server: ${headers.server}`,"low","Server header");
  return tech.filter((x,i,a)=>a.findIndex(y=>y.name===x.name)===i);
}

function securityAnalysis(headers, html, finalUrl) {
  const checks = [];
  const h = headers;
  const check = (name, value, severity, detail, recommendation) =>
    checks.push({name, value, severity, detail, recommendation});
  check("HTTPS", finalUrl.startsWith("https://") ? "Present":"Missing",
    finalUrl.startsWith("https://") ? "good":"critical",
    finalUrl.startsWith("https://") ? "The analyzed URL uses HTTPS." : "The analyzed URL is not HTTPS.",
    "Serve the site over HTTPS and redirect HTTP to HTTPS.");
  const policies = [
    ["Strict-Transport-Security","HSTS","high","Use HSTS on HTTPS deployments."],
    ["Content-Security-Policy","CSP","high","Define an appropriate Content-Security-Policy."],
    ["X-Content-Type-Options","X-Content-Type-Options","medium","Set nosniff."],
    ["X-Frame-Options","X-Frame-Options","medium","Use DENY/SAMEORIGIN or CSP frame-ancestors as appropriate."],
    ["Referrer-Policy","Referrer-Policy","low","Set a deliberate Referrer-Policy."],
    ["Permissions-Policy","Permissions-Policy","low","Restrict browser features not needed by the application."]
  ];
  for (const [header,label,sev,rec] of policies) {
    const present = Boolean(h[header.toLowerCase()]);
    check(label, present ? "Present":"Missing", present ? "good":sev,
      present ? h[header.toLowerCase()].slice(0,300) : `The ${label} response header was not observed.`,
      rec);
  }
  const setCookie = h["set-cookie"] || "";
  if (setCookie) {
    const cookies = setCookie.split(/,(?=[^;,]+=)/).map(x=>x.trim()).filter(Boolean);
    for (const c of cookies.slice(0,20)) {
      const secure = /;\s*secure\b/i.test(c);
      const httpOnly = /;\s*httponly\b/i.test(c);
      const sameSite = /;\s*samesite=/i.test(c);
      check("Cookie flags", `${secure?"Secure ":""}${httpOnly?"HttpOnly ":""}${sameSite?"SameSite":"No SameSite"}`,
        secure && httpOnly && sameSite ? "good":"medium",
        c.slice(0,220),
        "Use Secure, HttpOnly and an appropriate SameSite value for sensitive cookies.");
    }
  }
  if (/server:\s*(apache|nginx|iis)/i.test(JSON.stringify(h))) {
    check("Server disclosure", h.server || "Observed", "info",
      "A Server header was exposed.",
      "Consider minimizing unnecessary version/product disclosure.");
  }
  return checks;
}

function scoreSecurity(checks) {
  let score = 100;
  for (const c of checks) {
    if (c.severity === "critical") score -= 25;
    else if (c.severity === "high") score -= 14;
    else if (c.severity === "medium") score -= 7;
    else if (c.severity === "low") score -= 3;
  }
  return Math.max(0, Math.min(100, score));
}
function performanceScore(ms, size) {
  let s = 100;
  if (ms > 1000) s -= 15;
  if (ms > 2500) s -= 20;
  if (ms > 5000) s -= 25;
  if (size > 1000000) s -= 15;
  if (size > 3000000) s -= 15;
  return Math.max(0, s);
}
function seoScore(meta) {
  let s=100;
  if (!meta.title) s-=25; else if (meta.title.length<20 || meta.title.length>70) s-=8;
  if (!meta.description) s-=25; else if (meta.description.length<50 || meta.description.length>170) s-=8;
  if (!meta.canonical) s-=10;
  if (!meta.lang) s-=10;
  if (meta.headings.h1 === 0) s-=10;
  return Math.max(0,s);
}
function accessibilityScore(meta) {
  const total = meta.images.length;
  const withAlt = meta.images.filter(x=>x.alt.trim()).length;
  let s=100;
  if (total && withAlt/total < .8) s-=25;
  if (!meta.headings.h1) s-=10;
  if (!meta.lang) s-=10;
  return Math.max(0,s);
}

function timingLookup(hostname) {
  return new Promise(async resolve => {
    const started = performance.now();
    try {
      const result = await dns.lookup(hostname, { all:true });
      resolve({ms: Math.round(performance.now()-started), addresses: result.map(x=>x.address)});
    } catch { resolve({ms: Math.round(performance.now()-started), addresses:[]}); }
  });
}
function tcpTiming(host, port=443) {
  return new Promise(resolve=>{
    const started=performance.now();
    const socket=net.createConnection({host,port});
    const timer=setTimeout(()=>{socket.destroy();resolve(null)},4000);
    socket.once("connect",()=>{clearTimeout(timer);const ms=Math.round(performance.now()-started);socket.destroy();resolve(ms)});
    socket.once("error",()=>{clearTimeout(timer);resolve(null)});
  });
}
function tlsTiming(host, port=443) {
  return new Promise(resolve=>{
    const started=performance.now();
    const socket=tls.connect({host,port,servername:host,rejectUnauthorized:false});
    const timer=setTimeout(()=>{socket.destroy();resolve(null)},5000);
    socket.once("secureConnect",()=>{clearTimeout(timer);const ms=Math.round(performance.now()-started);socket.end();resolve({ms,protocol:socket.getProtocol()})});
    socket.once("error",()=>{clearTimeout(timer);resolve(null)});
  });
}

async function checkLinks(baseUrl, links) {
  const targets = links.filter(x=>x.type==="internal").slice(0, Math.min(MAX_LINKS, 120));
  const out=[]; let idx=0;
  async function worker() {
    while(idx<targets.length) {
      const item=targets[idx++];
      try {
        const u=await safeUrl(item.url, new URL(baseUrl).origin);
        const result=await fetchLimited(u.toString(),{method:"GET",expectedOrigin:new URL(baseUrl).origin,maxBytes:256000,timeout:6000,accept:"text/html,*/*;q=0.5"});
        out.push({...item,status:result.res.status,ok:result.res.ok,redirects:result.redirects.length});
      } catch(e) {
        out.push({...item,status:null,ok:false,error:e.message});
      }
    }
  }
  await Promise.all(Array.from({length:5},worker));
  return out;
}

async function analyze(rawUrl) {
  const input = validateTarget(rawUrl);
  await resolveSafe(input.hostname);
  const start = performance.now();
  const dnsInfo = await timingLookup(input.hostname);
  const port = input.protocol === "https:" ? 443 : 80;
  const tcp = await tcpTiming(input.hostname, port);
  const tls = input.protocol === "https:" ? await tlsTiming(input.hostname,443) : null;
  const fetched = await fetchLimited(input.toString(), {maxBytes:MAX_HTML_BYTES});
  const totalMs = Math.round(performance.now()-start);
  const headers = headerObject(fetched.res.headers);
  const finalUrl = fetched.finalUrl || input.toString();
  const contentType = headers["content-type"] || "";
  const html = /html|xhtml/i.test(contentType) ? fetched.body : "";
  const parsed = html ? extractHtml(html, finalUrl) : {
    title:"",description:"",canonical:null,lang:"",favicon:null,links:[],resources:[],videos:[],forms:[],metas:[],structured:[],headings:{h1:0,h2:0,h3:0},images:[]
  };
  const security = securityAnalysis(headers,html,finalUrl);
  const linkResults = html ? await checkLinks(finalUrl, parsed.links) : [];
  const robotsUrl = new URL("/robots.txt", new URL(finalUrl).origin).toString();
  const sitemapUrl = new URL("/sitemap.xml", new URL(finalUrl).origin).toString();
  const robots = await fetchLimited(robotsUrl,{method:"GET",expectedOrigin:new URL(finalUrl).origin,maxBytes:150000,timeout:5000,accept:"text/plain,*/*;q=0.5"}).catch(()=>null);
  const sitemap = await fetchLimited(sitemapUrl,{method:"GET",expectedOrigin:new URL(finalUrl).origin,maxBytes:500000,timeout:5000,accept:"application/xml,text/xml,*/*;q=0.5"}).catch(()=>null);

  const technologies=detectTechnologies(html,headers,finalUrl);
  const perf=performanceScore(totalMs,Buffer.byteLength(fetched.body));
  const seo=seoScore(parsed);
  const accessibility=accessibilityScore(parsed);
  const sec=scoreSecurity(security);
  const overall=Math.round((sec+perf+seo+accessibility)/4);

  const report={
    id:"WS-"+sha(finalUrl+"|"+Date.now()),
    scannedAt:nowIso(),
    inputUrl:input.toString(),
    finalUrl,
    overview:{
      status:fetched.res.status,
      statusText:fetched.res.statusText,
      contentType,
      responseBytes:Buffer.byteLength(fetched.body),
      redirects:fetched.redirects,
      title:parsed.title,
      description:parsed.description,
      language:parsed.lang,
      canonical:parsed.canonical,
      favicon:parsed.favicon
    },
    timing:{dnsMs:dnsInfo.ms,tcpMs:tcp,tlsMs:tls?.ms ?? null,tlsProtocol:tls?.protocol ?? null,totalMs},
    dns:{hostname:input.hostname,addresses:dnsInfo.addresses},
    headers,
    security:{score:sec,checks:security},
    performance:{score:perf},
    seo:{score:seo,headings:parsed.headings},
    accessibility:{score:accessibility,images:parsed.images.length,imagesWithAlt:parsed.images.filter(x=>x.alt.trim()).length},
    technologies,
    links:{all:parsed.links.slice(0,MAX_LINKS),checked:linkResults,
      internal:parsed.links.filter(x=>x.type==="internal").length,
      external:parsed.links.filter(x=>x.type==="external").length,
      broken:linkResults.filter(x=>!x.ok).length,
      redirects:linkResults.filter(x=>x.redirects>0).length},
    resources:parsed.resources.slice(0,MAX_LINKS),
    videos:parsed.videos,
    forms:parsed.forms,
    meta:parsed.metas,
    structuredData:parsed.structured.slice(0,30),
    robots:{url:robotsUrl,available:Boolean(robots && robots.res.ok),status:robots?.res.status ?? null,content:robots?.body?.slice(0,5000) || ""},
    sitemap:{url:sitemapUrl,available:Boolean(sitemap && sitemap.res.ok),status:sitemap?.res.status ?? null},
    overallScore:overall
  };
  const history=readHistory();
  history.unshift({
    id:report.id,url:report.finalUrl,scannedAt:report.scannedAt,
    overallScore:report.overallScore,securityScore:sec,performanceScore:perf
  });
  writeHistory(history);
  return report;
}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"WebScope Pro",time:nowIso()}));

app.post("/api/analyze", async (req,res)=>{
  try {
    const url=req.body?.url;
    if(!url) return res.status(400).json({error:"URL is required."});
    const report=await analyze(url);
    res.json(report);
  } catch(e) {
    res.status(400).json({error:e.message || "Analysis failed."});
  }
});

app.get("/api/history",(req,res)=>res.json(readHistory()));

app.delete("/api/history",(req,res)=>{
  writeHistory([]);
  res.json({ok:true});
});

app.get("/api/report/:id",(req,res)=>{
  const history=readHistory();
  const found=history.find(x=>x.id===req.params.id);
  if(!found) return res.status(404).json({error:"History record not found. Full report is intentionally not persisted by default."});
  res.json(found);
});

app.use(express.static(path.join(__dirname,"public"),{
  extensions:["html"]
}));

app.get("*", (req,res)=>{
  res.sendFile(path.join(__dirname,"public","index.html"));
});

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({error:"Unexpected server error."});
});

app.listen(PORT,()=>console.log(`WebScope Pro running on http://localhost:${PORT}`));
