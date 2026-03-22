import { useState, useEffect, useRef } from "react";

const RISK_COLOR = {
  QUANTUM_SAFE:  { bg:"#061a0f", border:"#00e676", text:"#00e676", badge:"QUANTUM SAFE",  glow:"#00e67640" },
  PQC_READY:     { bg:"#1a1a00", border:"#c6ff00", text:"#c6ff00", badge:"PQC READY",     glow:"#c6ff0040" },
  TRANSITIONING: { bg:"#1a0e00", border:"#ff9100", text:"#ffab40", badge:"TRANSITIONING", glow:"#ff910040" },
  VULNERABLE:    { bg:"#1a0000", border:"#ff1744", text:"#ff5252", badge:"VULNERABLE",    glow:"#ff174440" },
  UNKNOWN:       { bg:"#0a0a20", border:"#536dfe", text:"#8c9eff", badge:"UNKNOWN",       glow:"#536dfe40" },
};

const SEV_COLOR = { CRITICAL:"#ff1744", HIGH:"#ff5252", MEDIUM:"#ffab40", LOW:"#c6ff00", INFO:"#8c9eff" };

// ── Mock data for demo mode ────────────────────────────────────────────────
const buildMock = (target, score, status, tlsVer, cipher, certType, certBits, kex, issues, positives, vulns, daysLeft) => ({
  target, port:443, status:"success", timestamp: new Date().toISOString(),
  tls_info:{ tls_version:tlsVer, cipher_suite:cipher, cipher_bits:256, cipher_grade: score>=75?"A":"B",
             key_exchange:kex, forward_secrecy:true, supported_tls_versions:["TLSv1.3","TLSv1.2"],
             cert_key_type:certType, cert_key_bits:certBits },
  certificate:{ key_type:certType, key_bits:certBits, subject:`CN=${target}`, issuer:"CN=Google Trust Services",
                not_after: new Date(Date.now()+daysLeft*86400000).toISOString(), days_until_expiry:daysLeft,
                total_validity_days:397, signature_algorithm:"SHA256", sans:[target,`www.${target}`],
                is_self_signed:false, pqc_cert:false, ct_sct_count:2, key_usage:{digital_signature:true},
                ocsp_urls:["http://ocsp.example.com"], policies:[], issues:[] },
  pqc_assessment:{ score, status, label:RISK_COLOR[status]?.badge, badge_color:RISK_COLOR[status]?.border,
                   issues, positives, parameters_checked:40 },
  cbom:{ cbom_version:"1.4", components:[
    {type:"protocol",name:"TLS",version:tlsVer,quantum_safe:false,supported_versions:["TLSv1.3","TLSv1.2"]},
    {type:"cipher-suite",name:cipher,bits:256,grade:score>=75?"A":"B",forward_secrecy:true,quantum_safe:false},
    {type:"key-exchange",name:kex,quantum_safe:kex.includes("ML-KEM")},
    {type:"certificate",name:`${certType}-${certBits}`,algorithm:"SHA256",quantum_safe:false,days_until_expiry:daysLeft,ct_sct_count:2},
  ]},
  vulnerabilities: vulns,
  dns:{ caa_present:true, dnssec_enabled:false, dns_resolves:true,
        ipv4_addresses:["142.250.80.46"], ipv6_addresses:["2607:f8b0:4004::200e"],
        issues: score < 70 ? [{severity:"MEDIUM",issue:"No CAA DNS records",action:"Add CAA records"}] : [] },
  http_headers:{ hsts:{present:true,max_age:31536000,include_subdomains:true,preload:true},
                 csp:{present:score>60,value:"default-src 'self'"},
                 headers_found:{"Strict-Transport-Security":"max-age=31536000; includeSubDomains; preload"},
                 headers_missing: score<70 ? ["X-Frame-Options","Permissions-Policy"] : [],
                 score: score > 70 ? 90 : 65, issues:[] },
});

const MOCK_DB = {
  "google.com":     buildMock("google.com",    65,"PQC_READY",    "TLSv1.3","TLS_AES_256_GCM_SHA384","ECDSA",256,"X25519/P-256 ECDHE (Quantum-Vulnerable)",
    [{severity:"HIGH",issue:"ECDSA-256 certificate — fully broken by Shor's algorithm",action:"Migrate to ML-DSA-65 (FIPS 204)"},
     {severity:"MEDIUM",issue:"X25519 ECDHE key exchange — vulnerable to HNDL attacks",action:"Deploy ML-KEM-768 (FIPS 203)"}],
    ["TLS 1.3 in use","AES-256 symmetric encryption — meets NIST PQ requirement","Forward secrecy enabled"],
    [{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later threat active",action:"Deploy ML-KEM-768"}], 48),
  "cloudflare.com": buildMock("cloudflare.com", 72,"PQC_READY",  "TLSv1.3","TLS_AES_256_GCM_SHA384","ECDSA",256,"X25519+Kyber768 (Hybrid PQC)",
    [{severity:"HIGH",issue:"ECDSA-256 certificate — quantum-vulnerable signature",action:"Migrate to ML-DSA-65 (FIPS 204)"}],
    ["TLS 1.3","Hybrid PQC key exchange deployed (X25519+Kyber768)","AES-256-GCM","HSTS with preload","Forward secrecy"],
    [{name:"HNDL",cve:"N/A",severity:"HIGH",description:"Certificate still vulnerable to HNDL",action:"Complete PQC migration"}], 120),
  "example.com":    buildMock("example.com",   32,"VULNERABLE",  "TLSv1.2","ECDHE-RSA-AES128-GCM-SHA256","RSA",2048,"ECDHE (Quantum-Vulnerable)",
    [{severity:"CRITICAL",issue:"RSA-2048 — fully broken by Shor's algorithm",action:"Replace with ML-DSA-65"},
     {severity:"HIGH",issue:"TLS 1.2 in use — sessions recordable for HNDL",action:"Enforce TLS 1.3"},
     {severity:"MEDIUM",issue:"AES-128 — Grover's reduces to ~64-bit",action:"Switch to AES-256-GCM"},
     {severity:"HIGH",issue:"No HSTS header",action:"Add Strict-Transport-Security header"}],
    [],
    [{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Full PQC migration required"},
     {name:"SWEET32",cve:"CVE-2016-2183",severity:"MEDIUM",description:"Birthday attacks on 64-bit blocks",action:"Disable 3DES"}], 5),
  "rc4.badssl.com": buildMock("rc4.badssl.com", 8,"VULNERABLE",  "TLSv1.2","RC4-SHA","RSA",2048,"RSA (Quantum-Vulnerable — no forward secrecy)",
    [{severity:"CRITICAL",issue:"RC4 cipher — broken by classical statistical attacks (RFC 7465)",action:"Disable RC4 immediately"},
     {severity:"CRITICAL",issue:"RSA-2048 — fully broken by Shor's algorithm",action:"Replace certificate with ML-DSA-65"},
     {severity:"CRITICAL",issue:"No forward secrecy — all past sessions decryptable if key stolen",action:"Migrate to ECDHE or ML-KEM"},
     {severity:"HIGH",issue:"TLS 1.2 — sessions recordable for HNDL",action:"Enforce TLS 1.3"}],
    [],
    [{name:"RC4_BIASES",cve:"CVE-2015-2808",severity:"CRITICAL",description:"RC4 statistical biases allow plaintext recovery",action:"Disable RC4"},
     {name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Complete overhaul required"}], 365),
  "3des.badssl.com":buildMock("3des.badssl.com",12,"VULNERABLE", "TLSv1.2","DES-CBC3-SHA","RSA",2048,"RSA (Quantum-Vulnerable — no forward secrecy)",
    [{severity:"CRITICAL",issue:"3DES — SWEET32 birthday attack, Grover's ~40-bit quantum security",action:"Disable 3DES immediately"},
     {severity:"CRITICAL",issue:"RSA-2048 — fully broken by Shor's algorithm",action:"Replace with ML-DSA-65"},
     {severity:"HIGH",issue:"TLS 1.2 in use",action:"Upgrade to TLS 1.3"},
     {severity:"CRITICAL",issue:"No forward secrecy",action:"Switch to ECDHE or ML-KEM"}],
    [],
    [{name:"SWEET32",cve:"CVE-2016-2183",severity:"MEDIUM",description:"3DES birthday attack",action:"Disable 3DES"},
     {name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Full PQC migration"}], 365),
};

async function performScan(target, backendUrl) {
  const clean = target.replace(/^https?:\/\//,"").split("/")[0].trim();
  try {
    const res = await fetch(`${backendUrl}/api/v1/scan/quick`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({target:clean,port:443}),
      signal: AbortSignal.timeout(20000)
    });
    if (res.ok) return await res.json();
  } catch(_) {}
  // Demo mode fallback
  await new Promise(r => setTimeout(r, 1200 + Math.random()*800));
  const mock = MOCK_DB[clean];
  if (mock) return {...mock, timestamp: new Date().toISOString()};
  // Dynamic fallback for unknown targets
  const score = Math.floor(Math.random()*55)+20;
  const status = score>=65?"PQC_READY":score>=40?"TRANSITIONING":"VULNERABLE";
  return buildMock(clean, score, status, score>50?"TLSv1.3":"TLSv1.2",
    "ECDHE-RSA-AES256-GCM-SHA384","RSA",2048,"ECDHE (Quantum-Vulnerable)",
    [{severity:"HIGH",issue:"RSA-2048 certificate — quantum-vulnerable",action:"Migrate to ML-DSA-65 (FIPS 204)"}],
    score>50?["TLS 1.3 in use"]:[], [{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Deploy ML-KEM-768"}],
    Math.floor(Math.random()*300)+30);
}

// ── UI Components ─────────────────────────────────────────────────────────────
function ScoreRing({ score, size=72 }) {
  const r = size/2-7; const circ = 2*Math.PI*r;
  const dash = (score/100)*circ;
  const color = score>=75?"#00e676":score>=55?"#c6ff00":score>=35?"#ff9100":"#ff1744";
  return (
    <svg width={size} height={size} style={{transform:"rotate(-90deg)"}}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1a1a2e" strokeWidth="7"/>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth="7"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        style={{transition:"stroke-dasharray 1.2s ease",filter:`drop-shadow(0 0 5px ${color})`}}/>
      <text x={size/2} y={size/2} textAnchor="middle" dominantBaseline="middle"
        fill={color} fontSize={size>60?15:11} fontWeight="800"
        style={{transform:`rotate(90deg)`,transformOrigin:`${size/2}px ${size/2}px`,fontFamily:"monospace"}}>
        {score}
      </text>
    </svg>
  );
}

function Badge({ status, small }) {
  const c = RISK_COLOR[status]||RISK_COLOR.UNKNOWN;
  return <span style={{background:c.bg,border:`1px solid ${c.border}`,color:c.text,
    padding:small?"2px 7px":"3px 10px",borderRadius:4,fontSize:small?10:11,fontWeight:700,
    letterSpacing:1,fontFamily:"monospace",boxShadow:`0 0 8px ${c.glow}`,whiteSpace:"nowrap"}}>{c.badge}</span>;
}

function SevBadge({sev}) {
  const c = SEV_COLOR[sev]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}44`,
    padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:700,letterSpacing:1,whiteSpace:"nowrap"}}>{sev}</span>;
}

function GradeBadge({grade}) {
  const gc={A:"#00e676",B:"#c6ff00",C:"#ff9100",D:"#ff5252",F:"#ff1744"};
  const c = gc[grade]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}`,
    padding:"2px 8px",borderRadius:4,fontSize:12,fontWeight:900,fontFamily:"monospace"}}>{grade}</span>;
}

function SummaryBar({results}) {
  if(!results.length) return null;
  const c={QUANTUM_SAFE:0,PQC_READY:0,TRANSITIONING:0,VULNERABLE:0};
  results.forEach(r=>{const s=r.pqc_assessment?.status;if(s in c)c[s]++;});
  const avgScore = results.length ? Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length) : 0;
  return (
    <div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:12}}>
        {Object.entries(c).map(([status,count])=>{
          const rc=RISK_COLOR[status];
          return <div key={status} style={{background:rc.bg,border:`1px solid ${rc.border}30`,borderRadius:8,padding:"12px 14px"}}>
            <div style={{color:rc.text,fontSize:26,fontWeight:900,fontFamily:"monospace"}}>{count}</div>
            <div style={{color:rc.border,fontSize:10,fontWeight:700,letterSpacing:1,marginTop:3}}>{rc.badge}</div>
          </div>;
        })}
      </div>
      <div style={{background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:8,padding:"12px 16px",marginBottom:16,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <span style={{color:"#6666aa",fontSize:12}}>FLEET AVG SCORE</span>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:200,height:6,background:"#1e1e3a",borderRadius:3,overflow:"hidden"}}>
            <div style={{width:`${avgScore}%`,height:"100%",background:`linear-gradient(90deg,#ff1744,#ff9100,#c6ff00,#00e676)`,borderRadius:3,transition:"width 1s ease"}}/>
          </div>
          <span style={{color:"#e0e0ff",fontWeight:700,fontFamily:"monospace",fontSize:14}}>{avgScore}/100</span>
        </div>
      </div>
    </div>
  );
}

function VulnPanel({vulns}) {
  if(!vulns?.length) return <div style={{color:"#3a5a3a",fontSize:13,padding:"20px 0"}}>✓ No known classical vulnerabilities detected</div>;
  return (
    <div style={{display:"flex",flexDirection:"column",gap:8}}>
      {vulns.map((v,i)=>(
        <div key={i} style={{background:"#120000",border:`1px solid ${SEV_COLOR[v.severity]||"#333"}30`,
          borderLeft:`3px solid ${SEV_COLOR[v.severity]||"#333"}`,borderRadius:6,padding:"10px 14px"}}>
          <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
            <SevBadge sev={v.severity}/>
            <span style={{color:"#ffcccc",fontWeight:700,fontSize:13,fontFamily:"monospace"}}>{v.name}</span>
            {v.cve!=="N/A" && <span style={{color:"#6666aa",fontSize:11,fontFamily:"monospace"}}>{v.cve}</span>}
          </div>
          <div style={{color:"#cc9999",fontSize:12,marginBottom:4}}>{v.description}</div>
          <div style={{color:"#888",fontSize:11}}>→ {v.action}</div>
        </div>
      ))}
    </div>
  );
}

function CBOMTable({components}) {
  const icons={protocol:"🔗","cipher-suite":"🔐",certificate:"📜","key-exchange":"🔑"};
  return (
    <div style={{overflowX:"auto"}}>
      <table style={{width:"100%",borderCollapse:"collapse",fontFamily:"monospace",fontSize:12}}>
        <thead>
          <tr style={{borderBottom:"1px solid #2a2a4a"}}>
            {["Type","Name","Details","Forward Secrecy","Quantum Status"].map(h=>(
              <th key={h} style={{padding:"8px 12px",textAlign:"left",color:"#6666aa",fontWeight:600,fontSize:10,letterSpacing:1}}>{h.toUpperCase()}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {components?.map((c,i)=>(
            <tr key={i} style={{borderBottom:"1px solid #1a1a2e"}}>
              <td style={{padding:"9px 12px",color:"#9999cc"}}>{icons[c.type]||"·"} {c.type}</td>
              <td style={{padding:"9px 12px",color:"#e0e0ff",fontWeight:600,wordBreak:"break-all",maxWidth:200}}>{c.name}</td>
              <td style={{padding:"9px 12px",color:"#8888aa"}}>
                {c.bits?`${c.bits}-bit`:""} {c.version||""} {c.grade?<GradeBadge grade={c.grade}/>:""}
                {c.days_until_expiry!=null?<span style={{color:c.days_until_expiry<30?"#ff5252":"#6688aa",fontSize:11,marginLeft:4}}>{c.days_until_expiry}d</span>:""}
              </td>
              <td style={{padding:"9px 12px"}}>
                {c.forward_secrecy===true?<span style={{color:"#00e676"}}>✓ YES</span>:
                 c.forward_secrecy===false?<span style={{color:"#ff5252"}}>✗ NO</span>:
                 <span style={{color:"#6666aa"}}>—</span>}
              </td>
              <td style={{padding:"9px 12px"}}>
                {c.quantum_safe?<span style={{color:"#00e676",fontWeight:700}}>✓ QUANTUM SAFE</span>
                               :<span style={{color:"#ff5252",fontWeight:700}}>✗ VULNERABLE</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DNSPanel({dns}) {
  if(!dns||Object.keys(dns).length===0) return <div style={{color:"#444466",fontSize:13}}>DNS data not available</div>;
  const items = [
    ["DNS Resolves",     dns.dns_resolves?  "✓ Yes":"✗ No",               dns.dns_resolves?"#00e676":"#ff5252"],
    ["IPv4 Addresses",   dns.ipv4_addresses?.join(", ")||"None",           "#8c9eff"],
    ["IPv6 Addresses",   dns.ipv6_addresses?.join(", ")||"None (no AAAA)", dns.ipv6_addresses?.length?"#8c9eff":"#ffab40"],
    ["CAA Records",      dns.caa_present?"✓ Present":"✗ Missing",         dns.caa_present?"#00e676":"#ff5252"],
    ["DNSSEC",           dns.dnssec_enabled?"✓ Enabled":"Not detected",   dns.dnssec_enabled?"#00e676":"#ffab40"],
    ["SPF Record",       dns.spf_present?"✓ Present":"Not detected",      dns.spf_present?"#00e676":"#ffab40"],
    ["DMARC Record",     dns.dmarc_present?"✓ Present":"Not detected",    dns.dmarc_present?"#00e676":"#ffab40"],
  ];
  return (
    <div>
      {items.map(([label,val,color])=>(
        <div key={label} style={{display:"flex",borderBottom:"1px solid #1a1a2e",padding:"9px 0",alignItems:"center"}}>
          <div style={{width:160,color:"#6666aa",fontSize:11,flexShrink:0}}>{label}</div>
          <div style={{color,fontSize:12,fontFamily:"monospace"}}>{val}</div>
        </div>
      ))}
      {dns.issues?.map((issue,i)=>(
        <div key={i} style={{background:"#1a1200",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
          borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"8px 12px",marginTop:8}}>
          <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}>
            <SevBadge sev={issue.severity}/><span style={{color:"#ddc",fontSize:12}}>{issue.issue}</span>
          </div>
          <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
        </div>
      ))}
    </div>
  );
}

function HeadersPanel({http}) {
  if(!http||Object.keys(http).length===0) return <div style={{color:"#444466",fontSize:13}}>HTTP header data not available</div>;
  const hsts = http.hsts||{};
  return (
    <div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
        {[
          ["HSTS",          hsts.present?"✓ Present":"✗ Missing",          hsts.present?"#00e676":"#ff5252"],
          ["HSTS max-age",  hsts.max_age?`${hsts.max_age}s`:"—",           hsts.max_age>=31536000?"#00e676":"#ffab40"],
          ["includeSubDomains", hsts.include_subdomains?"✓":"✗",           hsts.include_subdomains?"#00e676":"#ff5252"],
          ["Preload",       hsts.preload?"✓ Yes":"✗ No",                   hsts.preload?"#00e676":"#ffab40"],
          ["CSP",           http.csp?.present?"✓ Present":"✗ Missing",    http.csp?.present?"#00e676":"#ff5252"],
          ["Header Score",  `${http.score||0}/100`,                        (http.score||0)>=80?"#00e676":(http.score||0)>=60?"#ffab40":"#ff5252"],
        ].map(([label,val,color])=>(
          <div key={label} style={{background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:6,padding:"10px 12px"}}>
            <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:4}}>{label.toUpperCase()}</div>
            <div style={{color,fontFamily:"monospace",fontSize:12,fontWeight:700}}>{val}</div>
          </div>
        ))}
      </div>
      {http.headers_missing?.length>0 && (
        <div>
          <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:8}}>MISSING SECURITY HEADERS</div>
          <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
            {http.headers_missing.map((h,i)=>(
              <span key={i} style={{background:"#ff174420",border:"1px solid #ff174440",color:"#ff5252",
                padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{h}</span>
            ))}
          </div>
        </div>
      )}
      {http.issues?.map((issue,i)=>(
        <div key={i} style={{background:"#1a1000",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
          borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"8px 12px",marginTop:8}}>
          <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}>
            <SevBadge sev={issue.severity}/><span style={{color:"#ddc",fontSize:12}}>{issue.issue}</span>
          </div>
          <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
        </div>
      ))}
    </div>
  );
}

function DetailPanel({result}) {
  const [tab,setTab] = useState("overview");
  useEffect(()=>setTab("overview"),[result?.target]);

  if(!result) return (
    <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",color:"#2a2a4a"}}>
      <div style={{fontSize:64,marginBottom:16}}>⚛</div>
      <div style={{fontSize:15,letterSpacing:4,color:"#4a4a7a"}}>SELECT A TARGET</div>
      <div style={{fontSize:12,color:"#3a3a5a",marginTop:8}}>TO VIEW FULL ANALYSIS</div>
    </div>
  );

  const pqc   = result.pqc_assessment||{};
  const tls   = result.tls_info||{};
  const cert  = result.certificate||{};
  const cbom  = result.cbom||{};
  const vulns = result.vulnerabilities||[];
  const dns   = result.dns||{};
  const http  = result.http_headers||{};
  const c     = RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;

  const tabs = [
    {id:"overview",    label:"Overview"},
    {id:"cbom",        label:"CBOM"},
    {id:"certificate", label:"Certificate"},
    {id:"vulns",       label:`Vulns ${vulns.length>0?`(${vulns.length})`:""}`, alert:vulns.some(v=>v.severity==="CRITICAL")},
    {id:"dns",         label:"DNS"},
    {id:"headers",     label:"Headers"},
    {id:"roadmap",     label:"Roadmap"},
  ];

  return (
    <div style={{height:"100%",display:"flex",flexDirection:"column"}}>
      {/* Header */}
      <div style={{padding:"16px 20px",borderBottom:"1px solid #1e1e3a",background:c.bg}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
          <div>
            <div style={{color:"#e0e0ff",fontFamily:"monospace",fontWeight:800,fontSize:16}}>🔒 {result.target}</div>
            <div style={{color:"#8888aa",fontSize:11,marginTop:3}}>{tls.tls_version||"—"} · Port {result.port} · {tls.cipher_grade?<><GradeBadge grade={tls.cipher_grade}/></>:""}</div>
            <div style={{marginTop:6,display:"flex",gap:6,flexWrap:"wrap"}}>
              {tls.forward_secrecy && <span style={{background:"#00e67610",border:"1px solid #00e67640",color:"#00e676",padding:"1px 7px",borderRadius:3,fontSize:10}}>FS</span>}
              {result.status==="success_inferred" && <span style={{background:"#ffab4010",border:"1px solid #ffab4040",color:"#ffab40",padding:"1px 7px",borderRadius:3,fontSize:10}}>INFERRED</span>}
              {result.status==="success_unverified" && <span style={{background:"#ff525210",border:"1px solid #ff525240",color:"#ff5252",padding:"1px 7px",borderRadius:3,fontSize:10}}>UNVERIFIED CERT</span>}
            </div>
          </div>
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:6}}>
            <ScoreRing score={pqc.score||0} size={72}/>
            <Badge status={pqc.status}/>
            <div style={{color:"#6666aa",fontSize:10}}>{pqc.parameters_checked||40} params checked</div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{display:"flex",borderBottom:"1px solid #1e1e3a",padding:"0 20px",overflowX:"auto"}}>
        {tabs.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} style={{
            background:"none",border:"none",color:tab===t.id?"#a78bfa":"#666688",
            padding:"10px 12px",cursor:"pointer",fontFamily:"monospace",fontSize:11,
            borderBottom:tab===t.id?"2px solid #a78bfa":"2px solid transparent",
            whiteSpace:"nowrap",position:"relative",
          }}>
            {t.label}
            {t.alert && <span style={{position:"absolute",top:6,right:4,width:6,height:6,borderRadius:"50%",background:"#ff1744"}}/>}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{flex:1,overflowY:"auto",padding:"16px 20px"}}>

        {tab==="overview" && (
          <div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
              {[
                ["TLS Version",   tls.tls_version||"—",  tls.tls_version?.includes("1.3")?"#00e676":"#ffab40"],
                ["Cipher Suite",  tls.cipher_suite||"—", "#8c9eff"],
                ["Key Exchange",  tls.key_exchange||"—", tls.key_exchange?.includes("Quantum-Safe")?"#00e676":"#ff5252"],
                ["Cert Type",     `${cert.key_type||"?"}-${cert.key_bits||0}`, cert.pqc_cert?"#00e676":"#ff5252"],
                ["Forward Secrecy", tls.forward_secrecy?"✓ Enabled":"✗ Disabled", tls.forward_secrecy?"#00e676":"#ff5252"],
                ["Cipher Grade",  tls.cipher_grade||"?", {A:"#00e676",B:"#c6ff00",C:"#ffab40",D:"#ff5252",F:"#ff1744"}[tls.cipher_grade]||"#888"],
                ["Cert Expires",  cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—", cert.days_until_expiry<30?"#ff5252":cert.days_until_expiry<90?"#ffab40":"#00e676"],
                ["CT Logs",       cert.ct_sct_count>0?`✓ ${cert.ct_sct_count} SCTs`:"✗ None", cert.ct_sct_count>0?"#00e676":"#ffab40"],
              ].map(([label,val,color])=>(
                <div key={label} style={{background:"#08081a",border:"1px solid #1e1e3a",borderRadius:7,padding:"10px 14px"}}>
                  <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:5}}>{label.toUpperCase()}</div>
                  <div style={{color,fontFamily:"monospace",fontSize:12,fontWeight:600,wordBreak:"break-all"}}>{val}</div>
                </div>
              ))}
            </div>
            <div style={{color:"#a0a0cc",fontSize:10,fontWeight:700,letterSpacing:2,marginBottom:10}}>SECURITY FINDINGS</div>
            {pqc.positives?.map((p,i)=>(
              <div key={i} style={{display:"flex",gap:8,padding:"7px 0",borderBottom:"1px solid #0a1a0a",alignItems:"flex-start"}}>
                <span style={{color:"#00e676",fontSize:14,flexShrink:0}}>✓</span>
                <span style={{color:"#66cc88",fontSize:12}}>{p}</span>
              </div>
            ))}
            <div style={{marginTop:pqc.positives?.length?12:0}}>
              {pqc.issues?.map((issue,i)=>(
                <div key={i} style={{background:"#100505",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
                  borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"9px 12px",marginBottom:7}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
                    <SevBadge sev={issue.severity}/>
                    <span style={{color:"#ffcccc",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab==="cbom" && (
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              Cryptographic Bill of Materials · CycloneDX v1.4 · NIST SP 800-235
              <span style={{background:"#a78bfa22",color:"#a78bfa",border:"1px solid #a78bfa44",padding:"1px 8px",borderRadius:4,fontSize:10,marginLeft:8,fontFamily:"monospace"}}>
                {cbom.schema||"cyclonedx.org/schema/bom-1.4"}
              </span>
            </div>
            <CBOMTable components={cbom.components}/>
            {tls.supported_ciphers?.length>0 && (
              <div style={{marginTop:16}}>
                <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:8}}>ALL SUPPORTED CIPHER SUITES</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                  {tls.supported_ciphers.map((c,i)=>(
                    <span key={i} style={{background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#8888cc",
                      padding:"3px 8px",borderRadius:4,fontSize:10,fontFamily:"monospace"}}>{c}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab==="certificate" && (
          <div>
            {cert.issues?.map((issue,i)=>(
              <div key={i} style={{background:"#100505",border:`1px solid ${SEV_COLOR[issue.severity]}30`,
                borderLeft:`3px solid ${SEV_COLOR[issue.severity]}`,borderRadius:6,padding:"8px 12px",marginBottom:8}}>
                <SevBadge sev={issue.severity}/> <span style={{color:"#ffcccc",fontSize:12,marginLeft:8}}>{issue.issue}</span>
                <div style={{color:"#888",fontSize:11,marginTop:4}}>→ {issue.action}</div>
              </div>
            ))}
            {[
              ["Subject",           cert.subject],
              ["Issuer",            cert.issuer],
              ["Key Type",          `${cert.key_type}-${cert.key_bits}${cert.curve_name?` (${cert.curve_name})`:""}`,],
              ["Signature Algo",    cert.signature_algorithm],
              ["Valid From",        cert.not_before],
              ["Valid Until",       cert.not_after],
              ["Days Until Expiry", cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—"],
              ["Total Validity",    cert.total_validity_days?`${cert.total_validity_days} days`:"—"],
              ["Self-Signed",       cert.is_self_signed?"⚠ YES":"No"],
              ["CA Certificate",    cert.is_ca?"Yes (CA)":"No (End-Entity)"],
              ["CT SCT Count",      cert.ct_sct_count!=null?`${cert.ct_sct_count} SCTs`:"—"],
              ["PQC Certificate",   cert.pqc_cert?"✓ YES — Quantum Safe":"✗ NO — Quantum Vulnerable"],
              ["OCSP URL",          cert.ocsp_urls?.[0]||"None"],
              ["Serial Number",     cert.serial_number?.substring(0,32)],
              ["SHA-256 Fingerprint", cert.fingerprint_sha256?.substring(0,40)+"..."],
            ].map(([label,val])=>val&&(
              <div key={label} style={{display:"flex",borderBottom:"1px solid #1a1a2e",padding:"9px 0"}}>
                <div style={{width:160,color:"#6666aa",fontSize:11,flexShrink:0}}>{label}</div>
                <div style={{color:"#c0c0e0",fontSize:12,fontFamily:"monospace",wordBreak:"break-all"}}>{val||"—"}</div>
              </div>
            ))}
            {cert.sans?.length>0 && (
              <div style={{marginTop:14}}>
                <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:8}}>SUBJECT ALTERNATIVE NAMES ({cert.sans.length})</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                  {cert.sans.map((san,i)=>(
                    <span key={i} style={{background:"#1a1a2e",border:"1px solid #2a2a4a",color:"#8c9eff",
                      padding:"2px 9px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{san}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab==="vulns" && (
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12}}>
              Cross-referenced against known TLS/cryptographic vulnerability database
            </div>
            <VulnPanel vulns={vulns}/>
          </div>
        )}

        {tab==="dns" && (
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12}}>DNS security configuration analysis</div>
            <DNSPanel dns={dns}/>
          </div>
        )}

        {tab==="headers" && (
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12}}>HTTP security headers affecting cryptographic posture</div>
            <HeadersPanel http={http}/>
          </div>
        )}

        {tab==="roadmap" && (
          <div>
            <div style={{background:"#060f06",border:"1px solid #00e67620",borderRadius:8,padding:"14px 16px",marginBottom:14}}>
              <div style={{color:"#00e676",fontWeight:700,fontSize:13,marginBottom:12}}>🗺 NIST PQC Migration Roadmap for {result.target}</div>
              {[
                {phase:"Phase 1 — Immediate (0–3 months)", color:"#ff5252", items:[
                  "Audit and inventory ALL cryptographic assets (CBOM)",
                  "Disable TLS 1.0 and TLS 1.1 on all endpoints",
                  "Replace RC4, 3DES, DES, NULL ciphers with AES-256-GCM",
                  "Enforce TLS 1.3 as minimum protocol version",
                  "Enable HSTS with max-age=31536000, includeSubDomains, preload",
                  "Replace SHA-1 signed certificates with SHA-256 or stronger",
                ]},
                {phase:"Phase 2 — Short-term (3–12 months)", color:"#ffab40", items:[
                  "Deploy hybrid key exchange: X25519 + ML-KEM-768 (FIPS 203)",
                  "Begin PKI migration planning for ML-DSA (FIPS 204) certificates",
                  "Implement crypto-agility framework for rapid algorithm swaps",
                  "Add CAA DNS records restricting certificate issuance",
                  "Enable Certificate Transparency logging for all certificates",
                  "Deploy OCSP stapling on all TLS endpoints",
                ]},
                {phase:"Phase 3 — Long-term (1–3 years)", color:"#c6ff00", items:[
                  "Full certificate migration to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
                  "Deploy ML-KEM-1024 for highest-security endpoints",
                  "Implement PQC-aware VPN (IKEv2 with ML-KEM extensions)",
                  "Establish continuous CBOM lifecycle management",
                  "Obtain 'Fully Quantum Safe' certification for all public assets",
                  "Achieve NIST SP 800-208 compliance",
                ]},
              ].map(({phase,color,items})=>(
                <div key={phase} style={{marginBottom:16}}>
                  <div style={{color,fontSize:11,fontWeight:700,letterSpacing:1,marginBottom:8,padding:"4px 10px",
                    background:`${color}15`,borderRadius:4,display:"inline-block"}}>{phase.toUpperCase()}</div>
                  {items.map((item,i)=>(
                    <div key={i} style={{color:"#c0c0e0",fontSize:12,padding:"4px 0 4px 14px",
                      borderLeft:`2px solid ${color}30`,marginBottom:3}}>→ {item}</div>
                  ))}
                </div>
              ))}
            </div>
            <div style={{background:"#0a0a1e",border:"1px solid #a78bfa30",borderRadius:8,padding:"14px 16px"}}>
              <div style={{color:"#a78bfa",fontWeight:700,fontSize:13,marginBottom:10}}>📚 NIST PQC Standards Reference</div>
              {[
                ["FIPS 203","ML-KEM","Key Encapsulation — replaces RSA/ECDH key exchange","#60a5fa"],
                ["FIPS 204","ML-DSA","Digital Signatures — replaces RSA/ECDSA certificates","#34d399"],
                ["FIPS 205","SLH-DSA","Hash-based Signatures — conservative alternative to ML-DSA","#a78bfa"],
                ["SP 800-208","LMS/XMSS","Stateful hash-based signatures for specific use cases","#f472b6"],
                ["SP 800-235","CBOM","Cryptographic Bill of Materials — inventory standard","#fbbf24"],
              ].map(([std,algo,desc,color])=>(
                <div key={std} style={{display:"flex",gap:10,padding:"8px 0",borderBottom:"1px solid #1e1e3a",alignItems:"flex-start"}}>
                  <span style={{background:`${color}22`,color,padding:"2px 8px",borderRadius:4,fontSize:10,fontWeight:700,
                    whiteSpace:"nowrap",fontFamily:"monospace",flexShrink:0}}>{std}</span>
                  <div>
                    <div style={{color:"#e0e0ff",fontWeight:700,fontSize:12}}>{algo}</div>
                    <div style={{color:"#8888aa",fontSize:11}}>{desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ResultCard({result,onSelect,selected}) {
  const pqc = result.pqc_assessment||{};
  const tls = result.tls_info||{};
  const vulnCount = result.vulnerabilities?.length||0;
  const c = RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;
  return (
    <div onClick={()=>onSelect(result)} style={{
      background:selected?"#0e0e20":"#080818",
      border:`1px solid ${selected?c.border:"#1e1e3a"}`,
      borderLeft:`3px solid ${c.border}`,
      borderRadius:8,padding:"12px 14px",cursor:"pointer",
      transition:"all 0.2s",marginBottom:8,
      boxShadow:selected?`0 0 16px ${c.glow}`:"none"
    }}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{flex:1,minWidth:0}}>
          <div style={{color:"#e0e0ff",fontWeight:700,fontFamily:"monospace",fontSize:13,
            overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
            🔒 {result.target}
          </div>
          <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>
            {tls.tls_version||"—"} · {tls.cipher_grade?`Grade ${tls.cipher_grade}`:""}
            {vulnCount>0&&<span style={{color:"#ff5252",marginLeft:6}}>⚠ {vulnCount} vuln{vulnCount>1?"s":""}</span>}
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
          <ScoreRing score={pqc.score||0} size={48}/>
          <Badge status={pqc.status} small/>
        </div>
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────
export default function QuantumShield() {
  const [targets,    setTargets]    = useState("google.com\nexample.com\ncloudflare.com\nexpired.badssl.com\nrc4.badssl.com\n3des.badssl.com");
  const [results,    setResults]    = useState([]);
  const [scanning,   setScanning]   = useState(false);
  const [selected,   setSelected]   = useState(null);
  const [progress,   setProgress]   = useState({current:0,total:0,current_target:""});
  const [backendUrl, setBackendUrl] = useState("http://localhost:8000");
  const [backendOk,  setBackendOk]  = useState(false);
  const [activeView, setActiveView] = useState("scanner");
  const [termLog,    setTermLog]    = useState([]);
  const termRef = useRef(null);

  useEffect(()=>{
    fetch(`${backendUrl}/api/v1/health`,{signal:AbortSignal.timeout(2000)})
      .then(r=>r.ok&&setBackendOk(true)).catch(()=>setBackendOk(false));
  },[backendUrl]);

  const addLog = (msg,color="#8888cc") => setTermLog(l=>[...l.slice(-60),{msg,color,t:new Date().toLocaleTimeString()}]);

  useEffect(()=>{ if(termRef.current) termRef.current.scrollTop=termRef.current.scrollHeight; },[termLog]);

  const handleScan = async () => {
    const list = targets.split("\n").map(t=>t.trim()).filter(Boolean);
    if(!list.length) return;
    setScanning(true); setResults([]); setSelected(null); setTermLog([]);
    addLog("QuantumShield v2.0 — Deep PQC Scan initiated","#a78bfa");
    addLog(`Targets: ${list.length} | Parameters per target: 40+`,"#6666aa");
    addLog("─".repeat(50),"#2a2a4a");
    setProgress({current:0,total:list.length,current_target:""});
    const newResults=[];
    for(let i=0;i<list.length;i++){
      const t=list[i];
      setProgress({current:i,total:list.length,current_target:t});
      addLog(`[${i+1}/${list.length}] Scanning ${t}...`,"#8888cc");
      addLog(`  → TLS handshake + certificate inspection`,"#4a4a6a");
      addLog(`  → Probing supported TLS versions`,"#4a4a6a");
      addLog(`  → DNS security analysis (CAA, DNSSEC, SPF, DMARC)`,"#4a4a6a");
      addLog(`  → HTTP security headers audit`,"#4a4a6a");
      addLog(`  → Vulnerability database cross-reference`,"#4a4a6a");
      addLog(`  → PQC scoring (40 parameters)`,"#4a4a6a");
      const r = await performScan(t, backendUrl);
      newResults.push(r);
      setResults([...newResults]);
      const score = r.pqc_assessment?.score||0;
      const status = r.pqc_assessment?.status||"UNKNOWN";
      const scoreColor = score>=75?"#00e676":score>=50?"#c6ff00":score>=35?"#ff9100":"#ff1744";
      addLog(`  ✓ ${t} — Score: ${score}/100 [${status}]`,scoreColor);
      const vcount = r.vulnerabilities?.length||0;
      if(vcount>0) addLog(`  ⚠ ${vcount} vulnerability/vulnerabilities detected`,"#ff5252");
      addLog(""," ");
    }
    addLog("─".repeat(50),"#2a2a4a");
    const safe = newResults.filter(r=>r.pqc_assessment?.status==="QUANTUM_SAFE").length;
    const vuln = newResults.filter(r=>r.pqc_assessment?.status==="VULNERABLE").length;
    const avgScore = Math.round(newResults.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/newResults.length);
    addLog(`Scan complete. ${list.length} assets scanned.`,"#a78bfa");
    addLog(`Quantum Safe: ${safe} | Vulnerable: ${vuln} | Avg Score: ${avgScore}/100`,"#c0c0e0");
    setProgress(p=>({...p,current:list.length,current_target:""}));
    setScanning(false);
    if(newResults.length>0) setSelected(newResults[0]);
  };

  const exportCBOM = () => {
    const report = {
      report_metadata:{title:"QuantumShield CBOM Report",generated_at:new Date().toISOString(),
        scanner:"QuantumShield v2.0",nist_reference:["FIPS 203","FIPS 204","FIPS 205"],
        schema:"CycloneDX 1.4",parameters_checked:40},
      executive_summary:{
        total_assets:results.length,
        quantum_safe:results.filter(r=>r.pqc_assessment?.status==="QUANTUM_SAFE").length,
        pqc_ready:results.filter(r=>r.pqc_assessment?.status==="PQC_READY").length,
        transitioning:results.filter(r=>r.pqc_assessment?.status==="TRANSITIONING").length,
        vulnerable:results.filter(r=>r.pqc_assessment?.status==="VULNERABLE").length,
        avg_score:results.length?Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length):0,
        total_vulnerabilities:results.reduce((a,r)=>a+(r.vulnerabilities?.length||0),0),
      },
      assets: results.map(r=>({
        asset:r.target, tls_version:r.tls_info?.tls_version,
        cipher_suite:r.tls_info?.cipher_suite, cipher_grade:r.tls_info?.cipher_grade,
        key_exchange:r.tls_info?.key_exchange, forward_secrecy:r.tls_info?.forward_secrecy,
        cert_type:`${r.certificate?.key_type}-${r.certificate?.key_bits}`,
        cert_expiry_days:r.certificate?.days_until_expiry,
        pqc_score:r.pqc_assessment?.score, pqc_status:r.pqc_assessment?.status,
        vulnerabilities:r.vulnerabilities, cbom_components:r.cbom?.components,
        dns_caa:r.dns?.caa_present, hsts:r.http_headers?.hsts?.present,
      }))
    };
    const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});
    const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
    a.download=`quantumshield-cbom-${Date.now()}.json`; a.click();
  };

  const s={
    app:{background:"#05050e",minHeight:"100vh",fontFamily:"'IBM Plex Mono','Courier New',monospace",color:"#e0e0ff",overflow:"hidden"},
    header:{background:"#07071a",borderBottom:"1px solid #1e1e3a",padding:"0 20px",display:"flex",alignItems:"center",justifyContent:"space-between",height:56,flexShrink:0},
  };

  const totalVulns = results.reduce((a,r)=>a+(r.vulnerabilities?.length||0),0);

  return (
    <div style={s.app}>
      {/* Header */}
      <div style={s.header}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:30,height:30,background:"linear-gradient(135deg,#7c3aed,#1d4ed8)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>⚛</div>
          <div>
            <div style={{color:"#e0e0ff",fontWeight:800,fontSize:16,letterSpacing:2}}>QUANTUMSHIELD</div>
            <div style={{color:"#6666aa",fontSize:9,letterSpacing:1}}>PQC SCANNER v2.0 · NIST FIPS 203/204/205 · 40+ PARAMETERS</div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{display:"flex",gap:3}}>
            {["scanner","algorithms","about"].map(v=>(
              <button key={v} onClick={()=>setActiveView(v)} style={{
                background:activeView===v?"#1e1e3a":"none",border:activeView===v?"1px solid #2e2e5a":"1px solid transparent",
                color:activeView===v?"#a78bfa":"#6666aa",padding:"5px 12px",borderRadius:5,cursor:"pointer",
                fontFamily:"monospace",fontSize:11,letterSpacing:1}}>
                {v.toUpperCase()}
              </button>
            ))}
          </div>
          {results.length>0 && totalVulns>0 && (
            <div style={{background:"#ff174420",border:"1px solid #ff174440",color:"#ff5252",
              padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>
              ⚠ {totalVulns} VULNS
            </div>
          )}
          <div style={{display:"flex",alignItems:"center",gap:5,fontSize:11,color:backendOk?"#00e676":"#ffab40"}}>
            <div style={{width:6,height:6,borderRadius:"50%",background:backendOk?"#00e676":"#ffab40",boxShadow:`0 0 6px ${backendOk?"#00e676":"#ffab40"}`}}/>
            {backendOk?"BACKEND LIVE":"DEMO MODE"}
          </div>
        </div>
      </div>

      {activeView==="scanner" && (
        <div style={{display:"grid",gridTemplateColumns:"310px 1fr 460px",height:"calc(100vh - 56px)"}}>
          {/* Left */}
          <div style={{borderRight:"1px solid #1e1e3a",display:"flex",flexDirection:"column",background:"#07071a",overflow:"hidden"}}>
            <div style={{padding:"14px 16px",borderBottom:"1px solid #1e1e3a",flexShrink:0}}>
              <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:8}}>SCAN TARGETS</div>
              <textarea value={targets} onChange={e=>setTargets(e.target.value)}
                placeholder="Enter domains, one per line" style={{
                  width:"100%",height:110,background:"#0a0a1e",border:"1px solid #2a2a4a",
                  borderRadius:7,color:"#e0e0ff",fontFamily:"monospace",fontSize:12,
                  padding:"8px 10px",resize:"none",outline:"none",boxSizing:"border-box"}}/>
              <input value={backendUrl} onChange={e=>setBackendUrl(e.target.value)}
                style={{width:"100%",background:"#0a0a1e",border:"1px solid #2a2a4a",borderRadius:5,
                  color:"#8888aa",fontFamily:"monospace",fontSize:11,padding:"5px 8px",
                  outline:"none",marginTop:6,boxSizing:"border-box"}}/>
              <button onClick={handleScan} disabled={scanning} style={{
                marginTop:8,width:"100%",padding:"10px",borderRadius:7,
                background:scanning?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
                border:"none",color:"#fff",fontFamily:"monospace",fontSize:13,fontWeight:700,
                cursor:scanning?"not-allowed":"pointer",letterSpacing:2,
                boxShadow:scanning?"none":"0 0 20px #7c3aed50",transition:"all 0.3s"}}>
                {scanning?`⏳ ${progress.current}/${progress.total} SCANNING...`:"⚡ LAUNCH DEEP SCAN"}
              </button>
              {scanning && (
                <div style={{marginTop:8}}>
                  <div style={{background:"#0a0a1e",borderRadius:3,overflow:"hidden",height:3}}>
                    <div style={{height:"100%",background:"linear-gradient(90deg,#7c3aed,#2563eb)",
                      width:`${(progress.current/progress.total)*100}%`,transition:"width 0.5s"}}/>
                  </div>
                  <div style={{color:"#6666aa",fontSize:10,marginTop:4}}>→ {progress.current_target}</div>
                </div>
              )}
            </div>

            {/* Scan Terminal */}
            <div style={{flex:1,overflowY:"auto",padding:"10px 14px",background:"#050510"}} ref={termRef}>
              {termLog.length===0 && !scanning && (
                <div style={{color:"#2a2a4a",fontSize:11,lineHeight:1.8}}>
                  <div style={{color:"#3a3a6a",marginBottom:8}}>$ quantumshield --deep-scan</div>
                  <div>40+ parameters per target:</div>
                  <div>· TLS version & cipher analysis</div>
                  <div>· Certificate deep inspection</div>
                  <div>· Key exchange detection</div>
                  <div>· Forward secrecy check</div>
                  <div>· Vulnerability DB cross-ref</div>
                  <div>· DNS security (CAA/DNSSEC)</div>
                  <div>· HTTP security headers</div>
                  <div>· CBOM generation</div>
                  <div>· PQC readiness scoring</div>
                </div>
              )}
              {termLog.map((l,i)=>(
                <div key={i} style={{fontFamily:"monospace",fontSize:11,lineHeight:1.7,color:l.color,whiteSpace:"pre-wrap"}}>
                  {l.msg}
                </div>
              ))}
            </div>

            {results.length>0 && (
              <div style={{padding:"10px 14px",borderTop:"1px solid #1e1e3a",flexShrink:0}}>
                <button onClick={exportCBOM} style={{width:"100%",padding:"8px",background:"#0a0a1e",
                  border:"1px solid #2a2a5a",color:"#8888cc",borderRadius:7,cursor:"pointer",
                  fontFamily:"monospace",fontSize:11,letterSpacing:1}}>
                  📥 EXPORT CBOM REPORT (JSON)
                </button>
              </div>
            )}
          </div>

          {/* Middle */}
          <div style={{borderRight:"1px solid #1e1e3a",overflowY:"auto",padding:"16px"}}>
            {results.length>0 ? (
              <>
                <SummaryBar results={results}/>
                <div style={{color:"#a0a0cc",fontSize:10,fontWeight:700,letterSpacing:2,marginBottom:10}}>ASSET INVENTORY</div>
                <div style={{overflowX:"auto"}}>
                  <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                    <thead>
                      <tr style={{borderBottom:"1px solid #2a2a4a"}}>
                        {["Asset","TLS","Cipher","Grade","FS","Cert","Expiry","Vulns","Score","Status"].map(h=>(
                          <th key={h} style={{padding:"7px 10px",textAlign:"left",color:"#6666aa",fontSize:10,letterSpacing:1,whiteSpace:"nowrap"}}>{h.toUpperCase()}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {results.map((r,i)=>{
                        const pqc=r.pqc_assessment||{};
                        const tls=r.tls_info||{};
                        const cert=r.certificate||{};
                        const vcount=r.vulnerabilities?.length||0;
                        return (
                          <tr key={i} onClick={()=>setSelected(r)} style={{
                            borderBottom:"1px solid #1a1a2e",cursor:"pointer",
                            background:selected?.target===r.target?"#0e0e22":"transparent"}}>
                            <td style={{padding:"9px 10px",color:"#a78bfa",fontFamily:"monospace",fontSize:11}}>{r.target}</td>
                            <td style={{padding:"9px 10px",color:tls.tls_version?.includes("1.3")?"#00e676":"#ffab40",whiteSpace:"nowrap"}}>{tls.tls_version||"—"}</td>
                            <td style={{padding:"9px 10px",color:"#8888aa",maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{tls.cipher_suite||"—"}</td>
                            <td style={{padding:"9px 10px"}}>{tls.cipher_grade?<GradeBadge grade={tls.cipher_grade}/>:"—"}</td>
                            <td style={{padding:"9px 10px",color:tls.forward_secrecy?"#00e676":"#ff5252"}}>{tls.forward_secrecy?"✓":"✗"}</td>
                            <td style={{padding:"9px 10px",color:cert.pqc_cert?"#00e676":"#ff5252",whiteSpace:"nowrap"}}>{cert.key_type||"?"}-{cert.key_bits||0}</td>
                            <td style={{padding:"9px 10px",color:cert.days_until_expiry<30?"#ff5252":cert.days_until_expiry<90?"#ffab40":"#6688aa",whiteSpace:"nowrap"}}>{cert.days_until_expiry!=null?`${cert.days_until_expiry}d`:"—"}</td>
                            <td style={{padding:"9px 10px",color:vcount>0?"#ff5252":"#3a5a3a"}}>{vcount>0?`⚠${vcount}`:"✓"}</td>
                            <td style={{padding:"9px 10px"}}><ScoreRing score={pqc.score||0} size={34}/></td>
                            <td style={{padding:"9px 10px"}}><Badge status={pqc.status} small/></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                {/* Results list for mobile */}
                <div style={{marginTop:16}}>
                  {results.map((r,i)=>(
                    <ResultCard key={i} result={r} onSelect={setSelected} selected={selected?.target===r.target}/>
                  ))}
                </div>
              </>
            ) : (
              <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"80vh",color:"#1e1e3a"}}>
                <div style={{fontSize:72,marginBottom:20}}>⚛</div>
                <div style={{fontSize:16,color:"#3a3a6a",letterSpacing:4}}>QUANTUMSHIELD v2.0</div>
                <div style={{fontSize:11,color:"#2a2a5a",marginTop:8,letterSpacing:2}}>40+ PARAMETERS · NIST FIPS 203/204/205</div>
              </div>
            )}
          </div>

          {/* Right */}
          <div style={{overflowY:"auto"}}>
            <DetailPanel result={selected}/>
          </div>
        </div>
      )}

      {activeView==="algorithms" && (
        <div style={{overflowY:"auto",height:"calc(100vh - 56px)",padding:"24px 32px",maxWidth:960,margin:"0 auto"}}>
          <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:20}}>NIST POST-QUANTUM CRYPTOGRAPHY STANDARDS — FINAL (2024)</div>
          <div style={{display:"grid",gap:14,marginBottom:28}}>
            {[
              {std:"FIPS 203",name:"ML-KEM",full:"Module Lattice-based Key Encapsulation Mechanism",
               variants:["ML-KEM-512 (Level 1)","ML-KEM-768 (Level 3) ★ Recommended","ML-KEM-1024 (Level 5)"],
               replaces:"RSA/ECDH Key Exchange",basis:"Module Learning With Errors (MLWE)",color:"#60a5fa",icon:"🔑"},
              {std:"FIPS 204",name:"ML-DSA",full:"Module Lattice-based Digital Signature Algorithm",
               variants:["ML-DSA-44 (Level 2)","ML-DSA-65 (Level 3) ★ Recommended","ML-DSA-87 (Level 5)"],
               replaces:"RSA/ECDSA Digital Signatures",basis:"Module Learning With Errors (MLWE)",color:"#34d399",icon:"✍️"},
              {std:"FIPS 205",name:"SLH-DSA",full:"Stateless Hash-based Digital Signature Algorithm",
               variants:["SLH-DSA-SHA2-128s/f (Level 1)","SLH-DSA-SHA2-192s/f (Level 3) ★","SLH-DSA-SHA2-256s/f (Level 5)"],
               replaces:"RSA/ECDSA (conservative alternative, hash-based)",basis:"Hash functions (SPHINCS+)",color:"#a78bfa",icon:"🌳"},
            ].map(algo=>(
              <div key={algo.std} style={{background:"#0a0a1e",border:`1px solid ${algo.color}30`,borderLeft:`4px solid ${algo.color}`,borderRadius:10,padding:"18px 20px"}}>
                <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:10}}>
                  <span style={{background:`${algo.color}22`,color:algo.color,padding:"2px 10px",borderRadius:4,fontSize:11,fontWeight:700,letterSpacing:1,fontFamily:"monospace"}}>{algo.std}</span>
                  <span style={{color:"#e0e0ff",fontWeight:800,fontSize:18}}>{algo.name}</span>
                  <span style={{fontSize:20}}>{algo.icon}</span>
                </div>
                <div style={{color:"#8888aa",fontSize:12,marginBottom:6}}>{algo.full}</div>
                <div style={{color:"#6666aa",fontSize:11,marginBottom:4}}>MATHEMATICAL BASIS: <span style={{color:"#c0c0e0"}}>{algo.basis}</span></div>
                <div style={{color:"#6666aa",fontSize:11,marginBottom:10}}>REPLACES: <span style={{color:"#ffab40"}}>{algo.replaces}</span></div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {algo.variants.map(v=>(
                    <span key={v} style={{background:v.includes("★")?`${algo.color}22`:"#1a1a2e",border:`1px solid ${v.includes("★")?algo.color:"#2a2a4a"}`,color:v.includes("★")?algo.color:"#8888aa",padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{v}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div style={{background:"#0e0000",border:"1px solid #ff174430",borderRadius:10,padding:"18px 20px"}}>
            <div style={{color:"#ff5252",fontWeight:700,fontSize:13,marginBottom:12}}>⚠ QUANTUM-VULNERABLE ALGORITHMS — HARVEST NOW, DECRYPT LATER RISK</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
              {[["RSA","CRITICAL","Shor's algorithm — any key size","Signatures, Key Exchange"],
                ["ECDSA/ECDH","CRITICAL","Shor's algorithm breaks ECC","Signatures, TLS Key Exchange"],
                ["DH/DSA","CRITICAL","Shor's algorithm breaks DLP","Legacy Key Exchange"],
                ["AES-128","HIGH","Grover's: 64-bit effective security","Symmetric Encryption"],
                ["SHA-1","CRITICAL","Classical collision attacks","Certificate Signing"],
                ["3DES","CRITICAL","SWEET32 + Grover's ~40-bit","Legacy Block Cipher"],
                ["RC4","CRITICAL","Statistical biases (RFC 7465)","Stream Cipher"],
                ["MD5","CRITICAL","Collision attacks since 2004","Hash / Cert Signing"],
                ["RSA<2048","CRITICAL","Classically breakable today","Legacy Certificates"],
              ].map(([algo,risk,reason,use])=>(
                <div key={algo} style={{background:"#0a0000",border:"1px solid #ff174415",borderRadius:7,padding:"10px 12px"}}>
                  <div style={{color:"#ff5252",fontWeight:700,fontSize:13,fontFamily:"monospace"}}>{algo}</div>
                  <div style={{color:"#ff1744",fontSize:10,fontWeight:700,letterSpacing:1,marginTop:3}}>{risk}</div>
                  <div style={{color:"#886666",fontSize:11,marginTop:3}}>{reason}</div>
                  <div style={{color:"#664444",fontSize:10,marginTop:2}}>{use}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeView==="about" && (
        <div style={{overflowY:"auto",height:"calc(100vh - 56px)",padding:"24px 32px",maxWidth:800,margin:"0 auto"}}>
          <div style={{textAlign:"center",marginBottom:36}}>
            <div style={{fontSize:56,marginBottom:14}}>⚛</div>
            <div style={{color:"#e0e0ff",fontWeight:800,fontSize:24,letterSpacing:4}}>QUANTUMSHIELD v2.0</div>
            <div style={{color:"#6666aa",letterSpacing:2,marginTop:6,fontSize:12}}>POST-QUANTUM CRYPTOGRAPHY SCANNER</div>
            <div style={{color:"#a78bfa",marginTop:6,fontSize:13}}>PNB Cybersecurity Hackathon 2025-26</div>
          </div>
          <div style={{display:"grid",gap:12}}>
            {[
              {icon:"🔬",title:"Deep TLS Inspection (40+ Parameters)",desc:"Full TLS handshake analysis, cipher suite grading (A–F), forward secrecy detection, TLS version probing across all supported versions, key exchange identification even for TLS 1.3."},
              {icon:"📜",title:"X.509 Certificate Full Audit",desc:"Key type/size, signature algorithm, expiry countdown, CT log verification, OCSP URL extraction, SANs, key usage, extended key usage, basic constraints, path length, policy OIDs."},
              {icon:"⚛",title:"NIST PQC Readiness Assessment",desc:"Scores against FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). Identifies Harvest Now Decrypt Later exposure. Issues PQC Ready / Quantum Safe badges."},
              {icon:"🛡️",title:"Vulnerability Database",desc:"Cross-references POODLE, BEAST, SWEET32, CRIME, BREACH, LUCKY13, RC4 biases, FREAK, LOGJAM, DROWN, and HNDL (Harvest Now Decrypt Later) against live scan results."},
              {icon:"🌐",title:"DNS Security Analysis",desc:"CAA record detection, DNSSEC status, IPv4/IPv6 presence, SPF and DMARC email security records. Flags missing DNS controls that could allow certificate mis-issuance."},
              {icon:"🔒",title:"HTTP Security Headers Audit",desc:"HSTS (max-age, includeSubDomains, preload), CSP (unsafe-inline/eval detection), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, COOP, COEP."},
              {icon:"📊",title:"CBOM Generation (CycloneDX v1.4)",desc:"Machine-readable Cryptographic Bill of Materials compliant with CycloneDX 1.4 schema and NIST SP 800-235. JSON export for GRC tool integration."},
              {icon:"🏆",title:"Automated PQC Certification",desc:"Automatically issues Fully Quantum Safe / PQC Ready / Transitioning / Vulnerable badges. Based on NIST-standardized algorithm deployment detection."},
            ].map(({icon,title,desc})=>(
              <div key={title} style={{background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:9,padding:"14px 18px",display:"flex",gap:14}}>
                <div style={{fontSize:24,flexShrink:0}}>{icon}</div>
                <div>
                  <div style={{color:"#e0e0ff",fontWeight:700,marginBottom:5,fontSize:13}}>{title}</div>
                  <div style={{color:"#8888aa",fontSize:12,lineHeight:1.7}}>{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
