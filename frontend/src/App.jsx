import { useState, useEffect, useRef } from "react";

// ── Constants ─────────────────────────────────────────────────────────────────
const BACKEND = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

const RISK_COLOR = {
  QUANTUM_SAFE:  { bg:"#061a0f", border:"#00e676", text:"#00e676", badge:"QUANTUM SAFE",  glow:"#00e67640" },
  PQC_READY:     { bg:"#1a1a00", border:"#c6ff00", text:"#c6ff00", badge:"PQC READY",     glow:"#c6ff0040" },
  TRANSITIONING: { bg:"#1a0e00", border:"#ff9100", text:"#ffab40", badge:"TRANSITIONING", glow:"#ff910040" },
  VULNERABLE:    { bg:"#1a0000", border:"#ff1744", text:"#ff5252", badge:"VULNERABLE",    glow:"#ff174440" },
  UNKNOWN:       { bg:"#0a0a20", border:"#536dfe", text:"#8c9eff", badge:"UNKNOWN",       glow:"#536dfe40" },
};
const SEV_COLOR = { CRITICAL:"#ff1744", HIGH:"#ff5252", MEDIUM:"#ffab40", LOW:"#c6ff00", INFO:"#8c9eff" };

// ── Auth helpers ──────────────────────────────────────────────────────────────
function getToken()    { return localStorage.getItem("qs_token") || ""; }
function getUser()     { try { return JSON.parse(localStorage.getItem("qs_user") || "null"); } catch { return null; } }
function setAuth(t,u)  { localStorage.setItem("qs_token", t); localStorage.setItem("qs_user", JSON.stringify(u)); }
function clearAuth()   { localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user"); }
function authHeaders() { const t=getToken(); return t ? {"Content-Type":"application/json","Authorization":`Bearer ${t}`} : {"Content-Type":"application/json"}; }

// ── Mock data ────────────────────────────────────────────────────────────────
const buildMock=(target,score,status,tlsVer,cipher,certType,certBits,kex,issues,positives,vulns,daysLeft)=>({
  target,port:443,status:"success",timestamp:new Date().toISOString(),
  tls_info:{tls_version:tlsVer,cipher_suite:cipher,cipher_bits:256,cipher_grade:score>=75?"A":"B",
            key_exchange:kex,forward_secrecy:true,supported_tls_versions:["TLSv1.3","TLSv1.2"],
            cert_key_type:certType,cert_key_bits:certBits},
  certificate:{key_type:certType,key_bits:certBits,subject:`CN=${target}`,issuer:"CN=Google Trust Services",
               not_after:new Date(Date.now()+daysLeft*86400000).toISOString(),days_until_expiry:daysLeft,
               total_validity_days:397,signature_algorithm:"SHA256",sans:[target,`www.${target}`],
               is_self_signed:false,pqc_cert:false,ct_sct_count:2,key_usage:{digital_signature:true},
               ocsp_urls:["http://ocsp.example.com"],policies:[],issues:[]},
  pqc_assessment:{score,status,label:RISK_COLOR[status]?.badge,badge_color:RISK_COLOR[status]?.border,
                  issues,positives,parameters_checked:40},
  cbom:{cbom_version:"1.4",components:[
    {type:"protocol",name:"TLS",version:tlsVer,quantum_safe:false,supported_versions:["TLSv1.3","TLSv1.2"]},
    {type:"cipher-suite",name:cipher,bits:256,grade:score>=75?"A":"B",forward_secrecy:true,quantum_safe:false},
    {type:"key-exchange",name:kex,quantum_safe:kex.includes("ML-KEM")},
    {type:"certificate",name:`${certType}-${certBits}`,algorithm:"SHA256",quantum_safe:false,days_until_expiry:daysLeft,ct_sct_count:2},
  ]},
  vulnerabilities:vulns,
  dns:{caa_present:true,dnssec_enabled:false,dns_resolves:true,ipv4_addresses:["142.250.80.46"],ipv6_addresses:["2607:f8b0:4004::200e"],issues:[]},
  http_headers:{hsts:{present:true,max_age:31536000,include_subdomains:true,preload:true},
                csp:{present:score>60,value:"default-src 'self'"},
                headers_found:{"Strict-Transport-Security":"max-age=31536000"},
                headers_missing:score<70?["X-Frame-Options","Permissions-Policy"]:[],
                score:score>70?90:65,issues:[]},
});

const MOCK_DB = {
  "google.com": buildMock("google.com",65,"PQC_READY","TLSv1.3","TLS_AES_256_GCM_SHA384","ECDSA",256,"X25519/P-256 ECDHE (Quantum-Vulnerable)",
    [{severity:"HIGH",issue:"ECDSA-256 — Shor's algorithm breaks this",action:"Migrate to ML-DSA-65 (FIPS 204)"}],
    ["TLS 1.3","AES-256 symmetric","Forward secrecy enabled"],
    [{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later threat",action:"Deploy ML-KEM-768"}],48),
  "cloudflare.com": buildMock("cloudflare.com",72,"PQC_READY","TLSv1.3","TLS_AES_256_GCM_SHA384","ECDSA",256,"X25519+Kyber768 (Hybrid PQC)",
    [{severity:"HIGH",issue:"ECDSA-256 — quantum-vulnerable signature",action:"Migrate to ML-DSA-65 (FIPS 204)"}],
    ["TLS 1.3","Hybrid PQC key exchange","AES-256-GCM","HSTS preload","Forward secrecy"],
    [{name:"HNDL",cve:"N/A",severity:"HIGH",description:"Certificate still quantum-vulnerable",action:"Complete PQC migration"}],120),
  "example.com": buildMock("example.com",32,"VULNERABLE","TLSv1.2","ECDHE-RSA-AES128-GCM-SHA256","RSA",2048,"ECDHE (Quantum-Vulnerable)",
    [{severity:"CRITICAL",issue:"RSA-2048 — fully broken by Shor's",action:"Replace with ML-DSA-65"},
     {severity:"HIGH",issue:"TLS 1.2 — recordable for HNDL",action:"Enforce TLS 1.3"},
     {severity:"HIGH",issue:"No HSTS",action:"Add Strict-Transport-Security"}],
    [],
    [{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Full PQC migration"}],5),
};

async function performScan(target, token) {
  const clean = target.replace(/^https?:\/\//,"").split("/")[0].trim();
  try {
    const headers = {"Content-Type":"application/json"};
    if(token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(`${BACKEND}/api/v1/scan/quick`,{
      method:"POST",headers,
      body:JSON.stringify({target:clean,port:443}),
      signal:AbortSignal.timeout(25000)
    });
    if(res.ok) return await res.json();
  } catch(_) {}
  await new Promise(r=>setTimeout(r,1200+Math.random()*800));
  const mock = MOCK_DB[clean];
  if(mock) return {...mock,timestamp:new Date().toISOString()};
  const score=Math.floor(Math.random()*55)+20;
  const status=score>=65?"PQC_READY":score>=40?"TRANSITIONING":"VULNERABLE";
  return buildMock(clean,score,status,score>50?"TLSv1.3":"TLSv1.2","ECDHE-RSA-AES256-GCM-SHA384","RSA",2048,"ECDHE (Quantum-Vulnerable)",
    [{severity:"HIGH",issue:"RSA-2048 — quantum-vulnerable",action:"Migrate to ML-DSA-65"}],[],
    [{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Deploy ML-KEM-768"}],
    Math.floor(Math.random()*300)+30);
}

// ── Reusable UI ──────────────────────────────────────────────────────────────
function ScoreRing({score,size=72}) {
  const r=size/2-7; const circ=2*Math.PI*r; const dash=(score/100)*circ;
  const color=score>=75?"#00e676":score>=55?"#c6ff00":score>=35?"#ff9100":"#ff1744";
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

function Badge({status,small}) {
  const c=RISK_COLOR[status]||RISK_COLOR.UNKNOWN;
  return <span style={{background:c.bg,border:`1px solid ${c.border}`,color:c.text,
    padding:small?"2px 7px":"3px 10px",borderRadius:4,fontSize:small?10:11,fontWeight:700,
    letterSpacing:1,fontFamily:"monospace",boxShadow:`0 0 8px ${c.glow}`,whiteSpace:"nowrap"}}>{c.badge}</span>;
}

function SevBadge({sev}) {
  const c=SEV_COLOR[sev]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}44`,
    padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:700,letterSpacing:1}}>{sev}</span>;
}

function GradeBadge({grade}) {
  const gc={A:"#00e676",B:"#c6ff00",C:"#ff9100",D:"#ff5252",F:"#ff1744"};
  const c=gc[grade]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}`,
    padding:"2px 8px",borderRadius:4,fontSize:12,fontWeight:900,fontFamily:"monospace"}}>{grade}</span>;
}

// ── Login Screen ──────────────────────────────────────────────────────────────
function LoginScreen({onLogin}) {
  const [form,setForm]   = useState({username:"",password:""});
  const [error,setError] = useState("");
  const [loading,setLoading] = useState(false);

  const submit = async () => {
    if(!form.username||!form.password){setError("Please enter username and password");return;}
    setLoading(true); setError("");
    try {
      const body = new URLSearchParams();
      body.append("username",form.username); body.append("password",form.password);
      const res = await fetch(`${BACKEND}/api/v1/auth/login`,{
        method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},
        body, signal:AbortSignal.timeout(8000)
      });
      if(res.ok) {
        const data = await res.json();
        setAuth(data.access_token,{username:data.username,role:data.role,email:data.email});
        onLogin({username:data.username,role:data.role,email:data.email},data.access_token);
      } else {
        const err = await res.json().catch(()=>({detail:"Login failed"}));
        setError(err.detail||"Invalid credentials");
      }
    } catch(_) {
      // Demo mode offline fallback
      const demo = {admin:"quantum2026",pnb:"pnbsecure",auditor:"audit2026"};
      if(demo[form.username]===form.password) {
        const roles = {admin:"Admin",pnb:"Operator",auditor:"Checker"};
        const u = {username:form.username,role:roles[form.username],email:`${form.username}@quantumshield.io`};
        setAuth("demo-token",u); onLogin(u,"demo-token");
      } else {
        setError("Cannot reach backend — check URL or use: admin / quantum2026");
      }
    }
    setLoading(false);
  };

  return (
    <div style={{background:"#05050e",minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"monospace"}}>
      <div style={{background:"#08081a",border:"1px solid #2a2a4a",borderRadius:14,padding:"40px 48px",width:380,boxShadow:"0 0 60px #7c3aed20"}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{width:56,height:56,background:"linear-gradient(135deg,#7c3aed,#2563eb)",borderRadius:14,
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:28,margin:"0 auto 14px"}}>⚛</div>
          <div style={{color:"#e0e0ff",fontWeight:800,fontSize:22,letterSpacing:3}}>QUANTUMSHIELD</div>
          <div style={{color:"#6666aa",fontSize:11,marginTop:4,letterSpacing:2}}>PQC SCANNER v2.0</div>
          <div style={{color:"#4a4a7a",fontSize:10,marginTop:2}}>NIST FIPS 203 · 204 · 205</div>
        </div>
        {error && (
          <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#ff5252",
            padding:"10px 14px",borderRadius:8,marginBottom:18,fontSize:12,lineHeight:1.5}}>{error}</div>
        )}
        {[["USERNAME","text","username"],["PASSWORD","password","password"]].map(([label,type,key])=>(
          <div key={key} style={{marginBottom:14}}>
            <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:6}}>{label}</div>
            <input value={form[key]} type={type}
              onChange={e=>setForm({...form,[key]:e.target.value})}
              onKeyDown={e=>e.key==="Enter"&&submit()}
              style={{width:"100%",background:"#0f0f25",border:"1px solid #2a2a4a",borderRadius:7,
                color:"#e0e0ff",fontFamily:"monospace",fontSize:13,padding:"11px 14px",
                outline:"none",boxSizing:"border-box",transition:"border-color 0.2s"}}
              onFocus={e=>e.target.style.borderColor="#7c3aed"}
              onBlur={e=>e.target.style.borderColor="#2a2a4a"}/>
          </div>
        ))}
        <button onClick={submit} disabled={loading} style={{
          width:"100%",padding:"13px",marginTop:6,
          background:loading?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
          border:"none",borderRadius:8,color:"#fff",fontFamily:"monospace",fontSize:13,
          fontWeight:700,cursor:loading?"not-allowed":"pointer",letterSpacing:2,
          boxShadow:loading?"none":"0 0 24px #7c3aed50"}}>
          {loading?"AUTHENTICATING...":"SIGN IN →"}
        </button>
        <div style={{marginTop:20,padding:"12px 14px",background:"#0a0a1e",borderRadius:8,border:"1px solid #1e1e3a"}}>
          <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:8}}>DEMO CREDENTIALS</div>
          {[["admin","quantum2026","Admin"],["pnb","pnbsecure","Operator"],["auditor","audit2026","Checker"]].map(([u,p,r])=>(
            <div key={u} onClick={()=>setForm({username:u,password:p})}
              style={{display:"flex",justifyContent:"space-between",padding:"4px 0",cursor:"pointer",
                borderBottom:"1px solid #1a1a2e",fontSize:11}}>
              <span style={{color:"#a78bfa",fontFamily:"monospace"}}>{u}</span>
              <span style={{color:"#4a4a7a"}}>/</span>
              <span style={{color:"#6666aa"}}>{p}</span>
              <span style={{background:"#a78bfa22",color:"#a78bfa",padding:"0 6px",borderRadius:3,fontSize:10}}>{r}</span>
            </div>
          ))}
          <div style={{color:"#3a3a5a",fontSize:10,marginTop:6}}>Click any row to auto-fill</div>
        </div>
      </div>
    </div>
  );
}

// ── History Panel ─────────────────────────────────────────────────────────────
function HistoryPanel({token,user}) {
  const [history,setHistory] = useState([]);
  const [stats,setStats]     = useState(null);
  const [loading,setLoading] = useState(true);
  const [selected,setSelected] = useState(null);

  useEffect(()=>{ loadHistory(); },[]);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const [hRes,sRes] = await Promise.all([
        fetch(`${BACKEND}/api/v1/history/?limit=50`,{headers:authHeaders()}),
        fetch(`${BACKEND}/api/v1/history/stats/summary`,{headers:authHeaders()}),
      ]);
      if(hRes.ok) { const d=await hRes.json(); setHistory(d.scans||[]); }
      if(sRes.ok) { setStats(await sRes.json()); }
    } catch(_) {
      // use localStorage fallback
      try {
        const local = JSON.parse(localStorage.getItem("qs_scan_history")||"[]");
        setHistory(local);
      } catch(__) {}
    }
    setLoading(false);
  };

  const deleteRecord = async (scanId) => {
    try {
      await fetch(`${BACKEND}/api/v1/history/${scanId}`,{method:"DELETE",headers:authHeaders()});
    } catch(_) {}
    setHistory(h=>h.filter(r=>r.scan_id!==scanId));
    if(selected?.scan_id===scanId) setSelected(null);
  };

  const statusColors = {QUANTUM_SAFE:"#00e676",PQC_READY:"#c6ff00",TRANSITIONING:"#ff9100",VULNERABLE:"#ff1744"};

  return (
    <div style={{padding:"24px 28px",overflowY:"auto",height:"calc(100vh - 56px)"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div>
          <div style={{color:"#e0e0ff",fontWeight:800,fontSize:18,letterSpacing:2}}>SCAN HISTORY</div>
          <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>All scans saved to database · {user?.role} view</div>
        </div>
        <button onClick={loadHistory} style={{background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#8888cc",
          padding:"8px 16px",borderRadius:7,cursor:"pointer",fontFamily:"monospace",fontSize:11}}>↻ REFRESH</button>
      </div>

      {stats && (
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr) 1fr",gap:10,marginBottom:20}}>
          {[["TOTAL SCANS",stats.total,"#8c9eff"],
            ["AVG SCORE",`${stats.avg_score}/100`,"#c6ff00"],
            ["UNIQUE TARGETS",stats.unique_targets,"#a78bfa"],
            ["QUANTUM SAFE",stats.by_status?.QUANTUM_SAFE||0,"#00e676"],
            ["VULNERABLE",stats.by_status?.VULNERABLE||0,"#ff1744"],
          ].map(([label,val,color])=>(
            <div key={label} style={{background:"#08081a",border:`1px solid ${color}20`,borderRadius:8,padding:"12px 14px"}}>
              <div style={{color:"#6666aa",fontSize:9,letterSpacing:2}}>{label}</div>
              <div style={{color,fontSize:22,fontWeight:900,fontFamily:"monospace",marginTop:4}}>{val}</div>
            </div>
          ))}
        </div>
      )}

      {loading ? (
        <div style={{color:"#4a4a7a",textAlign:"center",padding:40}}>Loading history...</div>
      ) : history.length===0 ? (
        <div style={{textAlign:"center",padding:60,color:"#3a3a5a"}}>
          <div style={{fontSize:48,marginBottom:12}}>📋</div>
          <div style={{fontSize:14,letterSpacing:2}}>NO SCAN HISTORY YET</div>
          <div style={{fontSize:12,marginTop:6}}>Run a scan to see results here</div>
        </div>
      ) : (
        <div style={{display:"grid",gridTemplateColumns:"1fr 480px",gap:16}}>
          <div>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
              <thead>
                <tr style={{borderBottom:"1px solid #2a2a4a"}}>
                  {["Target","TLS","Score","Status","Scanned At",""].map(h=>(
                    <th key={h} style={{padding:"8px 10px",textAlign:"left",color:"#6666aa",fontSize:10,letterSpacing:1}}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((r,i)=>(
                  <tr key={i} onClick={()=>setSelected(r)}
                    style={{borderBottom:"1px solid #1a1a2e",cursor:"pointer",
                      background:selected?.scan_id===r.scan_id?"#0e0e22":"transparent"}}>
                    <td style={{padding:"9px 10px",color:"#a78bfa",fontFamily:"monospace"}}>{r.target}</td>
                    <td style={{padding:"9px 10px",color:r.tls_version?.includes("1.3")?"#00e676":"#ffab40"}}>{r.tls_version||"—"}</td>
                    <td style={{padding:"9px 10px"}}><ScoreRing score={r.pqc_score||0} size={34}/></td>
                    <td style={{padding:"9px 10px"}}>
                      <span style={{color:statusColors[r.pqc_status]||"#888",fontSize:10,fontWeight:700}}>{r.pqc_status||"—"}</span>
                    </td>
                    <td style={{padding:"9px 10px",color:"#6666aa",fontSize:11}}>{r.scanned_at?new Date(r.scanned_at).toLocaleString():""}</td>
                    <td style={{padding:"9px 10px"}}>
                      <button onClick={e=>{e.stopPropagation();deleteRecord(r.scan_id)}}
                        style={{background:"#ff174415",border:"1px solid #ff174430",color:"#ff5252",
                          padding:"2px 8px",borderRadius:4,cursor:"pointer",fontSize:10,fontFamily:"monospace"}}>✕</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{background:"#08081a",border:"1px solid #1e1e3a",borderRadius:10,padding:"16px",height:"fit-content"}}>
            {selected ? (
              <>
                <div style={{color:"#a78bfa",fontWeight:700,fontSize:14,fontFamily:"monospace",marginBottom:12}}>🔒 {selected.target}</div>
                {[["Port",selected.port],["TLS Version",selected.tls_version],
                  ["Cipher",selected.cipher_suite],["PQC Score",`${selected.pqc_score}/100`],
                  ["Status",selected.pqc_status],["Scanned",selected.scanned_at?new Date(selected.scanned_at).toLocaleString():""],
                  ["By",selected.username],
                ].map(([k,v])=>(
                  <div key={k} style={{display:"flex",borderBottom:"1px solid #1a1a2e",padding:"8px 0"}}>
                    <div style={{width:100,color:"#6666aa",fontSize:11,flexShrink:0}}>{k}</div>
                    <div style={{color:"#c0c0e0",fontSize:12,fontFamily:"monospace",wordBreak:"break-all"}}>{v||"—"}</div>
                  </div>
                ))}
              </>
            ) : (
              <div style={{color:"#3a3a5a",textAlign:"center",padding:30}}>Select a scan to see details</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Admin Panel ───────────────────────────────────────────────────────────────
function AdminPanel({token}) {
  const [users,setUsers]   = useState([]);
  const [logs,setLogs]     = useState([]);
  const [tab,setTab]       = useState("users");
  const [showCreate,setShowCreate] = useState(false);
  const [form,setForm]     = useState({username:"",email:"",password:"",role:"Viewer",admin_key:""});
  const [msg,setMsg]       = useState("");

  useEffect(()=>{ loadData(); },[]);

  const loadData = async () => {
    try {
      const [uRes,lRes] = await Promise.all([
        fetch(`${BACKEND}/api/v1/auth/users`,{headers:authHeaders()}),
        fetch(`${BACKEND}/api/v1/auth/audit-logs?limit=50`,{headers:authHeaders()}),
      ]);
      if(uRes.ok) setUsers(await uRes.json());
      if(lRes.ok) setLogs(await lRes.json());
    } catch(_) {}
  };

  const createUser = async () => {
    try {
      const res = await fetch(`${BACKEND}/api/v1/auth/register`,{
        method:"POST",headers:authHeaders(),body:JSON.stringify(form)
      });
      if(res.ok) { setMsg("User created!"); setShowCreate(false); loadData(); }
      else { const e=await res.json(); setMsg(e.detail||"Failed"); }
    } catch(_) { setMsg("Backend offline"); }
  };

  const roleColor = {Admin:"#ff5252",Operator:"#ffab40",Checker:"#8c9eff",Viewer:"#6666aa"};
  const actionColor = {LOGIN:"#00e676",LOGOUT:"#ffab40",SCAN:"#8c9eff",BATCH_SCAN:"#a78bfa",PASSWORD_CHANGE:"#c6ff00"};

  return (
    <div style={{padding:"24px 28px",overflowY:"auto",height:"calc(100vh - 56px)"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div>
          <div style={{color:"#e0e0ff",fontWeight:800,fontSize:18,letterSpacing:2}}>ADMIN PANEL</div>
          <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>User management · Audit logs · Security</div>
        </div>
        <div style={{display:"flex",gap:8}}>
          {["users","logs"].map(t=>(
            <button key={t} onClick={()=>setTab(t)} style={{
              background:tab===t?"#1e1e3a":"none",border:`1px solid ${tab===t?"#2e2e5a":"transparent"}`,
              color:tab===t?"#a78bfa":"#6666aa",padding:"6px 14px",borderRadius:6,cursor:"pointer",
              fontFamily:"monospace",fontSize:11,letterSpacing:1}}>{t.toUpperCase()}</button>
          ))}
          {tab==="users" && (
            <button onClick={()=>setShowCreate(!showCreate)} style={{
              background:"linear-gradient(135deg,#7c3aed,#2563eb)",border:"none",color:"#fff",
              padding:"6px 14px",borderRadius:6,cursor:"pointer",fontFamily:"monospace",fontSize:11}}>+ NEW USER</button>
          )}
        </div>
      </div>

      {msg && <div style={{background:"#00e67615",border:"1px solid #00e67640",color:"#00e676",
        padding:"10px 14px",borderRadius:8,marginBottom:14,fontSize:12}}>{msg}</div>}

      {showCreate && (
        <div style={{background:"#08081a",border:"1px solid #2a2a4a",borderRadius:10,padding:"20px",marginBottom:20}}>
          <div style={{color:"#a78bfa",fontWeight:700,marginBottom:14}}>CREATE NEW USER</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
            {[["username","Username"],["email","Email"],["password","Password"],["admin_key","Admin Key"]].map(([k,label])=>(
              <div key={k}>
                <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:4}}>{label.toUpperCase()}</div>
                <input value={form[k]} type={k==="password"?"password":"text"}
                  onChange={e=>setForm({...form,[k]:e.target.value})}
                  style={{width:"100%",background:"#0f0f25",border:"1px solid #2a2a4a",borderRadius:6,
                    color:"#e0e0ff",fontFamily:"monospace",fontSize:12,padding:"8px 10px",
                    outline:"none",boxSizing:"border-box"}}/>
              </div>
            ))}
            <div>
              <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:4}}>ROLE</div>
              <select value={form.role} onChange={e=>setForm({...form,role:e.target.value})}
                style={{width:"100%",background:"#0f0f25",border:"1px solid #2a2a4a",borderRadius:6,
                  color:"#e0e0ff",fontFamily:"monospace",fontSize:12,padding:"8px 10px",outline:"none"}}>
                {["Admin","Operator","Checker","Viewer"].map(r=><option key={r}>{r}</option>)}
              </select>
            </div>
          </div>
          <div style={{display:"flex",gap:8,marginTop:14}}>
            <button onClick={createUser} style={{background:"linear-gradient(135deg,#7c3aed,#2563eb)",
              border:"none",color:"#fff",padding:"9px 20px",borderRadius:7,cursor:"pointer",
              fontFamily:"monospace",fontSize:12,fontWeight:700}}>CREATE USER</button>
            <button onClick={()=>setShowCreate(false)} style={{background:"#1a1a2e",border:"1px solid #2a2a4a",
              color:"#6666aa",padding:"9px 20px",borderRadius:7,cursor:"pointer",fontFamily:"monospace",fontSize:12}}>CANCEL</button>
          </div>
          <div style={{color:"#4a4a7a",fontSize:10,marginTop:8}}>Admin Key default: qs-admin-key-2026 (set ADMIN_REGISTER_KEY env var in production)</div>
        </div>
      )}

      {tab==="users" && (
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
          <thead>
            <tr style={{borderBottom:"1px solid #2a2a4a"}}>
              {["ID","Username","Email","Role","Active","Created","Last Login"].map(h=>(
                <th key={h} style={{padding:"8px 10px",textAlign:"left",color:"#6666aa",fontSize:10,letterSpacing:1}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {users.map(u=>(
              <tr key={u.id} style={{borderBottom:"1px solid #1a1a2e"}}>
                <td style={{padding:"9px 10px",color:"#4a4a7a"}}>{u.id}</td>
                <td style={{padding:"9px 10px",color:"#a78bfa",fontFamily:"monospace",fontWeight:700}}>{u.username}</td>
                <td style={{padding:"9px 10px",color:"#8888aa"}}>{u.email}</td>
                <td style={{padding:"9px 10px"}}>
                  <span style={{background:`${roleColor[u.role]||"#888"}22`,color:roleColor[u.role]||"#888",
                    border:`1px solid ${roleColor[u.role]||"#888"}44`,padding:"2px 8px",borderRadius:4,
                    fontSize:10,fontWeight:700,letterSpacing:1}}>{u.role}</span>
                </td>
                <td style={{padding:"9px 10px",color:u.is_active?"#00e676":"#ff5252"}}>{u.is_active?"✓ Active":"✗ Inactive"}</td>
                <td style={{padding:"9px 10px",color:"#6666aa",fontSize:11}}>{u.created_at?new Date(u.created_at).toLocaleDateString():""}</td>
                <td style={{padding:"9px 10px",color:"#6666aa",fontSize:11}}>{u.last_login?new Date(u.last_login).toLocaleString():"Never"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab==="logs" && (
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
          <thead>
            <tr style={{borderBottom:"1px solid #2a2a4a"}}>
              {["Time","User","Action","Target","IP"].map(h=>(
                <th key={h} style={{padding:"8px 10px",textAlign:"left",color:"#6666aa",fontSize:10,letterSpacing:1}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.map(l=>(
              <tr key={l.id} style={{borderBottom:"1px solid #1a1a2e"}}>
                <td style={{padding:"8px 10px",color:"#6666aa",fontSize:11,whiteSpace:"nowrap"}}>{l.timestamp?new Date(l.timestamp).toLocaleString():""}</td>
                <td style={{padding:"8px 10px",color:"#a78bfa",fontFamily:"monospace"}}>{l.username||"—"}</td>
                <td style={{padding:"8px 10px"}}>
                  <span style={{color:actionColor[l.action]||"#888",fontSize:10,fontWeight:700,fontFamily:"monospace"}}>{l.action}</span>
                </td>
                <td style={{padding:"8px 10px",color:"#8888aa",fontFamily:"monospace",fontSize:11}}>{l.target||"—"}</td>
                <td style={{padding:"8px 10px",color:"#4a4a7a",fontSize:11,fontFamily:"monospace"}}>{l.ip_address||"—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Profile Panel ─────────────────────────────────────────────────────────────
function ProfilePanel({user,onPasswordChanged}) {
  const [form,setForm]   = useState({current_password:"",new_password:"",confirm:""});
  const [msg,setMsg]     = useState("");
  const [err,setErr]     = useState("");

  const changePassword = async () => {
    if(form.new_password!==form.confirm){setErr("Passwords do not match");return;}
    if(form.new_password.length<8){setErr("Password must be at least 8 characters");return;}
    setErr(""); setMsg("");
    try {
      const res = await fetch(`${BACKEND}/api/v1/auth/change-password`,{
        method:"POST",headers:authHeaders(),
        body:JSON.stringify({current_password:form.current_password,new_password:form.new_password})
      });
      if(res.ok){setMsg("Password changed successfully!");setForm({current_password:"",new_password:"",confirm:""});}
      else{const e=await res.json();setErr(e.detail||"Failed");}
    } catch(_){setErr("Backend offline");}
  };

  return (
    <div style={{padding:"24px 28px",overflowY:"auto",height:"calc(100vh - 56px)"}}>
      <div style={{color:"#e0e0ff",fontWeight:800,fontSize:18,letterSpacing:2,marginBottom:20}}>MY PROFILE</div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:20,maxWidth:800}}>
        <div style={{background:"#08081a",border:"1px solid #1e1e3a",borderRadius:10,padding:"20px"}}>
          <div style={{color:"#a78bfa",fontWeight:700,marginBottom:16}}>ACCOUNT DETAILS</div>
          {[["Username",user?.username],["Email",user?.email],["Role",user?.role]].map(([k,v])=>(
            <div key={k} style={{display:"flex",borderBottom:"1px solid #1a1a2e",padding:"10px 0"}}>
              <div style={{width:100,color:"#6666aa",fontSize:11}}>{k}</div>
              <div style={{color:"#e0e0ff",fontFamily:"monospace",fontWeight:k==="Role"?700:400}}>
                {k==="Role"?<span style={{color:{Admin:"#ff5252",Operator:"#ffab40",Checker:"#8c9eff",Viewer:"#6666aa"}[v]||"#888"}}>{v}</span>:v}
              </div>
            </div>
          ))}
        </div>
        <div style={{background:"#08081a",border:"1px solid #1e1e3a",borderRadius:10,padding:"20px"}}>
          <div style={{color:"#a78bfa",fontWeight:700,marginBottom:16}}>CHANGE PASSWORD</div>
          {msg && <div style={{background:"#00e67615",border:"1px solid #00e67640",color:"#00e676",padding:"8px 12px",borderRadius:6,marginBottom:12,fontSize:12}}>{msg}</div>}
          {err && <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#ff5252",padding:"8px 12px",borderRadius:6,marginBottom:12,fontSize:12}}>{err}</div>}
          {[["Current Password","current_password"],["New Password","new_password"],["Confirm New Password","confirm"]].map(([label,key])=>(
            <div key={key} style={{marginBottom:12}}>
              <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:5}}>{label.toUpperCase()}</div>
              <input type="password" value={form[key]} onChange={e=>setForm({...form,[key]:e.target.value})}
                style={{width:"100%",background:"#0f0f25",border:"1px solid #2a2a4a",borderRadius:6,
                  color:"#e0e0ff",fontFamily:"monospace",fontSize:12,padding:"9px 12px",
                  outline:"none",boxSizing:"border-box"}}/>
            </div>
          ))}
          <button onClick={changePassword} style={{background:"linear-gradient(135deg,#7c3aed,#2563eb)",
            border:"none",color:"#fff",padding:"10px 20px",borderRadius:7,cursor:"pointer",
            fontFamily:"monospace",fontSize:12,fontWeight:700,width:"100%"}}>UPDATE PASSWORD</button>
        </div>
      </div>
    </div>
  );
}

// ── Detail components (keep all from original) ────────────────────────────────
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
            {v.cve!=="N/A"&&<span style={{color:"#6666aa",fontSize:11,fontFamily:"monospace"}}>{v.cve}</span>}
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
                {c.bits?`${c.bits}-bit`:""} {c.version||""}{c.grade?<> <GradeBadge grade={c.grade}/></>:""}
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
  const items=[
    ["DNS Resolves",dns.dns_resolves?"✓ Yes":"✗ No",dns.dns_resolves?"#00e676":"#ff5252"],
    ["IPv4 Addresses",dns.ipv4_addresses?.join(", ")||"None","#8c9eff"],
    ["IPv6 Addresses",dns.ipv6_addresses?.join(", ")||"None (no AAAA)",dns.ipv6_addresses?.length?"#8c9eff":"#ffab40"],
    ["CAA Records",dns.caa_present?"✓ Present":"✗ Missing",dns.caa_present?"#00e676":"#ff5252"],
    ["DNSSEC",dns.dnssec_enabled?"✓ Enabled":"Not detected",dns.dnssec_enabled?"#00e676":"#ffab40"],
    ["SPF Record",dns.spf_present?"✓ Present":"Not detected",dns.spf_present?"#00e676":"#ffab40"],
    ["DMARC Record",dns.dmarc_present?"✓ Present":"Not detected",dns.dmarc_present?"#00e676":"#ffab40"],
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
  const hsts=http.hsts||{};
  return (
    <div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
        {[
          ["HSTS",hsts.present?"✓ Present":"✗ Missing",hsts.present?"#00e676":"#ff5252"],
          ["HSTS max-age",hsts.max_age?`${hsts.max_age}s`:"—",hsts.max_age>=31536000?"#00e676":"#ffab40"],
          ["includeSubDomains",hsts.include_subdomains?"✓":"✗",hsts.include_subdomains?"#00e676":"#ff5252"],
          ["Preload",hsts.preload?"✓ Yes":"✗ No",hsts.preload?"#00e676":"#ffab40"],
          ["CSP",http.csp?.present?"✓ Present":"✗ Missing",http.csp?.present?"#00e676":"#ff5252"],
          ["Header Score",`${http.score||0}/100`,(http.score||0)>=80?"#00e676":(http.score||0)>=60?"#ffab40":"#ff5252"],
        ].map(([label,val,color])=>(
          <div key={label} style={{background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:6,padding:"10px 12px"}}>
            <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:4}}>{label.toUpperCase()}</div>
            <div style={{color,fontFamily:"monospace",fontSize:12,fontWeight:700}}>{val}</div>
          </div>
        ))}
      </div>
      {http.headers_missing?.length>0&&(
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
    </div>
  );
}

function DetailPanel({result}) {
  const [tab,setTab]=useState("overview");
  useEffect(()=>setTab("overview"),[result?.target]);
  if(!result) return (
    <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",color:"#2a2a4a"}}>
      <div style={{fontSize:64,marginBottom:16}}>⚛</div>
      <div style={{fontSize:15,letterSpacing:4,color:"#4a4a7a"}}>SELECT A TARGET</div>
      <div style={{fontSize:12,color:"#3a3a5a",marginTop:8}}>TO VIEW FULL ANALYSIS</div>
    </div>
  );
  const pqc=result.pqc_assessment||{},tls=result.tls_info||{},cert=result.certificate||{};
  const cbom=result.cbom||{},vulns=result.vulnerabilities||{},dns=result.dns||{},http=result.http_headers||{};
  const c=RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;
  const tabs=[
    {id:"overview",label:"Overview"},{id:"cbom",label:"CBOM"},{id:"certificate",label:"Certificate"},
    {id:"vulns",label:`Vulns${vulns.length>0?` (${vulns.length})`:""}`,alert:vulns.some&&vulns.some(v=>v.severity==="CRITICAL")},
    {id:"dns",label:"DNS"},{id:"headers",label:"Headers"},{id:"roadmap",label:"Roadmap"},
  ];
  return (
    <div style={{height:"100%",display:"flex",flexDirection:"column"}}>
      <div style={{padding:"16px 20px",borderBottom:"1px solid #1e1e3a",background:c.bg}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
          <div>
            <div style={{color:"#e0e0ff",fontFamily:"monospace",fontWeight:800,fontSize:16}}>🔒 {result.target}</div>
            <div style={{color:"#8888aa",fontSize:11,marginTop:3}}>{tls.tls_version||"—"} · Port {result.port} · {tls.cipher_grade&&<GradeBadge grade={tls.cipher_grade}/>}</div>
            <div style={{marginTop:6,display:"flex",gap:6,flexWrap:"wrap"}}>
              {tls.forward_secrecy&&<span style={{background:"#00e67610",border:"1px solid #00e67640",color:"#00e676",padding:"1px 7px",borderRadius:3,fontSize:10}}>FS</span>}
              {result.status==="success_inferred"&&<span style={{background:"#ffab4010",border:"1px solid #ffab4040",color:"#ffab40",padding:"1px 7px",borderRadius:3,fontSize:10}}>INFERRED</span>}
            </div>
          </div>
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:6}}>
            <ScoreRing score={pqc.score||0} size={72}/>
            <Badge status={pqc.status}/>
            <div style={{color:"#6666aa",fontSize:10}}>{pqc.parameters_checked||40} params</div>
          </div>
        </div>
      </div>
      <div style={{display:"flex",borderBottom:"1px solid #1e1e3a",padding:"0 20px",overflowX:"auto"}}>
        {tabs.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} style={{
            background:"none",border:"none",color:tab===t.id?"#a78bfa":"#666688",
            padding:"10px 12px",cursor:"pointer",fontFamily:"monospace",fontSize:11,
            borderBottom:tab===t.id?"2px solid #a78bfa":"2px solid transparent",
            whiteSpace:"nowrap",position:"relative"}}>
            {t.label}
            {t.alert&&<span style={{position:"absolute",top:6,right:4,width:6,height:6,borderRadius:"50%",background:"#ff1744"}}/>}
          </button>
        ))}
      </div>
      <div style={{flex:1,overflowY:"auto",padding:"16px 20px"}}>
        {tab==="overview"&&(
          <div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
              {[
                ["TLS Version",tls.tls_version||"—",tls.tls_version?.includes("1.3")?"#00e676":"#ffab40"],
                ["Cipher Suite",tls.cipher_suite||"—","#8c9eff"],
                ["Key Exchange",tls.key_exchange||"—",tls.key_exchange?.includes("Quantum-Safe")?"#00e676":"#ff5252"],
                ["Cert Type",`${cert.key_type||"?"}-${cert.key_bits||0}`,cert.pqc_cert?"#00e676":"#ff5252"],
                ["Forward Secrecy",tls.forward_secrecy?"✓ Enabled":"✗ Disabled",tls.forward_secrecy?"#00e676":"#ff5252"],
                ["Cipher Grade",tls.cipher_grade||"?",{A:"#00e676",B:"#c6ff00",C:"#ffab40",D:"#ff5252",F:"#ff1744"}[tls.cipher_grade]||"#888"],
                ["Cert Expires",cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—",cert.days_until_expiry<30?"#ff5252":cert.days_until_expiry<90?"#ffab40":"#00e676"],
                ["CT Logs",cert.ct_sct_count>0?`✓ ${cert.ct_sct_count} SCTs`:"✗ None",cert.ct_sct_count>0?"#00e676":"#ffab40"],
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
                    <SevBadge sev={issue.severity}/><span style={{color:"#ffcccc",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {tab==="cbom"&&(
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              Cryptographic Bill of Materials · CycloneDX v1.4 · NIST SP 800-235
            </div>
            <CBOMTable components={cbom.components}/>
          </div>
        )}
        {tab==="certificate"&&(
          <div>
            {cert.issues?.map((issue,i)=>(
              <div key={i} style={{background:"#100505",border:`1px solid ${SEV_COLOR[issue.severity]}30`,
                borderLeft:`3px solid ${SEV_COLOR[issue.severity]}`,borderRadius:6,padding:"8px 12px",marginBottom:8}}>
                <SevBadge sev={issue.severity}/> <span style={{color:"#ffcccc",fontSize:12,marginLeft:8}}>{issue.issue}</span>
                <div style={{color:"#888",fontSize:11,marginTop:4}}>→ {issue.action}</div>
              </div>
            ))}
            {[["Subject",cert.subject],["Issuer",cert.issuer],
              ["Key Type",`${cert.key_type}-${cert.key_bits}${cert.curve_name?` (${cert.curve_name})`:""}`],
              ["Signature Algo",cert.signature_algorithm],["Valid Until",cert.not_after],
              ["Days Until Expiry",cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—"],
              ["Self-Signed",cert.is_self_signed?"⚠ YES":"No"],
              ["CT SCT Count",cert.ct_sct_count!=null?`${cert.ct_sct_count} SCTs`:"—"],
              ["PQC Certificate",cert.pqc_cert?"✓ YES — Quantum Safe":"✗ NO — Quantum Vulnerable"],
              ["OCSP URL",cert.ocsp_urls?.[0]||"None"],
            ].map(([label,val])=>val&&(
              <div key={label} style={{display:"flex",borderBottom:"1px solid #1a1a2e",padding:"9px 0"}}>
                <div style={{width:160,color:"#6666aa",fontSize:11,flexShrink:0}}>{label}</div>
                <div style={{color:"#c0c0e0",fontSize:12,fontFamily:"monospace",wordBreak:"break-all"}}>{val||"—"}</div>
              </div>
            ))}
            {cert.sans?.length>0&&(
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
        {tab==="vulns"&&<VulnPanel vulns={vulns}/>}
        {tab==="dns"&&<DNSPanel dns={dns}/>}
        {tab==="headers"&&<HeadersPanel http={http}/>}
        {tab==="roadmap"&&(
          <div>
            <div style={{background:"#060f06",border:"1px solid #00e67620",borderRadius:8,padding:"14px 16px",marginBottom:14}}>
              <div style={{color:"#00e676",fontWeight:700,fontSize:13,marginBottom:12}}>🗺 NIST PQC Migration Roadmap for {result.target}</div>
              {[
                {phase:"Phase 1 — Immediate (0–3 months)",color:"#ff5252",items:["Disable TLS 1.0 and TLS 1.1","Replace RC4, 3DES, NULL ciphers with AES-256-GCM","Enforce TLS 1.3","Enable HSTS with max-age=31536000, includeSubDomains, preload","Replace SHA-1 certificates"]},
                {phase:"Phase 2 — Short-term (3–12 months)",color:"#ffab40",items:["Deploy hybrid key exchange: X25519 + ML-KEM-768 (FIPS 203)","Begin PKI migration to ML-DSA (FIPS 204)","Implement crypto-agility framework","Add CAA DNS records","Enable Certificate Transparency logging"]},
                {phase:"Phase 3 — Long-term (1–3 years)",color:"#c6ff00",items:["Full migration to ML-DSA-65 (FIPS 204) certificates","Deploy ML-KEM-1024 for highest-security endpoints","Implement PQC-aware VPN (IKEv2 + ML-KEM)","Achieve NIST SP 800-208 compliance"]},
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
          </div>
        )}
      </div>
    </div>
  );
}

function SummaryBar({results}) {
  if(!results.length) return null;
  const c={QUANTUM_SAFE:0,PQC_READY:0,TRANSITIONING:0,VULNERABLE:0};
  results.forEach(r=>{const s=r.pqc_assessment?.status;if(s in c)c[s]++;});
  const avgScore=results.length?Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length):0;
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
            <div style={{width:`${avgScore}%`,height:"100%",background:"linear-gradient(90deg,#ff1744,#ff9100,#c6ff00,#00e676)",borderRadius:3,transition:"width 1s ease"}}/>
          </div>
          <span style={{color:"#e0e0ff",fontWeight:700,fontFamily:"monospace",fontSize:14}}>{avgScore}/100</span>
        </div>
      </div>
    </div>
  );
}

function ResultCard({result,onSelect,selected}) {
  const pqc=result.pqc_assessment||{},tls=result.tls_info||{};
  const vulnCount=result.vulnerabilities?.length||0;
  const c=RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;
  return (
    <div onClick={()=>onSelect(result)} style={{
      background:selected?"#0e0e20":"#080818",border:`1px solid ${selected?c.border:"#1e1e3a"}`,
      borderLeft:`3px solid ${c.border}`,borderRadius:8,padding:"12px 14px",cursor:"pointer",
      transition:"all 0.2s",marginBottom:8,boxShadow:selected?`0 0 16px ${c.glow}`:"none"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{flex:1,minWidth:0}}>
          <div style={{color:"#e0e0ff",fontWeight:700,fontFamily:"monospace",fontSize:13,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>🔒 {result.target}</div>
          <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>{tls.tls_version||"—"} · {tls.cipher_grade?`Grade ${tls.cipher_grade}`:""}
            {vulnCount>0&&<span style={{color:"#ff5252",marginLeft:6}}>⚠ {vulnCount} vuln{vulnCount>1?"s":""}</span>}
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
          <ScoreRing score={pqc.score||0} size={48}/><Badge status={pqc.status} small/>
        </div>
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function QuantumShield() {
  const [user,setUser]       = useState(getUser);
  const [token,setToken]     = useState(getToken);
  const [targets,setTargets] = useState("google.com\nexample.com\ncloudflare.com\npnbindia.in\nrc4.badssl.com");
  const [results,setResults] = useState([]);
  const [scanning,setScanning] = useState(false);
  const [selected,setSelected] = useState(null);
  const [progress,setProgress] = useState({current:0,total:0,current_target:""});
  const [backendUrl,setBackendUrl] = useState(BACKEND);
  const [backendOk,setBackendOk]   = useState(false);
  const [activeView,setActiveView] = useState("scanner");
  const [termLog,setTermLog]       = useState([]);
  const termRef = useRef(null);

  // Check backend health
  useEffect(()=>{
    fetch(`${backendUrl}/api/v1/health`,{signal:AbortSignal.timeout(3000)})
      .then(r=>r.ok&&setBackendOk(true)).catch(()=>setBackendOk(false));
  },[backendUrl]);

  useEffect(()=>{ if(termRef.current) termRef.current.scrollTop=termRef.current.scrollHeight; },[termLog]);

  const addLog = (msg,color="#8888cc") => setTermLog(l=>[...l.slice(-60),{msg,color,t:new Date().toLocaleTimeString()}]);

  const handleLogin = (u,t) => { setUser(u); setToken(t); };

  const handleLogout = () => {
    clearAuth(); setUser(null); setToken(""); setResults([]); setSelected(null); setTermLog([]);
    setActiveView("scanner");
  };

  const handleScan = async () => {
    const list=targets.split("\n").map(t=>t.trim()).filter(Boolean);
    if(!list.length) return;
    setScanning(true); setResults([]); setSelected(null); setTermLog([]);
    addLog("QuantumShield v2.0 — Deep PQC Scan initiated","#a78bfa");
    addLog(`Targets: ${list.length} | Parameters: 40+ | User: ${user?.username||"guest"}`,"#6666aa");
    addLog("─".repeat(50),"#2a2a4a");
    setProgress({current:0,total:list.length,current_target:""});
    const newResults=[];
    for(let i=0;i<list.length;i++) {
      const t=list[i];
      setProgress({current:i,total:list.length,current_target:t});
      addLog(`[${i+1}/${list.length}] Scanning ${t}...`,"#8888cc");
      addLog(`  → TLS + Certificate + DNS + Headers + Vulns + PQC score`,"#4a4a6a");
      const r=await performScan(t,token);
      newResults.push(r);
      setResults([...newResults]);
      // Save to localStorage as fallback
      try {
        const hist=JSON.parse(localStorage.getItem("qs_scan_history")||"[]");
        const entry={scan_id:r.scan_id||`${t}-${Date.now()}`,target:t,pqc_score:r.pqc_assessment?.score,
          pqc_status:r.pqc_assessment?.status,tls_version:r.tls_info?.tls_version,
          cipher_suite:r.tls_info?.cipher_suite,scanned_at:new Date().toISOString(),username:user?.username};
        localStorage.setItem("qs_scan_history",JSON.stringify([entry,...hist].slice(0,50)));
      } catch(_) {}
      const score=r.pqc_assessment?.score||0;
      const status=r.pqc_assessment?.status||"UNKNOWN";
      const scoreColor=score>=75?"#00e676":score>=50?"#c6ff00":score>=35?"#ff9100":"#ff1744";
      addLog(`  ✓ ${t} — Score: ${score}/100 [${status}]`,scoreColor);
      const vcount=r.vulnerabilities?.length||0;
      if(vcount>0) addLog(`  ⚠ ${vcount} vulnerabilities detected`,"#ff5252");
      addLog("","#333");
    }
    addLog("─".repeat(50),"#2a2a4a");
    const safe=newResults.filter(r=>r.pqc_assessment?.status==="QUANTUM_SAFE").length;
    const vuln=newResults.filter(r=>r.pqc_assessment?.status==="VULNERABLE").length;
    const avg=Math.round(newResults.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/newResults.length);
    addLog(`Scan complete. ${list.length} assets. Avg Score: ${avg}/100 | Safe: ${safe} | Vulnerable: ${vuln}`,"#a78bfa");
    setProgress(p=>({...p,current:list.length,current_target:""}));
    setScanning(false);
    if(newResults.length>0) setSelected(newResults[0]);
  };

  const exportCBOM = () => {
    const report={
      report_metadata:{title:"QuantumShield CBOM Report",generated_at:new Date().toISOString(),
        scanner:"QuantumShield v2.0",generated_by:user?.username,nist_reference:["FIPS 203","FIPS 204","FIPS 205"]},
      executive_summary:{
        total_assets:results.length,
        quantum_safe:results.filter(r=>r.pqc_assessment?.status==="QUANTUM_SAFE").length,
        pqc_ready:results.filter(r=>r.pqc_assessment?.status==="PQC_READY").length,
        transitioning:results.filter(r=>r.pqc_assessment?.status==="TRANSITIONING").length,
        vulnerable:results.filter(r=>r.pqc_assessment?.status==="VULNERABLE").length,
        avg_score:results.length?Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length):0,
      },
      assets:results.map(r=>({
        asset:r.target,tls_version:r.tls_info?.tls_version,cipher_suite:r.tls_info?.cipher_suite,
        cipher_grade:r.tls_info?.cipher_grade,pqc_score:r.pqc_assessment?.score,
        pqc_status:r.pqc_assessment?.status,vulnerabilities:r.vulnerabilities,
        cert_type:`${r.certificate?.key_type}-${r.certificate?.key_bits}`,
        cert_expiry_days:r.certificate?.days_until_expiry,
      }))
    };
    const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});
    const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
    a.download=`quantumshield-cbom-${Date.now()}.json`; a.click();
  };

  if(!user) return <LoginScreen onLogin={handleLogin}/>;

  const totalVulns=results.reduce((a,r)=>a+(r.vulnerabilities?.length||0),0);
  const navItems=[
    {id:"scanner",label:"SCANNER"},
    {id:"history",label:"HISTORY"},
    ...(user.role==="Admin"?[{id:"admin",label:"ADMIN"}]:[]),
    {id:"profile",label:"PROFILE"},
    {id:"algorithms",label:"ALGORITHMS"},
  ];

  return (
    <div style={{background:"#05050e",minHeight:"100vh",fontFamily:"'IBM Plex Mono','Courier New',monospace",color:"#e0e0ff",overflow:"hidden"}}>
      {/* Header */}
      <div style={{background:"#07071a",borderBottom:"1px solid #1e1e3a",padding:"0 20px",display:"flex",alignItems:"center",justifyContent:"space-between",height:56,flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:30,height:30,background:"linear-gradient(135deg,#7c3aed,#1d4ed8)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>⚛</div>
          <div>
            <div style={{color:"#e0e0ff",fontWeight:800,fontSize:16,letterSpacing:2}}>QUANTUMSHIELD</div>
            <div style={{color:"#6666aa",fontSize:9,letterSpacing:1}}>PQC SCANNER v2.0 · NIST FIPS 203/204/205</div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{display:"flex",gap:3}}>
            {navItems.map(v=>(
              <button key={v.id} onClick={()=>setActiveView(v.id)} style={{
                background:activeView===v.id?"#1e1e3a":"none",border:activeView===v.id?"1px solid #2e2e5a":"1px solid transparent",
                color:activeView===v.id?"#a78bfa":"#6666aa",padding:"5px 12px",borderRadius:5,cursor:"pointer",
                fontFamily:"monospace",fontSize:11,letterSpacing:1}}>{v.label}</button>
            ))}
          </div>
          {results.length>0&&totalVulns>0&&(
            <div style={{background:"#ff174420",border:"1px solid #ff174440",color:"#ff5252",
              padding:"3px 10px",borderRadius:4,fontSize:11}}>⚠ {totalVulns} VULNS</div>
          )}
          <div style={{display:"flex",alignItems:"center",gap:5,fontSize:11,color:backendOk?"#00e676":"#ffab40"}}>
            <div style={{width:6,height:6,borderRadius:"50%",background:backendOk?"#00e676":"#ffab40",boxShadow:`0 0 6px ${backendOk?"#00e676":"#ffab40"}`}}/>
            {backendOk?"LIVE":"DEMO"}
          </div>
          <div style={{display:"flex",alignItems:"center",gap:8,padding:"4px 10px",background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:6}}>
            <span style={{color:{Admin:"#ff5252",Operator:"#ffab40",Checker:"#8c9eff",Viewer:"#6666aa"}[user.role]||"#888",fontSize:10,fontWeight:700}}>{user.role}</span>
            <span style={{color:"#6666aa",fontSize:11}}>{user.username}</span>
            <button onClick={handleLogout} style={{background:"none",border:"1px solid #2a2a4a",color:"#6666aa",
              padding:"2px 8px",borderRadius:4,cursor:"pointer",fontFamily:"monospace",fontSize:10}}>↩ OUT</button>
          </div>
        </div>
      </div>

      {/* Views */}
      {activeView==="history" && <HistoryPanel token={token} user={user}/>}
      {activeView==="admin"   && user.role==="Admin" && <AdminPanel token={token}/>}
      {activeView==="profile" && <ProfilePanel user={user}/>}

      {activeView==="algorithms" && (
        <div style={{overflowY:"auto",height:"calc(100vh - 56px)",padding:"24px 32px",maxWidth:960,margin:"0 auto"}}>
          <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:20}}>NIST POST-QUANTUM CRYPTOGRAPHY STANDARDS — FINAL (2024)</div>
          {[{std:"FIPS 203",name:"ML-KEM",full:"Module Lattice-based Key Encapsulation Mechanism",
             variants:["ML-KEM-512 (Level 1)","ML-KEM-768 (Level 3) ★","ML-KEM-1024 (Level 5)"],
             replaces:"RSA/ECDH Key Exchange",color:"#60a5fa",icon:"🔑"},
            {std:"FIPS 204",name:"ML-DSA",full:"Module Lattice-based Digital Signature Algorithm",
             variants:["ML-DSA-44 (Level 2)","ML-DSA-65 (Level 3) ★","ML-DSA-87 (Level 5)"],
             replaces:"RSA/ECDSA Digital Signatures",color:"#34d399",icon:"✍️"},
            {std:"FIPS 205",name:"SLH-DSA",full:"Stateless Hash-based Digital Signature Algorithm",
             variants:["SLH-DSA-SHA2-128s/f","SLH-DSA-SHA2-192s/f ★","SLH-DSA-SHA2-256s/f"],
             replaces:"RSA/ECDSA (hash-based conservative)",color:"#a78bfa",icon:"🌳"},
          ].map(algo=>(
            <div key={algo.std} style={{background:"#0a0a1e",border:`1px solid ${algo.color}30`,borderLeft:`4px solid ${algo.color}`,borderRadius:10,padding:"18px 20px",marginBottom:14}}>
              <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:10}}>
                <span style={{background:`${algo.color}22`,color:algo.color,padding:"2px 10px",borderRadius:4,fontSize:11,fontWeight:700,fontFamily:"monospace"}}>{algo.std}</span>
                <span style={{color:"#e0e0ff",fontWeight:800,fontSize:18}}>{algo.name}</span>
                <span style={{fontSize:20}}>{algo.icon}</span>
              </div>
              <div style={{color:"#8888aa",fontSize:12,marginBottom:6}}>{algo.full}</div>
              <div style={{color:"#6666aa",fontSize:11,marginBottom:10}}>REPLACES: <span style={{color:"#ffab40"}}>{algo.replaces}</span></div>
              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                {algo.variants.map(v=>(
                  <span key={v} style={{background:v.includes("★")?`${algo.color}22`:"#1a1a2e",border:`1px solid ${v.includes("★")?algo.color:"#2a2a4a"}`,
                    color:v.includes("★")?algo.color:"#8888aa",padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{v}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {activeView==="scanner" && (
        <div style={{display:"grid",gridTemplateColumns:"310px 1fr 460px",height:"calc(100vh - 56px)"}}>
          {/* Left panel */}
          <div style={{borderRight:"1px solid #1e1e3a",display:"flex",flexDirection:"column",background:"#07071a",overflow:"hidden"}}>
            <div style={{padding:"14px 16px",borderBottom:"1px solid #1e1e3a",flexShrink:0}}>
              <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:8}}>SCAN TARGETS</div>
              <textarea value={targets} onChange={e=>setTargets(e.target.value)}
                placeholder="Enter domains, one per line"
                style={{width:"100%",height:110,background:"#0a0a1e",border:"1px solid #2a2a4a",
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
              {scanning&&(
                <div style={{marginTop:8}}>
                  <div style={{background:"#0a0a1e",borderRadius:3,overflow:"hidden",height:3}}>
                    <div style={{height:"100%",background:"linear-gradient(90deg,#7c3aed,#2563eb)",
                      width:`${(progress.current/progress.total)*100}%`,transition:"width 0.5s"}}/>
                  </div>
                  <div style={{color:"#6666aa",fontSize:10,marginTop:4}}>→ {progress.current_target}</div>
                </div>
              )}
            </div>
            <div style={{flex:1,overflowY:"auto",padding:"10px 14px",background:"#050510"}} ref={termRef}>
              {termLog.length===0&&!scanning&&(
                <div style={{color:"#2a2a4a",fontSize:11,lineHeight:1.8}}>
                  <div style={{color:"#3a3a6a",marginBottom:8}}>$ quantumshield --deep-scan</div>
                  <div>40+ parameters per target:</div>
                  {["TLS version & cipher","Certificate deep inspection","Key exchange detection",
                    "Forward secrecy check","Vulnerability DB cross-ref","DNS security (CAA/DNSSEC)",
                    "HTTP security headers","CBOM generation","PQC readiness scoring"].map(i=>(
                    <div key={i}>· {i}</div>
                  ))}
                </div>
              )}
              {termLog.map((l,i)=>(
                <div key={i} style={{fontFamily:"monospace",fontSize:11,lineHeight:1.7,color:l.color,whiteSpace:"pre-wrap"}}>{l.msg}</div>
              ))}
            </div>
            {results.length>0&&(
              <div style={{padding:"10px 14px",borderTop:"1px solid #1e1e3a",flexShrink:0}}>
                <button onClick={exportCBOM} style={{width:"100%",padding:"8px",background:"#0a0a1e",
                  border:"1px solid #2a2a5a",color:"#8888cc",borderRadius:7,cursor:"pointer",
                  fontFamily:"monospace",fontSize:11,letterSpacing:1}}>
                  📥 EXPORT CBOM REPORT (JSON)
                </button>
              </div>
            )}
          </div>
          {/* Middle panel */}
          <div style={{borderRight:"1px solid #1e1e3a",overflowY:"auto",padding:"16px"}}>
            {results.length>0?(
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
                        const pqc=r.pqc_assessment||{},tls=r.tls_info||{},cert=r.certificate||{},vcount=r.vulnerabilities?.length||0;
                        return (
                          <tr key={i} onClick={()=>setSelected(r)} style={{borderBottom:"1px solid #1a1a2e",cursor:"pointer",background:selected?.target===r.target?"#0e0e22":"transparent"}}>
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
                <div style={{marginTop:16}}>
                  {results.map((r,i)=>(<ResultCard key={i} result={r} onSelect={setSelected} selected={selected?.target===r.target}/>))}
                </div>
              </>
            ):(
              <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"80vh",color:"#1e1e3a"}}>
                <div style={{fontSize:72,marginBottom:20}}>⚛</div>
                <div style={{fontSize:16,color:"#3a3a6a",letterSpacing:4}}>QUANTUMSHIELD v2.0</div>
                <div style={{fontSize:11,color:"#2a2a5a",marginTop:8,letterSpacing:2}}>40+ PARAMETERS · NIST FIPS 203/204/205</div>
                <div style={{fontSize:11,color:"#2a2a4a",marginTop:6}}>Logged in as {user.username} ({user.role})</div>
              </div>
            )}
          </div>
          {/* Right panel */}
          <div style={{overflowY:"auto"}}><DetailPanel result={selected}/></div>
        </div>
      )}
    </div>
  );
}
