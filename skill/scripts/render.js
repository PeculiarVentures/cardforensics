#!/usr/bin/env node
/**
 * CardForensics dashboard renderer v3 — matches web app UX.
 *
 * Two-line exchange rows, annotated hex detail, parsed cert display,
 * phase bar, session filtering, threat cross-referencing.
 */
import { readFileSync, writeFileSync, existsSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
const __dirname = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const inputIdx = args.indexOf("--input");
const outputIdx = args.indexOf("--output");
let json = (inputIdx >= 0 && args[inputIdx + 1]) ? readFileSync(args[inputIdx + 1], "utf-8") : readFileSync("/dev/stdin", "utf-8");
const data = JSON.parse(json);

// Auto-trim heavy fields for artifact size limits
const rawSize = JSON.stringify(data).length;
if (rawSize > 50000) {
  console.error(`Data is ${Math.round(rawSize/1024)}KB — stripping hex/timestamps...`);
  if (data.timeline) data.timeline.forEach(t => { delete t.ts; });
  delete data.all_annotations;
  delete data.object_ledger;
  if (data.sessions) data.sessions.forEach(s => { if (s.operations?.length > 10) s.operations = s.operations.slice(0, 10); });
  const trimmedSize = JSON.stringify(data).length;
  console.error(`  After strip: ${Math.round(trimmedSize/1024)}KB (${data.timeline?.length} exchanges)`);
  // If still large, drop hex data
  if (trimmedSize > 250000) {
    console.error(`  Stripping hex data...`);
    data.timeline.forEach(t => { delete t.cmdHex; delete t.rspHex; });
    const noHexSize = JSON.stringify(data).length;
    console.error(`  After hex strip: ${Math.round(noHexSize/1024)}KB`);
    // Only drop exchanges if still massive
    if (noHexSize > 250000 && data.timeline?.length > 200) {
      const notable = new Set((data.notable_annotations || []).map(a => a.exchange));
      const sessionStarts = new Set((data.sessions || []).map((s, i) => {
        const first = data.timeline.find(t => t.session === i);
        return first?.id;
      }).filter(Boolean));
      data.timeline = data.timeline.filter(t => notable.has(t.id) || sessionStarts.has(t.id) || t.flag);
      data._trimmed = { original: data.exchange_count, shown: data.timeline.length };
      console.error(`  Reduced timeline: ${data.exchange_count} → ${data.timeline.length} exchanges`);
    }
  }
}

// Load vendored PV cert viewer if data has certs
const hasCerts = data.timeline?.some(t => t.cert);
let pvB64 = "";
if (hasCerts) {
  const pvPath = join(__dirname, "../vendor/pv-cert-viewer.b64");
  if (existsSync(pvPath)) {
    pvB64 = readFileSync(pvPath, "utf-8").trim();
    console.error(`  PV cert viewer: ${Math.round(pvB64.length/1024)}KB (base64)`);
  } else {
    console.error(`  Warning: PV cert viewer not found at ${pvPath}`);
  }
}

const out = generateJSX(data, pvB64);
if (outputIdx >= 0 && args[outputIdx + 1]) { writeFileSync(args[outputIdx + 1], out); console.error(`Dashboard written to ${args[outputIdx + 1]}`); } else { console.log(out); }

function generateJSX(data, pvB64) {
const pvConst = pvB64 ? `\nconst PV_B64="${pvB64}";\nconst PV_VARS=[["--pv-color-black","#c8d3e8"],["--pv-color-white","#0e1218"],["--pv-color-base","#0e1218"],["--pv-color-gray-1","#0e1218"],["--pv-color-gray-2","#111620"],["--pv-color-gray-3","#151b28"],["--pv-color-gray-4","#1e2940"],["--pv-color-gray-5","#2a3654"],["--pv-color-gray-6","#3a4560"],["--pv-color-gray-7","#1e2940"],["--pv-color-gray-8","#4a5568"],["--pv-color-gray-9","#8899bb"],["--pv-color-gray-10","#c8d3e8"],["--pv-color-primary","#5eead4"],["--pv-color-primary-contrast","#0e1218"],["--pv-color-secondary","#a78bfa"],["--pv-color-success","#34d399"],["--pv-color-wrong","#f87171"],["--pv-color-attention","#fbbf24"],["--pv-font-family","'SF Mono',Menlo,Monaco,monospace"],["--pv-size-base","3px"],["--pv-text-b1-size","11px"],["--pv-text-b2-size","10px"],["--pv-text-b3-size","9px"],["--pv-text-h4-size","12px"],["--pv-text-h5-size","11px"],["--pv-text-s1-size","10px"],["--pv-text-s2-size","9px"],["--pv-shadow-dark-hight","none"],["--pv-shadow-dark-medium","none"],["--pv-shadow-light-hight","none"],["--pv-shadow-light-low","none"],["--pv-shadow-light-medium","none"]];
` : "";
return `import{useState,useRef,useEffect}from"react";
const D=${JSON.stringify(data)};${pvConst}
const C={bg:"#0a0d12",surface:"#111720",s2:"#161d28",border:"#1c2536",text:"#c8d0e0",dim:"#4a5570",muted:"#7888a4",teal:"#4ad8c7",green:"#34d399",amber:"#fbbf24",red:"#f87171",blue:"#60a5fa",purple:"#a78bfa",pink:"#f472b6",white:"#fff"};
const PC={"pre-select probing":"#6366f1","application selection":C.blue,"GP card enumeration":C.purple,"PIV discovery":C.teal,"vendor object inventory":"#8b5cf6",authentication:C.amber,personalization:C.pink,"post-write verification":C.green,"idle / status read":C.dim};
const PS={"pre-select probing":"PROBE","application selection":"SELECT","GP card enumeration":"GP","PIV discovery":"PIV","vendor object inventory":"VENDOR",authentication:"AUTH",personalization:"WRITE","post-write verification":"VERIFY","idle / status read":"IDLE"};
const CN={"5FC105":"PIV Auth (9A)","5FC10A":"Dig Sig (9C)","5FC10B":"Key Mgmt (9D)","5FC101":"Card Auth (9E)"};
const flagC=f=>f==="bug"?C.red:f==="key"?C.green:f==="warn"?C.amber:f==="expected"?C.dim:null;
const flagBg=f=>f==="bug"?"#1a080811":f==="key"?"#082a1811":f==="warn"?"#1a160811":f==="expected"?"#11111411":"transparent";
const Badge=({color:c,children:ch})=><span style={{fontSize:9,fontWeight:700,color:c,border:\`1px solid \${c}44\`,borderRadius:3,padding:"1px 6px",letterSpacing:.5,whiteSpace:"nowrap"}}>{ch}</span>;
const swC=s=>s==="ok"?C.green:s==="err"?C.red:s==="warn"?C.amber:C.muted;

function ExRow({t,sel,onClick}){
  const pc=PC[t.phase]||C.dim;
  return <div onClick={onClick} style={{borderBottom:\`1px solid \${C.border}\`,background:sel?\`\${C.teal}0c\`:"transparent",cursor:"pointer"}}>
    {/* CMD line */}
    <div style={{display:"flex",alignItems:"center",gap:6,padding:"4px 10px",fontFamily:"monospace",fontSize:11}}>
      <span style={{color:C.dim,fontSize:9,width:28,textAlign:"right",flexShrink:0}}>{t.id}</span>
      <span style={{color:C.muted,width:68,fontSize:9,flexShrink:0}}>{t.ts?.split(" ")[1]?.substring(0,12)||""}{t.dt!=null?<span style={{color:C.dim,fontSize:8,marginLeft:2}}>{t.dt}ms</span>:null}</span>
      {t.auth&&<span style={{fontSize:8,color:C.green,flexShrink:0}}>🔒</span>}
      <span style={{fontSize:8,color:pc,border:\`1px solid \${C.border}\`,borderRadius:2,padding:"0 3px",flexShrink:0}}>{PS[t.phase]||""}</span>
      <span style={{color:C.blue,fontSize:10,flexShrink:0}}>▶ CMD</span>
      <span style={{fontSize:8,padding:"1px 4px",borderRadius:2,background:C.purple+"22",color:C.purple,border:\`1px solid \${C.purple}44\`,flexShrink:0}}>{t.claDesc||t.cla}</span>
      <span style={{color:C.white,fontWeight:600,flexShrink:0}}>{t.ins}</span>
      <span style={{color:C.muted,flexShrink:0}}>P1={t.p1} P2={t.p2}</span>
      {t.lc!=null&&<span style={{color:C.dim,flexShrink:0}}>Lc={t.lc}</span>}
      <span style={{color:C.dim,fontSize:10,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",flex:1}}>{t.cmdHex?.substring(0,60)}</span>
    </div>
    {/* RSP line */}
    {t.sw&&<div style={{display:"flex",alignItems:"center",gap:6,padding:"2px 10px 3px",fontFamily:"monospace",fontSize:11}}>
      <span style={{width:28,flexShrink:0}}/>
      <span style={{width:68,flexShrink:0}}/>
      <span style={{color:C.green,fontSize:10,flexShrink:0}}>◀ RSP</span>
      <span style={{color:swC(t.swSev),fontWeight:700,flexShrink:0}}>{t.sw}</span>
      <span style={{color:swC(t.swSev),fontSize:10,flexShrink:0}}>{t.swMsg}</span>
      {t.dataLen>0&&<span style={{color:C.muted,fontSize:10,flexShrink:0}}>{t.dataLen}B</span>}
      {t.continuations>0&&<span style={{fontSize:8,color:C.teal,border:\`1px solid \${C.teal}44\`,borderRadius:3,padding:"0 4px"}}>⛓ {t.continuations+1} chunks</span>}
    </div>}
    {/* Annotation */}
    {t.note&&<div style={{padding:"3px 10px 3px 108px",borderLeft:\`2px solid \${flagC(t.flag)||C.muted}\`,background:flagBg(t.flag),color:flagC(t.flag)||C.muted,fontSize:10}}>✦ {t.note}</div>}
  </div>;
}

function ExDetail({t}){
  const [hexOpen,setHexOpen]=useState(false);
  return <div style={{background:C.s2,borderBottom:\`2px solid \${C.teal}44\`}}>
    {/* Header */}
    <div style={{padding:"8px 12px",borderBottom:\`1px solid \${C.border}\`,background:C.surface}}>
      <div style={{fontWeight:700,color:C.text,fontSize:13,fontFamily:"monospace"}}>Exchange #{t.id}</div>
      <div style={{display:"flex",gap:12,marginTop:4,fontSize:10,color:C.muted,fontFamily:"monospace",flexWrap:"wrap"}}>
        <span>{t.ts}</span>
        <span>{t.ins}</span>
        {t.sw&&<span style={{color:swC(t.swSev)}}>{t.sw} {t.swMsg}</span>}
        {t.dt!=null&&<span>{t.dt}ms</span>}
        {t.auth&&<span style={{color:C.green}}>🔒 {t.selected||"SCP"}</span>}
      </div>
    </div>

    {/* Annotation bar */}
    {t.note&&<div style={{padding:"6px 12px",borderLeft:\`3px solid \${flagC(t.flag)||C.teal}\`,background:flagBg(t.flag),color:flagC(t.flag)||C.teal,fontSize:11}}>✦ {t.note}</div>}

    {/* Fields */}
    <div style={{padding:"8px 12px",fontSize:11,display:"grid",gridTemplateColumns:"90px 1fr",gap:"2px 8px",lineHeight:1.7}}>
      <span style={{color:C.dim}}>Instruction</span><span>{t.ins}</span>
      <span style={{color:C.dim}}>CLA</span><span style={{fontFamily:"monospace"}}>{t.cla} ({t.claDesc})</span>
      <span style={{color:C.dim}}>P1 / P2</span><span style={{fontFamily:"monospace"}}>{t.p1} / {t.p2}</span>
      {t.lc!=null&&<><span style={{color:C.dim}}>Lc</span><span>{t.lc}</span></>}
      <span style={{color:C.dim}}>Phase</span><span style={{color:PC[t.phase]||C.muted}}>{t.phase}</span>
      <span style={{color:C.dim}}>Session</span><span>{t.session}</span>
      <span style={{color:C.dim}}>Auth</span><span style={{color:t.auth?C.green:C.dim}}>{t.auth?"Authenticated":"No"}</span>
      {t.selected&&<><span style={{color:C.dim}}>Selected</span><span>{t.selected}</span></>}
      <span style={{color:C.dim}}>Cmd size</span><span>{t.cmdLen}B</span>
      <span style={{color:C.dim}}>Rsp size</span><span>{t.rspLen}B{t.dataLen?\` (\${t.dataLen}B data)\`:""}</span>
      {t.continuations>0&&<><span style={{color:C.dim}}>Chaining</span><span>{t.continuations} GET RESPONSE continuations</span></>}
    </div>

    {/* PV Certificate Viewer */}
    {t.cert&&t.cert.b64&&typeof PV_B64!=="undefined"&&<PVMount b64={t.cert.b64} slot={CN[t.cert.slot]||t.cert.slot}/>}
    {t.cert&&(!t.cert.b64||typeof PV_B64==="undefined")&&<div style={{padding:"8px 12px",borderTop:\`1px solid \${C.border}\`,fontSize:10,color:C.muted}}>Certificate data not available for PV viewer</div>}

    {/* Hex toggle */}
    <div style={{borderTop:\`1px solid \${C.border}\`}}>
      <div onClick={()=>setHexOpen(!hexOpen)} style={{padding:"4px 12px",fontSize:10,color:C.muted,cursor:"pointer"}}>{hexOpen?"▼":"▶"} Raw Hex</div>
      {hexOpen&&<div style={{padding:"4px 12px 8px",fontFamily:"monospace",fontSize:10,lineHeight:1.8,wordBreak:"break-all"}}>
        <div style={{color:C.blue,marginBottom:2}}>CMD</div>
        <div style={{color:C.dim,marginBottom:6,background:C.bg,padding:"4px 6px",borderRadius:3}}>{t.cmdHex}</div>
        {t.rspHex&&<><div style={{color:C.green,marginBottom:2}}>RSP</div>
        <div style={{color:C.dim,background:C.bg,padding:"4px 6px",borderRadius:3}}>{t.rspHex}</div></>}
      </div>}
    </div>
  </div>;
}

let pvLoaded=false;
function loadPV(){
  if(pvLoaded||typeof PV_B64==="undefined")return Promise.resolve(false);
  try{
    const code=atob(PV_B64);
    new Function(code)();
    pvLoaded=true;
    return Promise.resolve(true);
  }catch(e){console.warn("PV load failed:",e);return Promise.resolve(false);}
}
function PVMount({b64,slot}){
  const ref=useRef(null);
  const[ready,setReady]=useState(pvLoaded);
  useEffect(()=>{if(!pvLoaded)loadPV().then(ok=>{if(ok)setReady(true);});},[]);
  useEffect(()=>{
    if(!ready||!ref.current||!b64)return;
    const el=ref.current;
    el.innerHTML="";
    const viewer=document.createElement("peculiar-certificate-viewer");
    if(typeof PV_VARS!=="undefined")PV_VARS.forEach(([k,v])=>viewer.style.setProperty(k,v));
    viewer.certificate=b64;
    el.appendChild(viewer);
    return()=>{el.innerHTML="";};
  },[ready,b64]);
  return <div style={{borderTop:\`1px solid \${C.border}\`}}>
    <div style={{padding:"6px 10px",background:"#0b0f16",display:"flex",alignItems:"center",gap:8,borderBottom:\`1px solid \${C.border}\`}}>
      <span style={{color:C.teal,fontWeight:700,fontSize:11}}>X.509 Certificate</span>
      <span style={{fontSize:9,padding:"1px 6px",borderRadius:3,background:C.teal+"18",color:C.teal,border:\`1px solid \${C.teal}44\`}}>{slot}</span>
    </div>
    <div ref={ref} style={{overflow:"auto",maxHeight:500,background:"#0b0f16"}}>
      {!ready&&<div style={{padding:10,fontSize:10,color:C.dim}}>Loading certificate viewer...</div>}
    </div>
  </div>;
}

function PhaseBar({tl,s,oc}){
  const exs=s!=null?tl.filter(t=>t.session===s):tl;
  if(!exs.length)return null;
  return <div style={{display:"flex",height:14,borderRadius:3,overflow:"hidden",cursor:"pointer"}}>
    {exs.map((t,i)=><div key={i} onClick={()=>oc(t.id)} title={\`#\${t.id} \${t.ins} \${t.note||""}\`}
      style={{flex:1,minWidth:1,background:t.flag==="bug"?C.red:t.flag==="key"?C.green:PC[t.phase]||C.dim,opacity:t.ok?.65:1,borderRight:i<exs.length-1?\`1px solid \${C.bg}\`:"none"}}/>)}
  </div>;
}

export default function Dashboard(){
  const d=D,card=d.card_identification,token=d.token_identity,chuid=token?.chuid,score=d.security_score,certs=d.cert_provisioning;
  const threats=(d.threats||[]).filter(t=>t.severity!=="pass"),tl=d.timeline||[],sessions=d.sessions||[];
  const[sel,setSel]=useState(null),[as,setAs]=useState(null),[tab,setTab]=useState("replay");
  const[playing,setPlaying]=useState(false);
  const playRef=useRef(null);
  const filtered=as!=null?tl.filter(t=>t.session===as):tl;
  const go=id=>{setSel(id);setTab("replay");setTimeout(()=>{const el=document.getElementById(\`ex-\${id}\`);if(el)el.scrollIntoView({behavior:"smooth",block:"center"});},30);};
  // Auto-advance when playing
  useEffect(()=>{
    if(playing&&filtered.length){
      playRef.current=setInterval(()=>{
        setSel(prev=>{
          const ids=filtered.map(t=>t.id);
          const ci=prev!=null?ids.indexOf(prev):-1;
          const ni=ci<ids.length-1?ci+1:0;
          const nid=ids[ni];
          if(ni===0&&ci===ids.length-1){setPlaying(false);clearInterval(playRef.current);}
          setTimeout(()=>{const el=document.getElementById(\`ex-\${nid}\`);if(el)el.scrollIntoView({behavior:"smooth",block:"nearest"});},20);
          return nid;
        });
      },800);
    }
    return()=>{if(playRef.current)clearInterval(playRef.current);};
  },[playing,filtered]);
  useEffect(()=>{
    const onKey=e=>{
      if(tab!=="replay"||!filtered.length)return;
      if(e.key===" "){e.preventDefault();setPlaying(p=>!p);return;}
      if(playing)return;
      const ids=filtered.map(t=>t.id);
      const ci=sel!=null?ids.indexOf(sel):-1;
      let ni=-1;
      if(e.key==="ArrowDown"||e.key==="j"){ni=ci<ids.length-1?ci+1:0;e.preventDefault();}
      else if(e.key==="ArrowUp"||e.key==="k"){ni=ci>0?ci-1:ids.length-1;e.preventDefault();}
      else return;
      if(ni>=0){const nid=ids[ni];setSel(nid);setTimeout(()=>{const el=document.getElementById(\`ex-\${nid}\`);if(el)el.scrollIntoView({behavior:"smooth",block:"nearest"});},20);}
    };
    window.addEventListener("keydown",onKey);
    return()=>window.removeEventListener("keydown",onKey);
  },[tab,sel,filtered,playing]);
  const sc=score?.score>=90?C.green:score?.score>=70?C.amber:C.red;
  const phases=[...new Set(tl.map(t=>t.phase).filter(Boolean))];

  return <div style={{fontFamily:"'IBM Plex Sans',-apple-system,sans-serif",background:C.bg,color:C.text,height:"100vh",display:"flex",flexDirection:"column",overflow:"hidden"}}>
    {/* Header */}
    <div style={{padding:"12px 14px",borderBottom:\`1px solid \${C.border}\`,display:"flex",alignItems:"center",gap:10,flexShrink:0,background:C.surface}}>
      <div style={{flex:1}}>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <span style={{fontWeight:700,fontSize:14,color:C.white,letterSpacing:1}}>CardForensics</span>
          {card&&<Badge color={C.teal}>{card.name}</Badge>}
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:2,display:"flex",gap:12,flexWrap:"wrap"}}>
          {token?.serial&&<span>S/N <span style={{color:C.muted,fontFamily:"monospace"}}>{token.serial}</span></span>}
          {token?.version&&<span>FW <span style={{color:C.muted,fontFamily:"monospace"}}>{token.version}</span></span>}
          <span>{d.exchange_count} exchanges</span><span>{d.session_count} sessions</span>
          {chuid?.expiration&&<span>Exp {chuid.expiration}</span>}
        </div>
      </div>
      {score&&<div style={{textAlign:"right"}}><div style={{fontSize:24,fontWeight:700,color:sc,lineHeight:1}}>{score.score}</div><div style={{fontSize:8,color:C.dim,letterSpacing:1}}>{score.label?.toUpperCase()}</div></div>}
    </div>

    {/* Threats */}
    {threats.length>0&&<div style={{padding:"6px 14px",borderBottom:\`1px solid \${C.border}\`,background:C.red+"06",display:"flex",gap:6,flexWrap:"wrap",flexShrink:0}}>
      {threats.map((t,i)=>{const tc=t.severity==="critical"?C.red:t.severity==="warn"?C.amber:C.blue;
        return <div key={i} onClick={()=>t.exchange_ids?.[0]!=null&&go(t.exchange_ids[0])} style={{fontSize:10,padding:"3px 8px",borderRadius:3,border:\`1px solid \${tc}44\`,background:\`\${tc}10\`,cursor:t.exchange_ids?.length?"pointer":"default"}}>
          <Badge color={tc}>{t.severity}</Badge> <span style={{color:C.text,marginLeft:4}}>{t.title}</span></div>;})}
    </div>}

    {/* Session tabs + phase bar */}
    <div style={{padding:"6px 14px 4px",borderBottom:\`1px solid \${C.border}\`,flexShrink:0,background:C.surface}}>
      <div style={{display:"flex",gap:4,marginBottom:4}}>
        <button onClick={()=>setAs(null)} style={{fontSize:9,padding:"2px 8px",borderRadius:3,border:\`1px solid \${as==null?C.teal:C.border}\`,background:as==null?\`\${C.teal}18\`:"transparent",color:as==null?C.teal:C.muted,cursor:"pointer"}}>ALL</button>
        {sessions.map(s=><button key={s.index} onClick={()=>setAs(s.index)} style={{fontSize:9,padding:"2px 8px",borderRadius:3,border:\`1px solid \${as===s.index?C.teal:C.border}\`,background:as===s.index?\`\${C.teal}18\`:"transparent",color:as===s.index?C.teal:C.muted,cursor:"pointer"}}>S{s.index} ({s.exchange_count})</button>)}
      </div>
      <PhaseBar tl={filtered} s={as} oc={go}/>
      <div style={{display:"flex",gap:8,marginTop:3,flexWrap:"wrap"}}>
        {phases.slice(0,8).map(p=><span key={p} style={{fontSize:8,color:PC[p],display:"flex",alignItems:"center",gap:3}}><span style={{width:6,height:6,borderRadius:1,background:PC[p],display:"inline-block"}}/>{PS[p]||p}</span>)}
      </div>
    </div>

    {/* Tabs */}
    <div style={{display:"flex",borderBottom:\`1px solid \${C.border}\`,flexShrink:0}}>
      {[["replay","Sequence Replay"],["findings","Findings"],["identity","Identity"]].map(([k,l])=>
        <button key={k} onClick={()=>setTab(k)} style={{flex:1,padding:"6px 0",fontSize:10,fontWeight:600,border:"none",borderBottom:tab===k?\`2px solid \${C.teal}\`:"2px solid transparent",background:"transparent",color:tab===k?C.teal:C.dim,cursor:"pointer",letterSpacing:.5}}>{l}</button>)}
    </div>

    {/* Content */}
    <div style={{flex:1,overflow:"auto"}} tabIndex={0}>
      {tab==="replay"&&<>
        {d._trimmed&&<div style={{padding:"6px 14px",fontSize:10,color:C.amber,background:C.amber+"08",borderBottom:\`1px solid \${C.border}\`}}>Showing {d._trimmed.shown} of {d._trimmed.original} exchanges (notable + session boundaries)</div>}
        <div style={{padding:"4px 14px",fontSize:10,color:C.dim,borderBottom:\`1px solid \${C.border}\`,display:"flex",alignItems:"center",gap:8}}>
          <button onClick={()=>{if(!playing&&sel==null&&filtered.length){setSel(filtered[0].id);}setPlaying(p=>!p);}} style={{background:playing?C.amber+"22":"transparent",border:\`1px solid \${playing?C.amber:C.teal}66\`,borderRadius:4,padding:"2px 10px",fontSize:10,color:playing?C.amber:C.teal,cursor:"pointer",display:"flex",alignItems:"center",gap:4}}>
            {playing?"⏸ Pause":"▶ Play"}
          </button>
          {sel!=null&&<span style={{color:C.muted,fontSize:9}}>{filtered.findIndex(t=>t.id===sel)+1} / {filtered.length}</span>}
          <span style={{marginLeft:"auto",fontSize:9}}>↑↓ or j/k navigate · space play/pause</span>
        </div>
        {filtered.map(t=><div key={t.id} id={\`ex-\${t.id}\`}>
        <ExRow t={t} sel={sel===t.id} onClick={()=>setSel(sel===t.id?null:t.id)}/>
        {sel===t.id&&<ExDetail t={t}/>}
      </div>)}</>}

      {tab==="findings"&&<div style={{padding:14}}>
        {certs&&<div style={{marginBottom:16}}><div style={{fontWeight:600,fontSize:12,marginBottom:6}}>Certificate Slots</div>
          <div style={{display:"flex",flexWrap:"wrap"}}>{(certs.probed||[]).map(tag=><div key={tag} style={{display:"inline-flex",alignItems:"center",gap:4,padding:"3px 8px",borderRadius:3,border:\`1px solid \${(certs.populated||[]).includes(tag)?C.green:C.red}33\`,background:\`\${(certs.populated||[]).includes(tag)?C.green:C.red}08\`,marginRight:4,marginBottom:4}}>
            <span style={{fontSize:10,color:(certs.populated||[]).includes(tag)?C.green:C.red}}>{(certs.populated||[]).includes(tag)?"●":"○"}</span>
            <span style={{fontSize:10}}>{CN[tag]||tag}</span></div>)}</div>
          {certs.all_empty&&<div style={{fontSize:10,color:C.amber,marginTop:4}}>All slots empty — unprovisioned</div>}
        </div>}

        <div style={{fontWeight:600,fontSize:12,marginBottom:6}}>Threats ({threats.length})</div>
        {threats.length===0?<div style={{color:C.green,fontSize:11}}>None</div>:threats.map((t,i)=>{
          const tc=t.severity==="critical"?C.red:t.severity==="warn"?C.amber:C.blue;
          return <div key={i} style={{marginBottom:8,padding:"8px 10px",borderRadius:4,border:\`1px solid \${tc}22\`,background:\`\${tc}08\`}}>
            <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:4}}><Badge color={tc}>{t.severity}</Badge><span style={{fontSize:11,fontWeight:600}}>{t.title}</span></div>
            <div style={{fontSize:10,color:C.muted,lineHeight:1.5}}>{t.detail}</div>
            {t.exchange_ids?.length>0&&<div style={{marginTop:4}}>{t.exchange_ids.map(id=><span key={id} onClick={()=>go(id)} style={{fontSize:9,color:C.teal,cursor:"pointer",marginRight:6,textDecoration:"underline"}}>ex:{id}</span>)}</div>}
          </div>;})}

        <div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:6}}>Key Check</div>
        <div style={{fontSize:11,color:C.muted}}>Tested {d.key_check?.keys_tested} known keys across {d.key_check?.pairs_tested} auth pairs</div>
        {d.key_check?.matches?.length>0?d.key_check.matches.map((m,i)=><div key={i} style={{color:C.red,fontSize:11,fontWeight:600,marginTop:4}}>DEFAULT KEY: {m.name}</div>):<div style={{fontSize:10,color:C.green,marginTop:2}}>No default keys</div>}

        {d.compliance&&<div style={{marginTop:16}}><div style={{fontWeight:600,fontSize:12,marginBottom:6}}>Compliance</div>
          <div style={{display:"flex",gap:2,height:6,borderRadius:3,overflow:"hidden",marginBottom:4}}>
            <div style={{width:\`\${d.compliance.standard_pct}%\`,background:C.teal}}/><div style={{width:\`\${d.compliance.proprietary_pct}%\`,background:C.purple}}/>
          </div>
          <div style={{fontSize:10,color:C.muted}}>{d.compliance.standard_pct}% standard, {d.compliance.proprietary_pct}% proprietary ({(d.compliance.proprietary_ins||[]).join(", ")})</div></div>}

        {d.notable_annotations?.length>0&&<div style={{marginTop:16}}><div style={{fontWeight:600,fontSize:12,marginBottom:6}}>Notable ({d.notable_annotations.length})</div>
          {d.notable_annotations.map((a,i)=><div key={i} onClick={()=>go(a.exchange)} style={{display:"flex",gap:6,fontSize:10,lineHeight:1.6,cursor:"pointer",padding:"2px 0"}}>
            <span style={{color:C.teal,fontFamily:"monospace",minWidth:28,textDecoration:"underline"}}>{a.exchange}</span>
            <Badge color={flagC(a.flag)||C.amber}>{a.flag}</Badge>
            <span style={{color:C.muted}}>{a.note}</span></div>)}</div>}
      </div>}

      {tab==="identity"&&<div style={{padding:14}}>
        <div style={{fontWeight:600,fontSize:12,marginBottom:8}}>Card Identification</div>
        {card?<div style={{fontSize:11,display:"grid",gridTemplateColumns:"90px 1fr",gap:"2px 8px",lineHeight:1.7}}>
          <span style={{color:C.dim}}>Card</span><span>{card.name}</span>
          <span style={{color:C.dim}}>Vendor</span><span>{card.vendor}</span>
          <span style={{color:C.dim}}>Confidence</span><span style={{color:card.confidence>=90?C.green:C.amber}}>{card.confidence}%</span>
        </div>:<div style={{color:C.dim}}>Not identified</div>}
        {card?.signals?.map((s,i)=><div key={i} style={{fontSize:10,color:C.muted,paddingLeft:98,lineHeight:1.5}}>· {s}</div>)}

        {token&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>Token Identity</div>
          <div style={{fontSize:11,display:"grid",gridTemplateColumns:"90px 1fr",gap:"2px 8px",lineHeight:1.7}}>
          {token.serial&&<><span style={{color:C.dim}}>Serial</span><span style={{fontFamily:"monospace"}}>{token.serial}</span></>}
          {token.version&&<><span style={{color:C.dim}}>Firmware</span><span style={{fontFamily:"monospace"}}>{token.version}</span></>}
          <span style={{color:C.dim}}>Vendor</span><span>{token.vendor}</span>
          </div></>}

        {chuid&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>CHUID</div>
          <div style={{fontSize:11,display:"grid",gridTemplateColumns:"90px 1fr",gap:"2px 8px",lineHeight:1.7}}>
          {chuid.guid&&<><span style={{color:C.dim}}>GUID</span><span style={{fontFamily:"monospace",fontSize:10}}>{chuid.guid}</span></>}
          {chuid.fascn&&<><span style={{color:C.dim}}>FASC-N</span><span style={{fontFamily:"monospace",fontSize:9,wordBreak:"break-all"}}>{chuid.fascn}</span></>}
          {chuid.expiration&&<><span style={{color:C.dim}}>Expiration</span><span>{chuid.expiration}</span></>}
          <span style={{color:C.dim}}>Signed</span><span style={{color:chuid.hasSignature?C.green:C.amber}}>{chuid.hasSignature?\`Yes (\${chuid.signatureLength}B)\`:"No"}</span>
          </div></>}

        {d.atr&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>ATR</div>
          <div style={{fontSize:11,display:"grid",gridTemplateColumns:"90px 1fr",gap:"2px 8px",lineHeight:1.7}}>
          <span style={{color:C.dim}}>Hex</span><span style={{fontFamily:"monospace",fontSize:9,wordBreak:"break-all"}}>{d.atr.hex}</span>
          {d.atr.parse?.summary&&<><span style={{color:C.dim}}>Parse</span><span>{d.atr.parse.summary}</span></>}
          </div></>}

        <div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>Trace</div>
        <div style={{fontSize:11,display:"grid",gridTemplateColumns:"90px 1fr",gap:"2px 8px",lineHeight:1.7}}>
          <span style={{color:C.dim}}>Integrity</span><span style={{color:d.integrity?.kind==="complete"?C.green:C.amber}}>{d.integrity?.kind}</span>
          <span style={{color:C.dim}}>Exchanges</span><span>{d.exchange_count}</span>
          <span style={{color:C.dim}}>Sessions</span><span>{d.session_count}</span>
        </div>
      </div>}
    </div>
  </div>;
}`;
}
