#!/usr/bin/env node
/**
 * CardForensics dashboard renderer v2 — sequence replay + visual forensics.
 *
 * Takes analyzer JSON (stdin or file) and writes a self-contained
 * React artifact (.jsx) with interactive trace replay.
 *
 * Usage:
 *   npx vite-node skill/scripts/analyze.js trace.log --verbose | npx vite-node skill/scripts/render.js
 *   npx vite-node skill/scripts/render.js --input analysis.json --output /path/to/dashboard.jsx
 */
import { readFileSync, writeFileSync } from "fs";

const args = process.argv.slice(2);
const inputIdx = args.indexOf("--input");
const outputIdx = args.indexOf("--output");

let json;
if (inputIdx >= 0 && args[inputIdx + 1]) {
  json = readFileSync(args[inputIdx + 1], "utf-8");
} else {
  json = readFileSync("/dev/stdin", "utf-8");
}

const data = JSON.parse(json);

const jsx = generateJSX(data);

if (outputIdx >= 0 && args[outputIdx + 1]) {
  writeFileSync(args[outputIdx + 1], jsx);
  console.error(`Dashboard written to ${args[outputIdx + 1]}`);
} else {
  console.log(jsx);
}

function generateJSX(data) {
  return `import { useState, useRef } from "react";
const DATA = ${JSON.stringify(data)};
const C={bg:"#0a0d12",surface:"#111720",surface2:"#161d28",border:"#1c2536",text:"#c8d0e0",dim:"#4a5570",muted:"#7888a4",teal:"#4ad8c7",green:"#34d399",amber:"#fbbf24",red:"#f87171",blue:"#60a5fa",purple:"#a78bfa",pink:"#f472b6"};
const PC={"pre-select probing":"#6366f1","application selection":C.blue,"GP card enumeration":C.purple,"PIV discovery":C.teal,"vendor object inventory":"#8b5cf6",authentication:C.amber,personalization:C.pink,"post-write verification":C.green,"idle / status read":C.dim};
const PS={"pre-select probing":"PROBE","application selection":"SELECT","GP card enumeration":"GP","PIV discovery":"PIV","vendor object inventory":"VENDOR",authentication:"AUTH",personalization:"WRITE","post-write verification":"VERIFY","idle / status read":"IDLE"};
const Badge=({color:c,children:ch,style:s})=><span style={{fontSize:9,fontWeight:700,color:c,border:\`1px solid \${c}44\`,borderRadius:3,padding:"1px 6px",letterSpacing:.6,whiteSpace:"nowrap",...s}}>{ch}</span>;
const Field=({label:l,value:v,mono:m,color:c,small:sm})=><div style={{display:"flex",gap:8,lineHeight:1.7,fontSize:sm?10:11}}><span style={{color:C.dim,minWidth:sm?70:90,flexShrink:0}}>{l}</span><span style={{color:c||C.text,fontFamily:m?"monospace":"inherit",fontSize:m?10:undefined,wordBreak:"break-all"}}>{v??"—"}</span></div>;
const CN={"5FC105":"PIV Auth (9A)","5FC10A":"Dig Sig (9C)","5FC10B":"Key Mgmt (9D)","5FC101":"Card Auth (9E)"};

function ExRow({t,selected:sel,onClick:oc}){
  const pc=PC[t.phase]||C.dim,fc=t.flag==="bug"?C.red:t.flag==="warn"?C.amber:t.flag==="key"?C.purple:t.flag==="expected"?C.dim:null;
  return <div onClick={oc} style={{display:"flex",alignItems:"center",gap:0,fontSize:11,cursor:"pointer",borderBottom:\`1px solid \${C.border}\`,padding:"3px 0",background:sel?\`\${C.teal}10\`:"transparent",borderLeft:\`3px solid \${pc}\`}}>
    <span style={{width:32,textAlign:"right",color:C.dim,fontSize:9,fontFamily:"monospace",paddingRight:6,flexShrink:0}}>{t.id}</span>
    <span style={{width:46,color:pc,fontSize:8,fontWeight:600,letterSpacing:.4,flexShrink:0}}>{PS[t.phase]||""}</span>
    <span style={{width:72,color:C.muted,fontSize:10,fontFamily:"monospace",flexShrink:0}}>{t.ins}</span>
    <span style={{flex:1,color:fc||C.text,fontSize:10,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",paddingRight:4}}>{t.note||""}</span>
    {t.flag&&t.flag!=="expected"&&<Badge color={fc} style={{marginRight:4}}>{t.flag.toUpperCase()}</Badge>}
    <span style={{width:38,textAlign:"right",fontFamily:"monospace",fontSize:9,color:!t.sw?C.dim:t.ok?C.green:C.red,paddingRight:8,flexShrink:0}}>{t.sw||"—"}</span>
  </div>;
}

function ExDetail({t}){
  return <div style={{padding:"10px 14px",background:C.surface2,borderBottom:\`1px solid \${C.border}\`,fontSize:11}}>
    <div style={{fontWeight:600,color:C.teal,marginBottom:6}}>Exchange {t.id}</div>
    <Field label="Instruction" value={t.ins} small/>
    <Field label="CLA" value={t.cla} mono small/>
    <Field label="Status" value={t.sw?\`\${t.sw} \${t.ok?"(OK)":"(ERROR)"}\`:"no response"} color={t.ok?C.green:C.red} small/>
    <Field label="Phase" value={t.phase} small/>
    <Field label="Session" value={t.session} small/>
    <Field label="Authenticated" value={t.auth?"Yes":"No"} color={t.auth?C.green:C.dim} small/>
    {t.selected&&<Field label="Selected" value={t.selected} small/>}
    <Field label="Cmd size" value={\`\${t.cmdLen}B\`} small/>
    <Field label="Rsp size" value={\`\${t.rspLen}B\${t.dataLen?\` (\${t.dataLen}B data)\`:""}\`} small/>
    {t.continuations>0&&<Field label="61xx chains" value={t.continuations} small/>}
    {t.note&&<div style={{marginTop:6,padding:"6px 8px",background:C.bg,borderRadius:4,color:C.text,lineHeight:1.5}}>
      {t.flag&&<Badge color={t.flag==="bug"?C.red:t.flag==="key"?C.purple:C.amber} style={{marginRight:6}}>{t.flag}</Badge>}
      {t.note}
    </div>}
  </div>;
}

function PhaseBar({timeline:tl,session:s,onClickExchange:oce}){
  const exs=s!=null?tl.filter(t=>t.session===s):tl;
  if(!exs.length)return null;
  return <div style={{display:"flex",height:14,borderRadius:3,overflow:"hidden",margin:"0 0 2px",cursor:"pointer"}}>
    {exs.map((t,i)=><div key={i} onClick={()=>oce(t.id)} title={\`#\${t.id} \${t.ins} \${t.note||""}\`}
      style={{flex:1,minWidth:1,background:t.flag==="bug"?C.red:t.flag==="key"?C.purple:PC[t.phase]||C.dim,opacity:t.ok?.7:1,borderRight:i<exs.length-1?\`1px solid \${C.bg}\`:"none"}}/>)}
  </div>;
}

export default function Dashboard(){
  const d=DATA,card=d.card_identification,token=d.token_identity,chuid=token?.chuid,score=d.security_score,certs=d.cert_provisioning;
  const threats=(d.threats||[]).filter(t=>t.severity!=="pass"),timeline=d.timeline||[],sessions=d.sessions||[];
  const [selectedEx,setSelectedEx]=useState(null),[activeSession,setActiveSession]=useState(null),[tab,setTab]=useState("replay");
  const filtered=activeSession!=null?timeline.filter(t=>t.session===activeSession):timeline;
  const scrollTo=id=>{setSelectedEx(id);setTimeout(()=>{const el=document.getElementById(\`ex-\${id}\`);if(el)el.scrollIntoView({behavior:"smooth",block:"center"});},20);};
  const sc=score?.score>=90?C.green:score?.score>=70?C.amber:C.red;
  const phases=[...new Set(timeline.map(t=>t.phase).filter(Boolean))];

  return <div style={{fontFamily:"'IBM Plex Sans',-apple-system,sans-serif",background:C.bg,color:C.text,height:"100vh",display:"flex",flexDirection:"column",overflow:"hidden"}}>
    {/* Header */}
    <div style={{padding:"12px 14px",borderBottom:\`1px solid \${C.border}\`,display:"flex",alignItems:"center",gap:10,flexShrink:0,background:C.surface}}>
      <div style={{flex:1}}>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <span style={{fontWeight:700,fontSize:13,color:"#fff",letterSpacing:.5}}>CardForensics</span>
          {card&&<Badge color={C.teal}>{card.name}</Badge>}
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:2,display:"flex",gap:12,flexWrap:"wrap"}}>
          {token?.serial&&<span>S/N: <span style={{color:C.muted,fontFamily:"monospace"}}>{token.serial}</span></span>}
          {token?.version&&<span>FW: <span style={{color:C.muted,fontFamily:"monospace"}}>{token.version}</span></span>}
          <span>{d.exchange_count} exchanges</span>
          <span>{d.session_count} sessions</span>
        </div>
      </div>
      {score&&<div style={{textAlign:"right"}}><div style={{fontSize:22,fontWeight:700,color:sc,lineHeight:1}}>{score.score}</div><div style={{fontSize:8,color:C.dim,letterSpacing:1}}>{score.label?.toUpperCase()}</div></div>}
    </div>

    {/* Threats */}
    {threats.length>0&&<div style={{padding:"6px 14px",borderBottom:\`1px solid \${C.border}\`,background:\`\${C.red}08\`,display:"flex",gap:6,flexWrap:"wrap",flexShrink:0}}>
      {threats.map((t,i)=>{const tc=t.severity==="critical"?C.red:t.severity==="warn"?C.amber:C.blue;
        return <div key={i} onClick={()=>t.exchange_ids?.[0]!=null&&scrollTo(t.exchange_ids[0])} style={{fontSize:10,padding:"3px 8px",borderRadius:3,border:\`1px solid \${tc}44\`,background:\`\${tc}10\`,cursor:t.exchange_ids?.length?"pointer":"default"}}>
          <Badge color={tc} style={{marginRight:4}}>{t.severity}</Badge><span style={{color:C.text}}>{t.title}</span>
        </div>;})}
    </div>}

    {/* Sessions + phase bar */}
    <div style={{padding:"6px 14px 4px",borderBottom:\`1px solid \${C.border}\`,flexShrink:0,background:C.surface}}>
      <div style={{display:"flex",gap:4,marginBottom:4}}>
        <button onClick={()=>setActiveSession(null)} style={{fontSize:9,padding:"2px 8px",borderRadius:3,border:\`1px solid \${activeSession==null?C.teal:C.border}\`,background:activeSession==null?\`\${C.teal}18\`:"transparent",color:activeSession==null?C.teal:C.muted,cursor:"pointer"}}>ALL</button>
        {sessions.map(s=><button key={s.index} onClick={()=>setActiveSession(s.index)} style={{fontSize:9,padding:"2px 8px",borderRadius:3,border:\`1px solid \${activeSession===s.index?C.teal:C.border}\`,background:activeSession===s.index?\`\${C.teal}18\`:"transparent",color:activeSession===s.index?C.teal:C.muted,cursor:"pointer"}}>S{s.index} ({s.exchange_count})</button>)}
      </div>
      <PhaseBar timeline={filtered} session={activeSession} onClickExchange={scrollTo}/>
      <div style={{display:"flex",gap:8,marginTop:3,flexWrap:"wrap"}}>
        {phases.slice(0,8).map(p=><span key={p} style={{fontSize:8,color:PC[p],display:"flex",alignItems:"center",gap:3}}><span style={{width:6,height:6,borderRadius:1,background:PC[p],display:"inline-block"}}/>
          {PS[p]||p}</span>)}
      </div>
    </div>

    {/* Tabs */}
    <div style={{display:"flex",borderBottom:\`1px solid \${C.border}\`,flexShrink:0}}>
      {[["replay","Sequence Replay"],["findings","Findings"],["identity","Identity"]].map(([k,l])=>
        <button key={k} onClick={()=>setTab(k)} style={{flex:1,padding:"6px 0",fontSize:10,fontWeight:600,border:"none",borderBottom:tab===k?\`2px solid \${C.teal}\`:"2px solid transparent",background:"transparent",color:tab===k?C.teal:C.dim,cursor:"pointer",letterSpacing:.5}}>{l}</button>)}
    </div>

    {/* Content */}
    <div style={{flex:1,overflow:"auto"}}>
      {tab==="replay"&&<>{filtered.map(t=><div key={t.id} id={\`ex-\${t.id}\`}>
        <ExRow t={t} selected={selectedEx===t.id} onClick={()=>setSelectedEx(selectedEx===t.id?null:t.id)}/>
        {selectedEx===t.id&&<ExDetail t={t}/>}
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
            {t.exchange_ids?.length>0&&<div style={{marginTop:4}}>{t.exchange_ids.map(id=><span key={id} onClick={()=>{setTab("replay");setTimeout(()=>scrollTo(id),50);}} style={{fontSize:9,color:C.teal,cursor:"pointer",marginRight:6,textDecoration:"underline"}}>ex:{id}</span>)}</div>}
          </div>;})}

        <div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:6}}>Key Check</div>
        <Field label="Tested" value={d.key_check?.keys_tested} small/>
        {d.key_check?.matches?.length>0?d.key_check.matches.map((m,i)=><div key={i} style={{color:C.red,fontSize:11,fontWeight:600}}>DEFAULT KEY: {m.name}</div>):<div style={{fontSize:10,color:C.green}}>No default keys</div>}

        {d.compliance&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:6}}>Compliance</div>
          <div style={{display:"flex",gap:2,height:6,borderRadius:3,overflow:"hidden",marginBottom:4}}>
            <div style={{width:\`\${d.compliance.standard_pct}%\`,background:C.teal}}/><div style={{width:\`\${d.compliance.proprietary_pct}%\`,background:C.purple}}/>
          </div>
          <div style={{fontSize:10,color:C.muted}}>{d.compliance.standard_pct}% standard, {d.compliance.proprietary_pct}% proprietary</div></>}

        {d.notable_annotations?.length>0&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:6}}>Notable ({d.notable_annotations.length})</div>
          {d.notable_annotations.map((a,i)=><div key={i} onClick={()=>{setTab("replay");setTimeout(()=>scrollTo(a.exchange),50);}} style={{display:"flex",gap:6,fontSize:10,lineHeight:1.6,cursor:"pointer",padding:"2px 0"}}>
            <span style={{color:C.teal,fontFamily:"monospace",minWidth:28,textDecoration:"underline"}}>{a.exchange}</span>
            <Badge color={a.flag==="bug"?C.red:a.flag==="key"?C.purple:C.amber}>{a.flag}</Badge>
            <span style={{color:C.muted}}>{a.note}</span>
          </div>)}</>}
      </div>}

      {tab==="identity"&&<div style={{padding:14}}>
        <div style={{fontWeight:600,fontSize:12,marginBottom:8}}>Card Identification</div>
        {card?<><Field label="Card" value={card.name}/><Field label="Vendor" value={card.vendor}/>
          <Field label="Confidence" value={\`\${card.confidence}%\`} color={card.confidence>=90?C.green:C.amber}/>
          {card.signals?.map((s,i)=><div key={i} style={{fontSize:10,color:C.muted,paddingLeft:98,lineHeight:1.5}}>· {s}</div>)}
        </>:<div style={{color:C.dim}}>Not identified</div>}

        {token&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>Token</div>
          {token.serial&&<Field label="Serial" value={token.serial} mono/>}
          {token.version&&<Field label="Firmware" value={token.version} mono/>}</>}

        {chuid&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>CHUID</div>
          {chuid.guid&&<Field label="GUID" value={chuid.guid} mono/>}
          {chuid.fascn&&<Field label="FASC-N" value={chuid.fascn} mono/>}
          {chuid.expiration&&<Field label="Expiration" value={chuid.expiration}/>}
          <Field label="Signed" value={chuid.hasSignature?\`Yes (\${chuid.signatureLength}B)\`:"No"} color={chuid.hasSignature?C.green:C.amber}/></>}

        {d.atr&&<><div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>ATR</div>
          <Field label="Hex" value={d.atr.hex} mono/>{d.atr.parse?.summary&&<Field label="Parse" value={d.atr.parse.summary}/>}</>}

        <div style={{fontWeight:600,fontSize:12,marginTop:16,marginBottom:8}}>Trace</div>
        <Field label="Integrity" value={d.integrity?.kind} color={d.integrity?.kind==="complete"?C.green:C.amber}/>
        <Field label="Exchanges" value={d.exchange_count}/><Field label="Sessions" value={d.session_count}/>
      </div>}
    </div>
  </div>;
}`;
}
