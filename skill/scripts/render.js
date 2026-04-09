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
const C={bg:"#0a0d12",surface:"#111720",s2:"#161d28",border:"#1c2536",text:"#dce4f0",dim:"#6b7a94",muted:"#98a8c0",teal:"#4ad8c7",green:"#34d399",amber:"#fbbf24",red:"#f87171",blue:"#60a5fa",purple:"#a78bfa",pink:"#f472b6",white:"#f0f4fa"};
const PC={"pre-select probing":"#6366f1","application selection":C.blue,"GP card enumeration":C.purple,"PIV discovery":C.teal,"vendor object inventory":"#8b5cf6",authentication:C.amber,personalization:C.pink,"post-write verification":C.green,"idle / status read":C.dim};
const PS={"pre-select probing":"PROBE","application selection":"SELECT","GP card enumeration":"GP","PIV discovery":"PIV","vendor object inventory":"VENDOR",authentication:"AUTH",personalization:"WRITE","post-write verification":"VERIFY","idle / status read":"IDLE"};
const CN={"5FC105":"PIV Auth (9A)","5FC10A":"Dig Sig (9C)","5FC10B":"Key Mgmt (9D)","5FC101":"Card Auth (9E)"};
const flagC=f=>f==="bug"?C.red:f==="key"?C.green:f==="warn"?C.amber:f==="expected"?C.dim:null;
const flagBg=f=>f==="bug"?"#1a080811":f==="key"?"#082a1811":f==="warn"?"#1a160811":f==="expected"?"#11111411":"transparent";
const Badge=({color:c,children:ch})=><span style={{fontSize:9,fontWeight:700,color:c,border:\`1px solid \${c}44\`,borderRadius:3,padding:"1px 6px",letterSpacing:.5,whiteSpace:"nowrap"}}>{ch}</span>;
const swC=s=>s==="ok"?C.green:s==="err"?C.red:s==="warn"?C.amber:C.muted;
const SPECS={"iso7816_4":{s:"ISO 7816-4",u:"https://www.iso.org/standard/77180.html"},"nist_73":{s:"SP 800-73-4",u:"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf"},"gp_scp03":{s:"GP SCP03",u:"https://globalplatform.org/specs-library/secure-channel-protocol-03-amendment-d-v1-1-2/"},"gp_card":{s:"GP Card 2.3",u:"https://globalplatform.org/specs-library/card-specification-v2-3-1/"},"emv":{s:"EMV",u:"https://www.emvco.com/emv-technologies/contact/"}};
const INS_SPECS={0xA4:[{k:"nist_73",r:"§3.1"},{k:"iso7816_4",r:"§10.1"}],0xCB:[{k:"nist_73",r:"§3.5"}],0xCA:[{k:"nist_73",r:"§3.5"}],0xDB:[{k:"nist_73",r:"§3.6"}],0x87:[{k:"nist_73",r:"§3.7"},{k:"gp_scp03",r:"§3"}],0x20:[{k:"nist_73",r:"§3.2"},{k:"iso7816_4",r:"§10.7"}],0x2C:[{k:"iso7816_4",r:"§10.9"}],0x82:[{k:"gp_scp03",r:"§4"}],0x84:[{k:"gp_scp03",r:"§3"}],0xFD:[{k:"nist_73",r:"Vendor"}],0xFB:[{k:"nist_73",r:"Vendor"}]};
const insToNum={"SELECT":0xA4,"GET DATA":0xCB,"PUT DATA":0xDB,"GEN AUTH":0x87,"VERIFY":0x20,"CHG REF DATA":0x2C,"EXT AUTH":0x82,"GET CHALLENGE":0x84,"INS_FD":0xFD,"PIV RESET":0xFB};
function specRefs(ins){const n=insToNum[ins];return n?INS_SPECS[n]||[]:[];}

function ExRow({t,sel,onClick}){
  const pc=PC[t.phase]||C.dim;
  return <div onClick={onClick} style={{borderBottom:\`1px solid \${C.border}\`,background:sel?\`\${C.teal}0c\`:"transparent",cursor:"pointer"}}>
    {/* CMD line */}
    <div style={{display:"flex",alignItems:"center",gap:6,padding:"5px 10px",fontFamily:"monospace",fontSize:12}}>
      <span style={{color:C.dim,fontSize:11,width:30,textAlign:"right",flexShrink:0}}>{t.id}</span>
      <span style={{color:C.muted,width:36,fontSize:10,flexShrink:0}}>{t.dt!=null?<span>{t.dt}ms</span>:null}</span>
      {t.auth&&<span style={{fontSize:10,color:C.green,flexShrink:0}}>🔒</span>}
      <span style={{fontSize:9,color:pc,border:\`1px solid \${pc}44\`,borderRadius:2,padding:"1px 4px",flexShrink:0,fontWeight:600}}>{PS[t.phase]||""}</span>
      <span style={{color:C.blue,fontSize:11,flexShrink:0}}>▶ CMD</span>
      <span style={{fontSize:9,padding:"1px 5px",borderRadius:2,background:C.purple+"22",color:C.purple,border:\`1px solid \${C.purple}44\`,flexShrink:0}}>{t.claDesc||t.cla}</span>
      <span style={{color:C.white,fontWeight:700,flexShrink:0}}>{t.ins}</span>
      <span style={{color:C.muted,flexShrink:0}}>P1={t.p1} P2={t.p2}</span>
      {t.lc!=null&&<span style={{color:C.dim,flexShrink:0}}>Lc={t.lc}</span>}
      <span style={{color:C.dim,fontSize:11,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",flex:1}}>{t.cmdHex?.substring(0,60)}</span>
    </div>
    {/* RSP line */}
    {t.sw&&<div style={{display:"flex",alignItems:"center",gap:6,padding:"2px 10px 4px",fontFamily:"monospace",fontSize:12}}>
      <span style={{width:30,flexShrink:0}}/>
      <span style={{width:36,flexShrink:0}}/>
      <span style={{color:C.green,fontSize:11,flexShrink:0}}>◀ RSP</span>
      <span style={{color:swC(t.swSev),fontWeight:700,flexShrink:0}}>{t.sw}</span>
      <span style={{color:swC(t.swSev),fontSize:11,flexShrink:0}}>{t.swMsg}</span>
      {t.dataLen>0&&<span style={{color:C.muted,fontSize:11,flexShrink:0}}>{t.dataLen}B</span>}
      {t.continuations>0&&<span style={{fontSize:9,color:C.teal,border:\`1px solid \${C.teal}44\`,borderRadius:3,padding:"1px 5px"}}>⛓ {t.continuations+1} chunks</span>}
    </div>}
    {/* Annotation */}
    {t.note&&<div style={{padding:"4px 10px 4px 80px",borderLeft:\`3px solid \${flagC(t.flag)||C.muted}\`,background:flagBg(t.flag),color:flagC(t.flag)||C.text,fontSize:11,lineHeight:1.5}}>✦ {t.note}</div>}
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

    {/* Spec references */}
    {specRefs(t.ins).length>0&&<div style={{padding:"4px 12px",borderBottom:\`1px solid \${C.border}\`,display:"flex",gap:4,flexWrap:"wrap",alignItems:"center"}}>
      <span style={{fontSize:9,color:C.dim,marginRight:4}}>SPEC</span>
      {specRefs(t.ins).map((s,i)=>{const sp=SPECS[s.k];return sp?<a key={i} href={sp.u} target="_blank" rel="noopener" style={{fontSize:9,padding:"1px 6px",borderRadius:3,background:C.blue+"14",border:\`1px solid \${C.blue}33\`,color:C.blue,textDecoration:"none",fontFamily:"monospace"}}>{sp.s} {s.r}</a>:null;})}
    </div>}

    {/* Two-column: Fields + AI Analysis */}
    <div style={{display:"flex",borderBottom:\`1px solid \${C.border}\`}}>
      {/* Left: decoded fields */}
      <div style={{flex:"0 0 auto",padding:"10px 14px",fontSize:12,display:"grid",gridTemplateColumns:"90px 1fr",gap:"3px 10px",lineHeight:1.7,borderRight:t.explanation?\`1px solid \${C.border}\`:"none"}}>
        <span style={{color:C.dim}}>Instruction</span><span style={{color:C.text}}>{t.ins}</span>
        <span style={{color:C.dim}}>CLA</span><span style={{fontFamily:"monospace",color:C.text}}>{t.cla} ({t.claDesc})</span>
        <span style={{color:C.dim}}>P1 / P2</span><span style={{fontFamily:"monospace",color:C.text}}>{t.p1} / {t.p2}</span>
        {t.lc!=null&&<><span style={{color:C.dim}}>Lc</span><span style={{color:C.text}}>{t.lc}</span></>}
        <span style={{color:C.dim}}>Phase</span><span style={{color:PC[t.phase]||C.muted}}>{t.phase}</span>
        <span style={{color:C.dim}}>Session</span><span style={{color:C.text}}>{t.session}</span>
        <span style={{color:C.dim}}>Auth</span><span style={{color:t.auth?C.green:C.dim}}>{t.auth?"Authenticated":"No"}</span>
        {t.selected&&<><span style={{color:C.dim}}>Selected</span><span style={{color:C.text}}>{t.selected}</span></>}
        <span style={{color:C.dim}}>Cmd size</span><span style={{color:C.text}}>{t.cmdLen}B</span>
        <span style={{color:C.dim}}>Rsp size</span><span style={{color:C.text}}>{t.rspLen}B{t.dataLen?\` (\${t.dataLen}B data)\`:""}</span>
        {t.continuations>0&&<><span style={{color:C.dim}}>Chaining</span><span style={{color:C.text}}>{t.continuations} GET RESPONSE continuations</span></>}
      </div>
      {/* Right: AI explanation (pre-computed by Claude during skill run) */}
      {t.explanation&&<div style={{flex:1,padding:"10px 14px",background:"#0d1117",minHeight:80}}>
        <div style={{fontSize:10,fontWeight:700,color:C.purple,letterSpacing:.5,marginBottom:8}}>AI ANALYSIS</div>
        <div style={{fontSize:12,color:"#c4ccdd",lineHeight:1.7}}>{t.explanation}</div>
      </div>}
    </div>

    {/* PV Certificate Viewer */}
    {t.cert&&t.cert.b64&&typeof PV_B64!=="undefined"&&<PVMount b64={t.cert.b64} slot={CN[t.cert.slot]||t.cert.slot} startOpen/>}
    {t.cert&&(!t.cert.b64||typeof PV_B64==="undefined")&&<div style={{padding:"8px 12px",borderTop:\`1px solid \${C.border}\`,fontSize:10,color:C.muted}}>Certificate data not available for PV viewer</div>}

    {/* Decoded structured data */}
    <DecodedFields t={t}/>

    {/* Annotated Hex */}
    <div style={{borderTop:\`1px solid \${C.border}\`}}>
      <div onClick={()=>setHexOpen(!hexOpen)} style={{padding:"5px 12px",fontSize:11,color:C.muted,cursor:"pointer"}}>{hexOpen?"▼":"▶"} Annotated Hex</div>
      {hexOpen&&<div style={{padding:"4px 12px 8px"}}>
        <div style={{color:C.blue,marginBottom:2,fontSize:10,fontWeight:600}}>CMD ({t.cmdLen}B)</div>
        <HexView hex={t.cmdHex} label="cmd"/>
        {t.rspHex&&<><div style={{color:C.green,marginBottom:2,marginTop:8,fontSize:10,fontWeight:600}}>RSP ({t.rspLen}B)</div>
        <HexView hex={t.rspHex} label="rsp"/></>}
      </div>}
    </div>
  </div>;
}

const hexToBytes=h=>h?h.split(" ").map(b=>parseInt(b,16)).filter(b=>!isNaN(b)):[];
const bytesToAscii=b=>b.filter(x=>x>=0x20&&x<=0x7E&&x!==0xFF).map(x=>String.fromCharCode(x)).join("");
const bytesToHex=b=>b.map(x=>x.toString(16).padStart(2,"0").toUpperCase()).join("");
const formatUUID=b=>b.length>=16?[bytesToHex(b.slice(0,4)),bytesToHex(b.slice(4,6)),bytesToHex(b.slice(6,8)),bytesToHex(b.slice(8,10)),bytesToHex(b.slice(10,16))].join("-"):bytesToHex(b);
function DecodedFields({t}){
  const cmd=hexToBytes(t.cmdHex),rsp=hexToBytes(t.rspHex);
  const fields=[];
  const ins=parseInt(t.cla,16)===0?parseInt(cmd[1]?.toString(16)||"0",16):null;
  // CHUID decode (GET DATA for 5FC102)
  if(t.note?.includes("CHUID")&&t.ok&&rsp.length>10){
    let d=rsp;if(d[0]===0x53){const l=d[1]===0x82?(d[2]<<8|d[3]):d[1];d=d.slice(d[1]===0x82?4:2);}
    let i=0;while(i<d.length-1){let tag=d[i++];if(i>=d.length)break;let len=d[i++];if(len===0x81)len=d[i++];else if(len===0x82){len=(d[i]<<8)|d[i+1];i+=2;}
      if(tag===0x30&&len===25)fields.push({l:"FASC-N",v:len+"B encoded"});
      if(tag===0x34&&len===16)fields.push({l:"GUID",v:formatUUID(d.slice(i,i+len))});
      if(tag===0x35&&len===8)fields.push({l:"Expiration",v:bytesToAscii(d.slice(i,i+len))});
      if(tag===0x36&&len===16)fields.push({l:"Cardholder UUID",v:formatUUID(d.slice(i,i+len))});
      if(tag===0x3E)fields.push({l:"Issuer Signature",v:len+"B"});
      if(tag===0xFE)fields.push({l:"Error Detection",v:len+"B"});
      i+=len;
    }
  }
  // Credential decode (CHANGE REF DATA)
  if(t.ins==="CHG REF DATA"&&cmd.length>=21){
    const data=cmd.slice(5);
    if(data.length>=16){
      const puk=data.slice(0,8).filter(b=>b!==0xFF);
      const pin=data.slice(8,16).filter(b=>b!==0xFF);
      fields.push({l:"PUK",v:puk.length?bytesToAscii(puk)+" ("+puk.length+" digits)":"(empty)",warn:true});
      fields.push({l:"PIN",v:pin.length?bytesToAscii(pin)+" ("+pin.length+" digits)":"(empty)",warn:true});
    }
  }
  // YubiKey version (INS FD)
  if(t.note?.includes("version")&&t.ok&&rsp.length>=5){
    const d=rsp.slice(0,-2);
    if(d.length===3)fields.push({l:"Firmware",v:d.join(".")});
    else if(d.length>=5&&d[0]===0xDF&&d[1]===0x30){const vb=d.slice(3);fields.push({l:"Version",v:bytesToAscii(vb)});}
  }
  // Discovery Object (7E)
  if(t.note?.includes("Discovery")&&t.ok&&rsp.length>4){
    const d=rsp;let i=0;if(d[0]===0x7E){i=2;}
    while(i<d.length-3){
      if(d[i]===0x4F){const len=d[i+1];fields.push({l:"PIV AID",v:d.slice(i+2,i+2+len).map(b=>b.toString(16).padStart(2,"0")).join(" ")});i+=2+len;}
      else if(d[i]===0x5F&&d[i+1]===0x2F){const len=d[i+2];const pp=d[i+3];fields.push({l:"PIN Policy",v:"0x"+pp.toString(16).padStart(2,"0")+(pp&0x40?" (global PIN)":"")+(pp&0x20?" (app PIN)":"")});i+=3+len;}
      else i++;
    }
  }
  // GP CPLC (9F7F)
  if(t.note?.includes("CPLC")&&t.ok&&rsp.length>20){
    fields.push({l:"CPLC",v:"Card Production Life Cycle data ("+rsp.length+"B)"});
  }
  // Hardware serial
  if(t.note?.includes("hardware serial")&&t.ok){
    const d=rsp.slice(0,-2);const start=d.findIndex((b,i)=>i>2&&b>=0x30&&b<=0x7A);
    if(start>=0)fields.push({l:"Serial",v:bytesToAscii(d.slice(start))});
  }
  if(!fields.length)return null;
  return <div style={{borderTop:\`1px solid \${C.border}\`,padding:"8px 12px",background:"#0e1218"}}>
    <div style={{fontSize:10,fontWeight:600,color:C.teal,marginBottom:4}}>Decoded</div>
    <div style={{display:"grid",gridTemplateColumns:"110px 1fr",gap:"2px 8px",fontSize:11,lineHeight:1.7}}>
      {fields.map((f,i)=><>{f.l&&<span key={"l"+i} style={{color:C.dim}}>{f.l}</span>}<span key={"v"+i} style={{color:f.warn?C.red:C.text,fontFamily:"monospace",fontSize:10,wordBreak:"break-all"}}>{f.v}</span></>)}
    </div>
  </div>;
}

const TLV_NAMES={0x30:"FASC-N",0x32:"Org ID",0x33:"DUNS",0x34:"GUID",0x35:"Expiration",0x36:"Cardholder UUID",0x3E:"Issuer Sig",0x4F:"AID",0x50:"Label",0x53:"PIV Data",0x5C:"Tag List",0x5F2F:"PIN Usage",0x5FC102:"CHUID",0x5FC105:"PIV Auth Cert",0x5FC10A:"Dig Sig Cert",0x5FC10B:"Key Mgmt Cert",0x5FC101:"Card Auth Cert",0x61:"App Template",0x6F:"FCI",0x70:"Cert Data",0x71:"Cert Info",0x73:"Discretionary",0x79:"Alloc Auth",0x7E:"Discovery",0x7F49:"Public Key",0x80:"Key Ref/Length",0x81:"Challenge/Witness",0x82:"Response",0x83:"Key ID",0x84:"DF Name",0x86:"PIN",0x87:"Auth Template",0x8A:"LC State",0x91:"Key Version",0x99:"Capability",0x9A:"Slot",0x9B:"Slot",0x9C:"Slot",0x9D:"Slot",0x9E:"Slot",0x9F65:"Max Length",0x9F6E:"App Prod ID",0xA0:"Key Set",0xA1:"Key Component",0xA5:"Proprietary",0xDF30:"Version",0xE2:"Container",0xEE:"Buffer Length",0xFE:"Error Detection"};
function parseTLVSegments(bytes){
  const segs=[];let i=0;
  while(i<bytes.length){
    const tagStart=i;
    let tag=bytes[i++];
    if((tag&0x1F)===0x1F){if(i<bytes.length)tag=(tag<<8)|bytes[i++];if(i<bytes.length&&(bytes[i-1]&0x80))tag=(tag<<8)|bytes[i++];}
    if(i>=bytes.length){segs.push({start:tagStart,end:bytes.length,type:"raw"});break;}
    const lenStart=i;
    let len=bytes[i++];
    if(len===0x81){if(i<bytes.length)len=bytes[i++];}
    else if(len===0x82){if(i+1<bytes.length){len=(bytes[i]<<8)|bytes[i+1];i+=2;}}
    else if(len>0x82){segs.push({start:tagStart,end:bytes.length,type:"raw"});break;}
    segs.push({start:tagStart,end:lenStart,type:"tag",tag,name:TLV_NAMES[tag]||null});
    segs.push({start:lenStart,end:i,type:"len",len});
    const valEnd=Math.min(i+len,bytes.length);
    if(valEnd>i)segs.push({start:i,end:valEnd,type:"val",tag});
    i=valEnd;
  }
  return segs;
}
function HexView({hex}){
  if(!hex)return null;
  const bytes=hex.split(" ").map(b=>parseInt(b,16)).filter(b=>!isNaN(b));
  const segs=parseTLVSegments(bytes);
  const[hover,setHover]=useState(null);
  const segColors={tag:C.teal,len:C.purple,val:C.text,raw:C.dim};
  return <div style={{background:C.bg,padding:"6px 8px",borderRadius:3,fontFamily:"monospace",fontSize:11,lineHeight:2,wordBreak:"break-all",position:"relative"}}>
    {segs.map((s,si)=>{
      const byteStr=bytes.slice(s.start,s.end).map(b=>b.toString(16).padStart(2,"0")).join(" ");
      return <span key={si} onMouseEnter={()=>setHover(s)} onMouseLeave={()=>setHover(null)} style={{color:segColors[s.type]||C.dim,cursor:"default",background:hover===s?(segColors[s.type]||C.dim)+"22":"transparent",borderRadius:2,padding:"0 1px"}}>{byteStr} </span>;
    })}
    {hover&&hover.name&&<div style={{position:"absolute",top:0,right:0,background:C.surface,border:\`1px solid \${C.border}\`,borderRadius:3,padding:"3px 8px",fontSize:10,color:C.text,pointerEvents:"none",zIndex:10}}>
      <span style={{color:C.teal,fontWeight:600}}>{hover.tag?.toString(16).toUpperCase()}</span> {hover.name}{hover.len!=null?\` (\${hover.len}B)\`:""}
    </div>}
  </div>;
}

let pvLoaded=false;
function loadPV(){
  if(pvLoaded||typeof PV_B64==="undefined")return false;
  try{
    const code=atob(PV_B64);
    new Function(code)();
    pvLoaded=true;
    return true;
  }catch(e){console.warn("PV load failed:",e);return false;}
}
function PVMount({b64,slot,startOpen}){
  const ref=useRef(null);
  const[open,setOpen]=useState(!!startOpen);
  const mounted=useRef(false);
  useEffect(()=>{
    if(!open||mounted.current||!ref.current||!b64)return;
    if(!pvLoaded)loadPV();
    if(!pvLoaded)return;
    const el=ref.current;
    el.innerHTML="";
    const viewer=document.createElement("peculiar-certificate-viewer");
    if(typeof PV_VARS!=="undefined")PV_VARS.forEach(([k,v])=>viewer.style.setProperty(k,v));
    viewer.certificate=b64;
    el.appendChild(viewer);
    mounted.current=true;
  },[open,b64]);
  return <div style={{borderTop:\`1px solid \${C.border}\`}}>
    <div onClick={()=>setOpen(!open)} style={{padding:"6px 10px",background:"#0b0f16",display:"flex",alignItems:"center",gap:8,cursor:"pointer",borderBottom:open?\`1px solid \${C.border}\`:"none"}}>
      <span style={{color:"#8899bb",fontSize:11}}>{open?"▼":"▶"}</span>
      <span style={{color:C.teal,fontWeight:700,fontSize:12}}>X.509 Certificate</span>
      <span style={{fontSize:10,padding:"1px 6px",borderRadius:3,background:C.teal+"18",color:C.teal,border:\`1px solid \${C.teal}44\`}}>{slot}</span>
    </div>
    {open&&<div ref={ref} style={{overflow:"auto",maxHeight:500,background:"#0b0f16"}}/>}
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
  const allThreats=d.threats||[],threats=allThreats.filter(t=>t.severity!=="pass"),tl=d.timeline||[],sessions=d.sessions||[];
  const[sel,setSel]=useState(null),[as,setAs]=useState(null),[tab,setTab]=useState("replay");
  const[playing,setPlaying]=useState(false);
  const[collapsed,setCollapsed]=useState({});
  const[search,setSearch]=useState(""),[errOnly,setErrOnly]=useState(false),[hideGet,setHideGet]=useState(false);
  const[sevFilter,setSevFilter]=useState(null);
  const playRef=useRef(null);
  const filtered=(()=>{
    let f=as!=null?tl.filter(t=>t.session===as):tl;
    if(errOnly)f=f.filter(t=>t.swSev==="err"||t.flag);
    if(hideGet)f=f.filter(t=>t.ins!=="GET DATA");
    if(search){const q=search.toLowerCase();f=f.filter(t=>(t.ins||"").toLowerCase().includes(q)||(t.note||"").toLowerCase().includes(q)||(t.sw||"").includes(q)||(t.cmdHex||"").toLowerCase().includes(q));}
    return f;
  })();
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
      {score&&(()=>{
        const grade=score.score>=90?"A":score.score>=80?"B":score.score>=70?"C":score.score>=60?"D":"F";
        const tip=(score.breakdown||[]).filter(b=>b.points>0).map(b=>"-"+b.points+" "+b.reason).join("\\n");
        return <div style={{textAlign:"right",cursor:"default"}} title={tip||"No deductions"}>
          <div style={{fontSize:32,fontWeight:800,color:sc,lineHeight:1,letterSpacing:2}}>{grade}</div>
          <div style={{fontSize:9,color:C.muted,letterSpacing:1,marginTop:2}}>{score.score}/100</div>
        </div>;
      })()}
    </div>

    {/* AI Summary */}
    {d.summary&&<div style={{padding:"10px 14px",borderBottom:\`1px solid \${C.border}\`,background:"#0d1117",flexShrink:0}}>
      <div style={{fontSize:10,fontWeight:700,color:C.purple,letterSpacing:.5,marginBottom:6}}>AI SUMMARY</div>
      <div style={{fontSize:12,color:"#c4ccdd",lineHeight:1.7}}>{d.summary}</div>
    </div>}

    {/* Threats */}
    {threats.length>0&&<div style={{padding:"8px 14px",borderBottom:\`1px solid \${C.border}\`,background:C.red+"06",display:"flex",gap:6,flexWrap:"wrap",flexShrink:0}}>
      {threats.map((t,i)=>{const tc=t.severity==="critical"?C.red:t.severity==="warn"?C.amber:C.blue;
        return <div key={i} onClick={()=>t.exchange_ids?.[0]!=null&&go(t.exchange_ids[0])} style={{fontSize:11,padding:"4px 10px",borderRadius:3,border:\`1px solid \${tc}44\`,background:\`\${tc}10\`,cursor:t.exchange_ids?.length?"pointer":"default"}}>
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
        {d._trimmed&&<div style={{padding:"6px 14px",fontSize:11,color:C.amber,background:C.amber+"08",borderBottom:\`1px solid \${C.border}\`}}>Showing {d._trimmed.shown} of {d._trimmed.original} exchanges (notable + session boundaries)</div>}
        <div style={{position:"sticky",top:0,zIndex:10,background:C.bg}}>
        <div style={{padding:"4px 14px",fontSize:11,color:C.dim,borderBottom:\`1px solid \${C.border}\`,display:"flex",alignItems:"center",gap:8}}>
          <button onClick={()=>{if(!playing&&sel==null&&filtered.length){setSel(filtered[0].id);}setPlaying(p=>!p);}} style={{background:playing?C.amber+"22":"transparent",border:\`1px solid \${playing?C.amber:C.teal}66\`,borderRadius:4,padding:"3px 12px",fontSize:11,color:playing?C.amber:C.teal,cursor:"pointer",display:"flex",alignItems:"center",gap:4}}>
            {playing?"⏸ Pause":"▶ Play"}
          </button>
          {sel!=null&&<span style={{color:C.muted,fontSize:10}}>{filtered.findIndex(t=>t.id===sel)+1} / {filtered.length}</span>}
          <span style={{marginLeft:"auto",fontSize:10}}>↑↓ j/k · space play</span>
        </div>
        <div style={{padding:"4px 14px",borderBottom:\`1px solid \${C.border}\`,display:"flex",alignItems:"center",gap:6,background:C.surface}}>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search INS, annotation, hex..." style={{flex:1,background:C.bg,border:\`1px solid \${C.border}\`,borderRadius:3,padding:"4px 8px",fontSize:11,color:C.text,outline:"none",fontFamily:"monospace",maxWidth:260}}/>
          <button onClick={()=>setErrOnly(!errOnly)} style={{fontSize:10,padding:"3px 8px",borderRadius:3,border:\`1px solid \${errOnly?C.red:C.border}\`,background:errOnly?C.red+"18":"transparent",color:errOnly?C.red:C.muted,cursor:"pointer"}}>Errors</button>
          <button onClick={()=>setHideGet(!hideGet)} style={{fontSize:10,padding:"3px 8px",borderRadius:3,border:\`1px solid \${hideGet?C.amber:C.border}\`,background:hideGet?C.amber+"18":"transparent",color:hideGet?C.amber:C.muted,cursor:"pointer"}}>Hide GET</button>
          <span style={{fontSize:10,color:C.dim}}>{filtered.length}/{tl.length}</span>
        </div>
        </div>
        {(()=>{
          const SC=["#6366f1","#f59e0b","#10b981","#ec4899","#3b82f6"];
          let lastSession=-1;
          return filtered.map(t=>{
            const showHeader=t.session!==lastSession;
            lastSession=t.session;
            const si=t.session;
            const sm=sessions[si];
            const sc=SC[si%SC.length];
            const isCollapsed=collapsed[si];
            const sessionExchanges=filtered.filter(x=>x.session===si);
            const errCount=sessionExchanges.filter(x=>x.swSev==="err"||x.flag==="bug").length;
            return <div key={t.id}>
              {showHeader&&<div onClick={()=>setCollapsed(p=>({...p,[si]:!p[si]}))} style={{position:"sticky",top:0,zIndex:9,background:"#131a28",borderBottom:\`1px solid \${C.border}\`,borderTop:\`1px solid \${C.border}\`,cursor:"pointer",userSelect:"none"}}>
                <div style={{display:"flex",alignItems:"center",gap:10,padding:"8px 12px"}}>
                  <div style={{width:3,alignSelf:"stretch",background:sc,borderRadius:"2px 0 0 2px",flexShrink:0,minHeight:20}}/>
                  <span style={{color:"#8899bb",fontSize:12}}>{isCollapsed?"▶":"▼"}</span>
                  <span style={{color:sc,fontWeight:700,fontSize:13,fontFamily:"monospace"}}>SESSION {si}</span>
                  {sm&&<span style={{color:C.muted,fontSize:11}}>{sm.start_time?.split(" ")[1]?.substring(0,8)||""} – {sm.end_time?.split(" ")[1]?.substring(0,8)||""}</span>}
                  <span style={{color:C.muted,fontSize:11}}>{sm?.exchange_count||"?"} exchanges</span>
                  {errCount>0&&<span style={{color:C.red,fontSize:10,fontFamily:"monospace"}}>{errCount} errors</span>}
                  <span style={{marginLeft:"auto",color:"#8899bb",fontSize:11}}>{isCollapsed?"▶":"▼"}</span>
                </div>
                {!isCollapsed&&sm?.summary&&<div style={{padding:"4px 16px 8px",fontSize:11,color:C.muted,lineHeight:1.6,borderTop:\`1px solid \${C.border}44\`}}>{sm.summary}</div>}
                {!isCollapsed&&sm?.operations?.length>0&&<div style={{padding:"4px 16px 8px",display:"flex",flexWrap:"wrap",gap:4,borderTop:\`1px solid \${C.border}44\`}}>
                  <span style={{fontSize:9,color:C.muted,fontFamily:"monospace",letterSpacing:.3}}>OPS:</span>
                  {sm.operations.map((op,i)=><span key={i} style={{fontSize:10,fontFamily:"monospace",color:C.teal,background:C.teal+"11",border:\`1px solid \${C.teal}33\`,borderRadius:3,padding:"1px 6px"}}>{op.label} ({op.detail})</span>)}
                </div>}
              </div>}
              {!isCollapsed&&<div id={\`ex-\${t.id}\`} style={{borderLeft:\`3px solid \${sc}22\`}}>
                <ExRow t={t} sel={sel===t.id} onClick={()=>setSel(sel===t.id?null:t.id)}/>
                {sel===t.id&&<ExDetail t={t}/>}
              </div>}
            </div>;
          });
        })()}</>}

      {tab==="findings"&&<div style={{padding:14}}>
        {certs&&<div style={{marginBottom:16}}><div style={{fontWeight:600,fontSize:13,marginBottom:8}}>Certificate Slots</div>
          <div style={{display:"flex",flexWrap:"wrap"}}>{(certs.probed||[]).map(tag=>{
            const pop=(certs.populated||[]).includes(tag);
            const certEx=pop?tl.find(e=>e.cert&&e.cert.slot===tag):null;
            return <div key={tag} onClick={()=>certEx&&go(certEx.id)} style={{display:"inline-flex",alignItems:"center",gap:4,padding:"4px 10px",borderRadius:3,border:\`1px solid \${pop?C.green:C.red}33\`,background:\`\${pop?C.green:C.red}08\`,marginRight:4,marginBottom:4,cursor:pop?"pointer":"default"}}>
            <span style={{fontSize:11,color:pop?C.green:C.red}}>{pop?"●":"○"}</span>
            <span style={{fontSize:11,color:C.text}}>{CN[tag]||tag}</span>
            {pop&&<span style={{fontSize:9,color:C.teal,marginLeft:4}}>→ #{certEx?.id}</span>}
          </div>;})}
          </div>
          {certs.all_empty&&<div style={{fontSize:11,color:C.amber,marginTop:4}}>All slots empty — unprovisioned</div>}
        </div>}

        <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}>
          <span style={{fontWeight:600,fontSize:13}}>Threats</span>
          {["critical","warn","info","pass"].map(sev=>{
            const sc2=sev==="critical"?C.red:sev==="warn"?C.amber:sev==="info"?C.teal:C.green;
            const ct=allThreats.filter(t=>t.severity===sev).length;
            if(!ct)return null;
            return <button key={sev} onClick={()=>setSevFilter(sevFilter===sev?null:sev)} style={{fontSize:10,padding:"2px 8px",borderRadius:3,border:\`1px solid \${sevFilter===sev?sc2:C.border}\`,background:sevFilter===sev?sc2+"22":"transparent",color:sevFilter===sev?sc2:C.muted,cursor:"pointer"}}>{sev} ({ct})</button>;
          })}
          {sevFilter&&<button onClick={()=>setSevFilter(null)} style={{fontSize:9,padding:"2px 6px",borderRadius:3,border:\`1px solid \${C.border}\`,background:"transparent",color:C.dim,cursor:"pointer"}}>clear</button>}
        </div>
        {(()=>{const ft=sevFilter?allThreats.filter(t=>t.severity===sevFilter):threats;
        return ft.length===0?<div style={{color:C.green,fontSize:12}}>None</div>:ft.map((t,i)=>{
          const tc=t.severity==="critical"?C.red:t.severity==="warn"?C.amber:C.blue;
          const certMatch=(t.title+" "+t.detail).match(/slot (5FC1[0-9A-Fa-f]+)/i);
          const certTag=certMatch?certMatch[1].toUpperCase():null;
          const certEx=certTag?tl.find(e=>e.cert&&e.cert.slot===certTag):null;
          return <div key={i} style={{marginBottom:10,borderRadius:4,border:\`1px solid \${tc}22\`,background:\`\${tc}08\`,overflow:"hidden"}}>
            <div style={{padding:"10px 12px"}}>
              <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:4}}><Badge color={tc}>{t.severity}</Badge><span style={{fontSize:12,fontWeight:600,color:C.text}}>{t.title}</span></div>
              <div style={{fontSize:11,color:C.muted,lineHeight:1.6}}>{t.detail}</div>
              {t.exchange_ids?.length>0&&<div style={{marginTop:6}}>{t.exchange_ids.map(id=><span key={id} onClick={()=>go(id)} style={{fontSize:10,color:C.teal,cursor:"pointer",marginRight:8,textDecoration:"underline"}}>Exchange #{id}</span>)}</div>}
            </div>
            {certEx&&certEx.cert?.b64&&typeof PV_B64!=="undefined"&&<PVMount b64={certEx.cert.b64} slot={CN[certTag]||certTag}/>}
          </div>;})})()}

        <div style={{fontWeight:600,fontSize:13,marginTop:16,marginBottom:8}}>Key Check</div>
        <div style={{fontSize:12,color:C.muted}}>Tested {d.key_check?.keys_tested} known keys across {d.key_check?.pairs_tested} auth pairs</div>
        {d.key_check?.matches?.length>0?d.key_check.matches.map((m,i)=><div key={i} style={{color:C.red,fontSize:11,fontWeight:600,marginTop:4}}>DEFAULT KEY: {m.name}</div>):<div style={{fontSize:10,color:C.green,marginTop:2}}>No default keys</div>}

        {d.compliance&&<div style={{marginTop:16}}><div style={{fontWeight:600,fontSize:12,marginBottom:6}}>Compliance</div>
          <div style={{display:"flex",gap:2,height:6,borderRadius:3,overflow:"hidden",marginBottom:4}}>
            <div style={{width:\`\${d.compliance.standard_pct}%\`,background:C.teal}}/><div style={{width:\`\${d.compliance.proprietary_pct}%\`,background:C.purple}}/>
          </div>
          <div style={{fontSize:10,color:C.muted}}>{d.compliance.standard_pct}% standard, {d.compliance.proprietary_pct}% proprietary ({(d.compliance.proprietary_ins||[]).join(", ")})</div></div>}

        {d.notable_annotations?.length>0&&<div style={{marginTop:16}}><div style={{fontWeight:600,fontSize:13,marginBottom:6}}>Notable ({d.notable_annotations.length})</div>
          {d.notable_annotations.map((a,i)=><div key={i} onClick={()=>go(a.exchange)} style={{display:"flex",gap:6,fontSize:11,lineHeight:1.6,cursor:"pointer",padding:"2px 0"}}>
            <span style={{color:C.teal,fontFamily:"monospace",minWidth:28,textDecoration:"underline"}}>{a.exchange}</span>
            <Badge color={flagC(a.flag)||C.amber}>{a.flag}</Badge>
            <span style={{color:C.muted}}>{a.note}</span></div>)}</div>}

        {d.object_ledger?.length>0&&<div style={{marginTop:16}}><div style={{fontWeight:600,fontSize:13,marginBottom:8}}>Object Ledger ({d.object_ledger.length} objects)</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:4}}>
          {d.object_ledger.map((obj,i)=>{
            const sc=obj.status==="present"?C.green:obj.status==="mutated"?C.amber:obj.status==="access-error"?C.red:C.dim;
            return <div key={i} style={{display:"flex",alignItems:"center",gap:6,padding:"4px 8px",borderRadius:3,border:\`1px solid \${sc}22\`,background:\`\${sc}08\`,fontSize:11}}>
              <span style={{width:6,height:6,borderRadius:"50%",background:sc,flexShrink:0}}/>
              <span style={{color:C.text,fontFamily:"monospace",fontSize:10}}>{obj.tag||"?"}</span>
              <span style={{color:C.muted,fontSize:10,flex:1}}>{obj.name||""}</span>
              {obj.size!=null&&<span style={{color:C.dim,fontSize:9}}>{obj.size}B</span>}
            </div>;
          })}
          </div>
        </div>}
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
