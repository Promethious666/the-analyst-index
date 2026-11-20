const encoder = new TextEncoder();
const xml = value => String(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").replace(/[<>&"']/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;","'":"&apos;"})[c]);
const table = new Uint32Array(256);
for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?0xedb88320^(c>>>1):c>>>1;table[n]=c>>>0;}
function crc32(bytes){let c=0xffffffff;for(const b of bytes)c=table[(c^b)&255]^(c>>>8);return(c^0xffffffff)>>>0;}
function header(size){const bytes=new Uint8Array(size);return{bytes,view:new DataView(bytes.buffer)};}

export function zipStore(files){
  const chunks=[],central=[];let offset=0,centralSize=0;
  for(const [name,text] of Object.entries(files)){
    const n=encoder.encode(name),data=encoder.encode(text),crc=crc32(data);
    const l=header(30);l.view.setUint32(0,0x04034b50,true);l.view.setUint16(4,20,true);l.view.setUint16(6,0x800,true);l.view.setUint16(12,33,true);l.view.setUint32(14,crc,true);l.view.setUint32(18,data.length,true);l.view.setUint32(22,data.length,true);l.view.setUint16(26,n.length,true);
    chunks.push(l.bytes,n,data);
    const c=header(46);c.view.setUint32(0,0x02014b50,true);c.view.setUint16(4,20,true);c.view.setUint16(6,20,true);c.view.setUint16(8,0x800,true);c.view.setUint16(14,33,true);c.view.setUint32(16,crc,true);c.view.setUint32(20,data.length,true);c.view.setUint32(24,data.length,true);c.view.setUint16(28,n.length,true);c.view.setUint32(42,offset,true);central.push(c.bytes,n);centralSize+=46+n.length;offset+=30+n.length+data.length;
  }
  const end=header(22);end.view.setUint32(0,0x06054b50,true);end.view.setUint16(8,Object.keys(files).length,true);end.view.setUint16(10,Object.keys(files).length,true);end.view.setUint32(12,centralSize,true);end.view.setUint32(16,offset,true);
  const all=[...chunks,...central,end.bytes],result=new Uint8Array(all.reduce((n,b)=>n+b.length,0));let position=0;for(const bytes of all){result.set(bytes,position);position+=bytes.length;}return result;
}

export function docxFiles(report){
  const p=(text,style="Normal")=>`<w:p><w:pPr><w:pStyle w:val="${style}"/></w:pPr>${String(text).split("\n").map((line,i)=>`<w:r>${i?"<w:br/>":""}<w:t xml:space="preserve">${xml(line)}</w:t></w:r>`).join("")}</w:p>`;
  return {
    "[Content_Types].xml":`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`,
    "_rels/.rels":`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`,
    "word/_rels/document.xml.rels":`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`,
    "docProps/core.xml":`<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${xml(report.title)}</dc:title>${report.author?`<dc:creator>${xml(report.author)}</dc:creator>`:""}<dcterms:created xsi:type="dcterms:W3CDTF">${xml(report.generatedAt)}</dcterms:created></cp:coreProperties>`,
    "word/styles.xml":`<?xml version="1.0" encoding="UTF-8"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="140" w:line="280" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val="40"/><w:color w:val="3E4A12"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="140"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style></w:styles>`,
    "word/document.xml":`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${p(report.title,"Title")}${p(`Generated: ${report.generatedAt}${report.author?` | Prepared by: ${report.author}`:""}`)}${p(report.scope==="update"?"Update report":"Technical report")}${report.sections.map(s=>p(s.heading,"Heading1")+s.lines.map(line=>p(line)).join("")).join("")}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1020" w:right="1020" w:bottom="1020" w:left="1020"/></w:sectPr></w:body></w:document>`
  };
}
export function createDocx(report){return zipStore(docxFiles(report));}
