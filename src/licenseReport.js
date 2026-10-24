export function licenseStatus(l,now=Date.now()){
 if(!l.active)return 'Bloqueada';
 if(l.expires_at<=now)return 'Caducada';
 return l.activated_at?'Activa':'Pendiente de activar';
}
export function filterLicenses(rows,filter='all',query='',now=Date.now()){
 return rows.filter(l=>{const status=licenseStatus(l,now);return (filter==='all'||filter==='active'&&status==='Activa'||filter==='inactive'&&(status==='Pendiente de activar'||status==='Caducada')||filter==='pending'&&status==='Pendiente de activar'||filter==='expired'&&status==='Caducada'||filter==='blocked'&&status==='Bloqueada')&&[l.label,l.owner_email,l.id,l.key].join(' ').toLocaleLowerCase().includes(query.trim().toLocaleLowerCase());});
}
let library;
async function pdfLibrary(){if(window.PDFLib)return window.PDFLib;if(!library)library=new Promise((resolve,reject)=>{const s=document.createElement('script');s.src='/vendor/pdf-lib.min.js';s.onload=()=>resolve(window.PDFLib);s.onerror=()=>reject(Error('No se pudo cargar el generador PDF.'));document.head.append(s);}).catch(e=>{library=null;throw e;});return library;}
export async function licensePdfBytes(rows,filterLabel='Todas',now=Date.now()){
 const {PDFDocument,StandardFonts,rgb}=await pdfLibrary(),pdf=await PDFDocument.create(),font=await pdf.embedFont(StandardFonts.Helvetica),bold=await pdf.embedFont(StandardFonts.HelveticaBold),green=rgb(.08,.31,.25),gray=rgb(.3,.38,.35);let page,y;
 const safe=value=>Array.from(String(value??'')).map(c=>{try{font.encodeText(c);return c;}catch{return '?';}}).join('');
 const lines=(value,size,width)=>{const result=[];let line='';for(const c of safe(value)){if(line&&font.widthOfTextAtSize(line+c,size)>width){result.push(line);line='';}line+=c;}result.push(line);return result;};
 const newPage=()=>{page=pdf.addPage([595.28,841.89]);page.drawText('ElorrietaTrack · Control de licencias',{x:40,y:792,size:19,font:bold,color:green});page.drawText(safe('Emitido: '+new Date(now).toLocaleString('es-ES')+' · '+filterLabel),{x:40,y:769,size:10,font,color:gray});page.drawText(`${rows.length} licencia(s) en este informe`,{x:40,y:752,size:10,font,color:gray});y=725;};newPage();
 for(const l of rows){const fields=[['Destinatario',l.label],['Correo',l.owner_email||'Sin indicar'],['Número / ID',l.id],['Clave',l.key||'Anterior: no conservada. Registrar la clave original si se dispone de ella.'],['Plan / Estado',(l.plan==='premium'?'Premium':'Básica')+' / '+licenseStatus(l,now)],['Activación',l.activated_at?new Date(l.activated_at).toLocaleDateString('es-ES'):'Sin activar'],['Caducidad',new Date(l.expires_at).toLocaleDateString('es-ES')]];
 const wrapped=fields.map(([name,value])=>[name,lines(value,9.5,393)]),height=20+wrapped.reduce((n,[,ls])=>n+Math.max(1,ls.length)*13+5,0);if(y-height<60)newPage();page.drawRectangle({x:35,y:y-height,width:525,height,color:rgb(.95,.97,.96)});let cy=y-19;for(const[name,ls]of wrapped){page.drawText(name,{x:45,y:cy,size:9,font:bold,color:green});for(const line of ls){page.drawText(line,{x:155,y:cy,size:9.5,font,color:gray});cy-=13;}cy-=5;}y-=height+13;
 }
 if(!rows.length)page.drawText('No hay licencias para el filtro seleccionado.',{x:40,y:710,size:12,font,color:gray});const pages=pdf.getPages();pages.forEach((p,i)=>{p.drawText('Uso administrativo · Contiene claves de acceso. Conservar en lugar privado.',{x:40,y:33,size:8,font,color:gray});p.drawText(`${i+1} / ${pages.length}`,{x:520,y:33,size:8,font,color:gray});});pdf.setTitle('ElorrietaTrack - Control de licencias');return pdf.save();
}
export async function downloadLicensePdf(rows,label){const bytes=await licensePdfBytes(rows,label),url=URL.createObjectURL(new Blob([bytes],{type:'application/pdf'})),a=document.createElement('a');a.href=url;a.download='ElorrietaTrack-licencias-'+new Date().toISOString().slice(0,10)+'.pdf';a.click();setTimeout(()=>URL.revokeObjectURL(url),60000);}
