const form=document.getElementById('scanForm');
const btn=document.getElementById('scanBtn');
const msg=document.getElementById('message');
const progress=document.getElementById('progress');
function showMessage(text,type){msg.textContent=text;msg.className='message '+type;msg.hidden=false;}
form.addEventListener('submit',async e=>{
  e.preventDefault();
  if(!document.getElementById('authorized').checked){showMessage('يرجى تأكيد امتلاكك للجهاز أو حصولك على إذن بفحصه.','error');return;}
  const target=document.getElementById('target').value.trim();
  btn.disabled=true;btn.textContent='جارٍ الفحص…';progress.hidden=false;msg.hidden=true;
  try{
    const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
    const data=await response.json();
    if(!response.ok||!data.ok)throw new Error(data.error||'تعذر تنفيذ الفحص.');
    const r=data.report;
    document.getElementById('lastTarget').textContent=r.target;
    document.getElementById('checkedCount').textContent=r.ports_checked;
    document.getElementById('openCount').textContent=r.open_count;
    const body=document.getElementById('resultsBody');body.replaceChildren();
    r.results.forEach(item=>{const tr=document.createElement('tr');[item.port,item.service,item.state].forEach((value,i)=>{const td=document.createElement('td');td.textContent=value;if(i===2)td.className=item.state==='مفتوح'?'state-open':'state-closed';tr.appendChild(td)});body.appendChild(tr)});
    const rec=document.getElementById('recommendations');rec.replaceChildren();
    r.recommendations.forEach(text=>{const div=document.createElement('div');div.className='rec';const icon=document.createElement('span');icon.textContent='✓';const p=document.createElement('p');p.textContent=text;div.append(icon,p);rec.appendChild(div)});
    showMessage(`اكتمل الفحص للعنوان ${r.target}. المنافذ المفتوحة: ${r.open_count}. تذكّر أن المنفذ المفتوح لا يعني بالضرورة وجود ثغرة.`,'success');
  }catch(err){showMessage(err.message,'error');}
  finally{btn.disabled=false;btn.textContent='⌕ ابدأ الفحص';progress.hidden=true;}
});
