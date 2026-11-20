'use strict';
/* VirusTotal checks are opt-in. Selecting a file NEVER uploads it. */
window.renderVirusTotal = function (set, api, fail) {
  set([
    '<div class="grid"><section class="panel stack">',
    '<h2>Inspect a file</h2><p class="muted">Browser-only SHA-256 and file signature inspection. No files are executed or uploaded on selection. Local file limit: 20 MB.</p>',
    '<input id="vt-file" type="file" aria-label="Choose a file"><pre id="vt-local" aria-live="polite">Choose a file to inspect locally.</pre>',
    '<h3>Existing file reputation</h3><label class="meta" for="vt-hash">MD5, SHA-1 or SHA-256</label>',
    '<input id="vt-hash" maxlength="64" placeholder="Paste a hash or select a file" aria-label="File hash">',
    '<button id="vt-hash-check" class="primary">Look up hash with VirusTotal</button>',
    '<p class="meta">Only the hash is sent. An unknown hash is NOT a clean verdict.</p><div id="vt-hash-result" class="vt-report" role="status" aria-live="polite"></div>',
    '<h3>Submit file for actual analysis</h3><p class="meta">Optional, maximum 2 MB. <b>Public VirusTotal uploads may be shared with security vendors.</b> Do not upload research papers, passwords, sensitive or personal files.</p>',
    '<label class="vt-consent"><input id="vt-file-consent" type="checkbox"> I consent to upload this file to VirusTotal and understand its contents may be shared.</label>',
    '<button id="vt-file-submit" disabled>Upload selected file to VirusTotal</button>',
    '<div id="vt-file-result" class="vt-report" role="status" aria-live="polite"></div>',
    '<button id="vt-file-refresh" hidden>Refresh submitted file analysis</button></section>',
    '<section class="panel stack"><h2>Check a website URL</h2>',
    '<p class="muted">Get existing VirusTotal reputation for a public URL. CTI Sentinel does not visit the website.</p>',
    '<input id="vt-url" type="url" maxlength="2048" placeholder="https://example.com/" aria-label="Website URL">',
    '<button id="vt-url-check" class="primary">Look up website reputation</button>',
    '<div id="vt-url-result" class="vt-report" role="status" aria-live="polite"></div>',
    '<h3>Request website analysis</h3><p class="meta">Submitting shares the full URL including any query parameters. Use only public URLs, not private links or internal websites.</p>',
    '<label class="vt-consent"><input type="checkbox" id="vt-url-consent"> I consent to submit this URL to VirusTotal for analysis.</label>',
    '<button id="vt-url-submit" disabled>Submit URL to VirusTotal</button>',
    '<div id="vt-url-submitted" class="vt-report" role="status" aria-live="polite"></div>',
    '<button id="vt-url-refresh" hidden>Refresh submitted URL analysis</button>',
    '<h2>Review a message</h2><textarea id="vt-message" maxlength="7000" aria-label="Message text" placeholder="Paste a message to review links and suspicious language…"></textarea>',
    '<button id="vt-message-check">Check locally stored intelligence</button>',
    '<p class="meta">Heuristic cues are review hints, not a malware verdict. Links are never visited.</p><pre id="vt-message-result"></pre>',
    '</section></div>'
  ].join(''));
  const $ = id => document.getElementById(id);
  let selected = null, selectedHash = '', fileId = '', urlId = '';
  function text(parent, value, strong) {
    const item = document.createElement('p');
    if (strong) item.className = 'vt-title';
    item.textContent = value;
    parent.append(item);
  }
  function result(target, data) {
    const root = $(target);
    root.replaceChildren();
    if (data.status === 'not_found') {
      text(root,'No existing VirusTotal report',true);
      text(root,data.message || 'No existing analysis found.');
      text(root,'This is NOT evidence that the file or website is safe.');
      return;
    }
    if (data.status === 'queued') {
      text(root,'Analysis submitted — pending',true);
      text(root,data.message || 'VirusTotal is still processing.');
      text(root,'Use Refresh analysis later; API requests are rate-limited.');
      return;
    }
    if (data.status === 'found' || data.status === 'completed') {
      text(root,data.status === 'completed' ? 'Analysis completed' : 'VirusTotal reputation report',true);
      if (data.analysisTime) text(root,'Last analysis: '+new Date(data.analysisTime).toLocaleString());
      if (data.stats) {
        const group = document.createElement('div');group.className='vt-stat-grid';
        for (const [label,key,cls] of [['Malicious','malicious','vt-danger'],['Suspicious','suspicious','vt-warning'],['Harmless','harmless','vt-positive'],['Undetected','undetected','vt-muted']]) {
          const card=document.createElement('div');card.className='vt-stat '+cls;
          const number=document.createElement('strong');number.textContent=String(data.stats[key]||0);
          const title=document.createElement('small');title.textContent=label;
          card.append(number,title);group.append(card);
        }
        root.append(group);
        const other=['timeout','failure','type-unsupported','confirmed-timeout'].reduce((sum,k)=>sum+(data.stats[k]||0),0);
        if (other) text(root,other+' engines timed out, failed or did not support this input.');
        const checked=Object.values(data.stats).reduce((sum,n)=>sum+(Number(n)||0),0);
        if(checked===0)text(root,'No antivirus engine results are available yet. No safety verdict is possible.');
        else if ((data.stats.malicious||0)+(data.stats.suspicious||0)>0)
          text(root,'Attention: some engines flagged this item. Review the full VirusTotal report.');
        else text(root,'No engines flagged this item in the available report; this is NOT a guarantee of safety.');
      } else text(root,'No engine detection counts were returned; no safety conclusion is possible.');
      if (data.note) text(root,data.note);
      if (data.reportUrl && data.reportUrl.startsWith('https://www.virustotal.com/gui/')) {
        const link=document.createElement('a');link.href=data.reportUrl;link.rel='noopener noreferrer';link.target='_blank';
        link.textContent='Open detailed VirusTotal report';root.append(link);
      }
      return;
    }
    text(root,data.message||'Unknown provider response.',true);
  }
  async function action(button, work, target, after) {
    const el=$(button),label=el.textContent;el.disabled=true;el.textContent='Contacting VirusTotal…';
    try {
      const data=await work();result(target,data);
      if(after)after(data);
    } catch(e) {
      $(target).replaceChildren();text($(target),e.message||'Request failed.',true);
    } finally {
      el.textContent=label;
      if(button==='vt-file-submit')el.disabled=!(selected&&selected.size>0&&selected.size<=2097152&&$('vt-file-consent').checked);
      else if(button==='vt-url-submit')el.disabled=!$('vt-url-consent').checked;
      else el.disabled=false;
    }
  }
  function signature(v) {
    const tests=[
      [[137,80,78,71,13,10,26,10],'PNG image'],
      [[37,80,68,70],'PDF document'],[[80,75,3,4],'ZIP archive'],
      [[255,216,255],'JPEG image'],[[77,90],'Windows executable (MZ)'],
      [[71,73,70,56,55,97],'GIF image']
    ];
    for(const [bytes,name] of tests)if(bytes.every((b,i)=>v[i]===b))return name;
    return 'Unknown signature (not a malware verdict)';
  }
  $('vt-file').onchange=async()=>{
    selected=null;selectedHash='';fileId='';
    $('vt-file-consent').checked=false;
    $('vt-file-refresh').hidden=true;$('vt-file-submit').disabled=true;
    $('vt-local').textContent='Inspecting…';$('vt-hash-result').replaceChildren();$('vt-file-result').replaceChildren();
    const file=$('vt-file').files[0];
    if(!file){$('vt-local').textContent='Choose a file to inspect locally.';return;}
    try{
      if(file.size>20*1024*1024)throw Error('Local inspection limit is 20 MB.');
      const bytes=await file.arrayBuffer();
      const sha=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
      selected=file;selectedHash=sha;$('vt-hash').value=sha;
      $('vt-local').textContent=JSON.stringify({name:file.name,bytes:file.size,signature:signature(new Uint8Array(bytes)),sha256:sha,executed:false,uploaded:false,virusTotalScanned:false},null,2);
      $('vt-file-submit').disabled=file.size===0||file.size>2097152||!$('vt-file-consent').checked;
      if(file.size>2097152)text($('vt-file-result'),'This file exceeds the 2 MB hosted upload limit. Hash reputation still works.');
    }catch(e){$('vt-local').textContent=e.message;}
  };
  $('vt-file-consent').onchange=()=>{$('vt-file-submit').disabled=!(selected&&selected.size>0&&selected.size<=2097152&&$('vt-file-consent').checked);};
  $('vt-hash-check').onclick=()=>action('vt-hash-check',()=>api('/api/vt/hash',{hash:$('vt-hash').value}),'vt-hash-result');
  function base64(bytes){
    const view=new Uint8Array(bytes);let binary='';
    for(let i=0;i<view.length;i+=32768)binary+=String.fromCharCode(...view.subarray(i,i+32768));
    return btoa(binary);
  }
  $('vt-file-submit').onclick=()=>{
    if(!selected||!$('vt-file-consent').checked)return;
    return action('vt-file-submit',async()=>api('/api/vt/file',{filename:selected.name,sha256:selectedHash,data:base64(await selected.arrayBuffer()),consent:true}),'vt-file-result',d=>{
      fileId=d.status==='queued'?d.analysisId:'';$('vt-file-refresh').hidden=!fileId;
    });
  };
  $('vt-file-refresh').onclick=()=>{
    if(!fileId)return;
    return action('vt-file-refresh',()=>api('/api/vt/analysis',{analysisId:fileId}),'vt-file-result',d=>{
      $('vt-file-refresh').hidden=d.status!=='queued';
      if(d.status==='completed'){
        text($('vt-file-result'),'File SHA-256: '+selectedHash);
        const link=document.createElement('a');link.href='https://www.virustotal.com/gui/file/'+selectedHash+'/detection';
        link.target='_blank';link.rel='noopener noreferrer';link.textContent='Open detailed file report';$('vt-file-result').append(link);
      }
    });
  };
  $('vt-url-check').onclick=()=>action('vt-url-check',()=>api('/api/vt/url',{url:$('vt-url').value}),'vt-url-result');
  $('vt-url').oninput=()=>{$('vt-url-consent').checked=false;$('vt-url-submit').disabled=true;urlId='';$('vt-url-refresh').hidden=true;};
  $('vt-url-consent').onchange=()=>{$('vt-url-submit').disabled=!$('vt-url-consent').checked;};
  $('vt-url-submit').onclick=()=>{
    if(!$('vt-url-consent').checked)return;
    return action('vt-url-submit',()=>api('/api/vt/url-submit',{url:$('vt-url').value,consent:true}),'vt-url-submitted',d=>{
      urlId=d.status==='queued'?d.analysisId:'';$('vt-url-refresh').hidden=!urlId;
    });
  };
  $('vt-url-refresh').onclick=()=>{
    if(!urlId)return;
    return action('vt-url-refresh',()=>api('/api/vt/analysis',{analysisId:urlId}),'vt-url-submitted',d=>{
      $('vt-url-refresh').hidden=d.status!=='queued';
      if(d.status==='completed')text($('vt-url-submitted'),'You may also check the URL reputation again for the latest report.');
    });
  };
  $('vt-message-check').onclick=async()=>{
    try{const d=await api('/api/intel/message',{text:$('vt-message').value});$('vt-message-result').textContent=JSON.stringify(d,null,2);}
    catch(e){fail(e);}
  };
};
