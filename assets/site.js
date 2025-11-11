
// Nav active state
(function(){
  const path = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav a').forEach(a=>{
    const href = a.getAttribute('href');
    if (href === path || (path==='index.html' && href==='index.html')) {
      a.classList.add('active');
    }
  });
})();

// Toggle cards
function toggleCard(cardEl){
  document.querySelectorAll('.card').forEach(c=>{ if(c!==cardEl) collapseCard(c); });
  const body=cardEl.querySelector('.card-body'); if(!body) return;
  const open = body.classList.contains('hidden');
  if(open){ body.classList.remove('hidden'); cardEl.classList.add('expanded'); }
  else    { collapseCard(cardEl); }
}
function collapseCard(cardEl){
  const body=cardEl.querySelector('.card-body'); if(!body||body.classList.contains('hidden'))return;
  const iframe=body.querySelector('iframe'); if(iframe){ const s=iframe.src; iframe.src=s; }
  body.classList.add('hidden'); cardEl.classList.remove('expanded');
}

// Lazy iframes
(function(){
  const io = new IntersectionObserver((entries)=>{
    for(const e of entries){
      if(!e.isIntersecting) continue;
      e.target.querySelectorAll('iframe.defer-embed[data-src]').forEach(ifr=>{
        if(!ifr.src){ ifr.src=ifr.getAttribute('data-src'); ifr.removeAttribute('data-src'); }
      });
      io.unobserve(e.target);
    }
  }, {root:null, rootMargin:'150px 0px', threshold:0.15});
  document.querySelectorAll('.shell, .shell-70, .shell-80').forEach(el=>io.observe(el));
})();

// EOR page init
(function(){
  const eorRoot = document.getElementById('eor-root');
  if(!eorRoot) return;

  const BASE="https://eor-api.exile-studios.com";
  const unk=document.getElementById("eor-unk");
  const q=document.getElementById("eor-q");
  const status=document.getElementById("eor-status");
  const listEl=document.getElementById("eor-list");
  const moreBtn=document.getElementById("eor-more");
  const detailEl=document.getElementById("eor-detail");
  const titleEl=document.getElementById("eor-detail-title");
  const imgWrap=document.getElementById("eor-images");
  const copyJsonBtn=document.getElementById("eor-copy-json");
  const copyCurlBtn=document.getElementById("eor-copy-curl");

  const tabs=[...document.querySelectorAll(".eor-tab")];
  let current="items";
  let cache={};
  let filtered=[];
  let page=0;
  const PAGE_SIZE=100;

  const catCfg={
    items:{list:"/api/items",detail:id=>`/api/items/${id}`,images:id=>[`/api/items/${id}/graphic`,`/api/items/${id}/graphic/ground`]},
    npcs:{list:"/api/npcs",detail:id=>`/api/npcs/${id}`,images:id=>[`/api/npcs/${id}/graphic`]},
    spells:{list:"/api/spells",detail:id=>`/api/spells/${id}`,images:id=>[`/api/spells/${id}/icon`,`/api/spells/${id}/graphic`]},
    maps:{list:"/api/maps",detail:id=>`/api/maps/${id}`,images:null},
    shops:{list:"/api/shops",detail:name=>`/api/shops/${encodeURIComponent(name)}`,images:null},
    classes:{list:"/api/classes",detail:id=>`/api/classes/${id}`,images:null},
    quests:{list:"/api/quests",detail:id=>`/api/quests/${id}`,images:null},
  };

  function qs(url){ return unk.checked ? url+(url.includes("?")?"&":"?")+"show_unk=1" : url; }

  async function fetchJson(path){
    const url=qs(BASE+path);
    const r=await fetch(url,{headers:{"Accept":"application/json"}});
    if(!r.ok) throw new Error(r.status+" "+r.statusText);
    return r.json();
  }

  function unwrapForList(cat,data){
    if(Array.isArray(data)) return data;
    if(data && typeof data==="object"){
      const keys=[cat,"data","results","list","records","items","npcs","spells","maps","classes","quests","shops"];
      for(const k of keys){ if(Array.isArray(data[k])) return data[k]; }
      const out=[];
      for(const [k,v] of Object.entries(data)){
        if(v==null) continue;
        if(typeof v==="string"||typeof v==="number"){ out.push({id:k,name:String(v),raw:v}); continue; }
        out.push({
          id:v.id??v.itemId??v.npcId??v.spellId??v.classId??v.questId??v.mapId??k,
          name:v.name??v.displayName??String(k),
          raw:v
        });
      }
      return out;
    }
    return [];
  }

  function normalizeList(cat,list){
    return list.map((rec,idx)=>{
      if(typeof rec==="string") return {id:rec,name:rec,raw:rec};
      if(typeof rec==="number") return {id:rec,name:String(rec),raw:rec};
      const id = rec.id ?? rec.itemId ?? rec.npcId ?? rec.spellId ?? rec.classId ?? rec.questId ?? rec.mapId ?? rec.index ?? (cat==="shops"?rec.name:undefined) ?? idx;
      const name = rec.name ?? rec.displayName ?? ("#"+id);
      return {id,name,raw:rec};
    });
  }

  async function ensureList(cat){
    if(cache[cat]?.list) return;
    status.textContent=`Loading ${cat}…`;
    try{
      const raw=await fetchJson(catCfg[cat].list);
      const unwrapped=unwrapForList(cat,raw);
      const list=normalizeList(cat,unwrapped);
      cache[cat]={raw,list};
      status.textContent=`Loaded ${list.length} ${cat}.`;
    }catch(e){
      status.textContent=`Error loading ${cat}: ${e.message}`;
      cache[cat]={raw:[],list:[]};
    }
  }

  function applyFilter(){
    const needle=q.value.trim().toLowerCase();
    const list=cache[current].list||[];
    filtered = needle ? list.filter(r =>
      String(r.name).toLowerCase().includes(needle) ||
      String(r.id).toLowerCase().includes(needle)
    ) : list.slice();
    page=0; renderPage();
  }

  function renderPage(){
    listEl.innerHTML="";
    const start=page*PAGE_SIZE;
    const slice=filtered.slice(start,start+PAGE_SIZE);
    if(!slice.length){
      listEl.innerHTML=`<li class="p-3 text-gray-300">No results.</li>`;
      moreBtn.classList.add("hidden"); return;
    }
    const frag=document.createDocumentFragment();
    for(const r of slice){
      const li=document.createElement("li");
      li.className="p-2 hover:bg-black/40 cursor-pointer";
      li.innerHTML=`<div class="flex items-center justify-between gap-2">
        <div class="truncate text-white">${escapeHtml(r.name)}</div>
        <div class="text-xs text-gray-400">ID: ${escapeHtml(String(r.id))}</div>
      </div>`;
      li.addEventListener("click",()=>showDetail(r));
      frag.appendChild(li);
    }
    listEl.appendChild(frag);
    moreBtn.classList.toggle("hidden", start+PAGE_SIZE>=filtered.length);
  }

  function escapeHtml(s){ return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

  async function showDetail(r){
    titleEl.textContent=`${capitalize(current)} – ${r.name}`;
    detailEl.textContent="Loading details…";
    imgWrap.innerHTML="";
    try{
      const key = (current==="shops") ? r.name : r.id;
      const path=catCfg[current].detail(key);
      const data=await fetchJson(path);
      detailEl.textContent=JSON.stringify(data,null,2);

      const imgs = catCfg[current].images ? catCfg[current].images(r.id) : [];
      if(imgs && imgs.length){
        for(const p of imgs){
          const url=qs(BASE+p);
          const img=document.createElement("img");
          img.src=url; img.alt=current+" image"; img.decoding="async";
          img.className="max-h-64 object-contain rounded border border-red-500/30 bg-black/70 p-2";
          imgWrap.appendChild(img);
        }
      }
      copyCurlBtn.onclick=()=>copy(`curl "${qs(BASE+path)}"`);
      copyJsonBtn.onclick=()=>copy(JSON.stringify(data,null,2));
    }catch(e){
      detailEl.textContent="Error: "+e.message;
      copyCurlBtn.onclick=null; copyJsonBtn.onclick=null;
    }
  }

  function copy(text){
    navigator.clipboard.writeText(text).then(()=>{
      copyJsonBtn.textContent="Copied"; copyCurlBtn.textContent="Copied";
      setTimeout(()=>{copyJsonBtn.textContent="Copy JSON";copyCurlBtn.textContent="Copy curl";},800);
    });
  }
  function capitalize(s){return s.charAt(0).toUpperCase()+s.slice(1);}
  function setActive(cat){
    current=cat;
    tabs.forEach(b=>b.classList.toggle("bg-red-600",b.dataset.cat===cat));
  }
  async function initCategory(cat){ setActive(cat); await ensureList(cat); applyFilter(); }

  tabs.forEach(b=>b.addEventListener("click",()=>initCategory(b.dataset.cat)));
  moreBtn.addEventListener("click",()=>{page++;renderPage();});
  let t=0; q.addEventListener("input",()=>{clearTimeout(t); t=setTimeout(applyFilter,150);});
  unk.addEventListener("change",()=>initCategory(current));

  initCategory(current);
})();

// Downloads page: search + category filters
(async function(){
  const grid = document.getElementById('downloadsContainer');
  if(!grid) return;
  const search = document.getElementById('dl-search');
  const catRow = document.getElementById('dl-cats');
  const countEl = document.getElementById('dl-count');

  let all = [];
  let activeCats = new Set();

  function renderCards(items){
    grid.innerHTML = '';
    if(!items.length){
      grid.innerHTML = '<p class="small" style="color:#ddd">No downloads match your filters.</p>';
      countEl.textContent = '0';
      return;
    }
    countEl.textContent = String(items.length);
    for(const d of items){
      const cats = Array.isArray(d.categories) ? d.categories : [];
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `
        <h3 style="font-weight:800;font-size:1.15rem;margin-bottom:.25rem">${d.title??'Untitled'}</h3>
        <p class="small">${d.description??''}</p>
        <div style="margin-top:.25rem;display:flex;flex-wrap:wrap;gap:.35rem">
          ${cats.map(c=>`<span class="chip small">${c}</span>`).join('')}
        </div>
        <div class="card-body hidden" style="margin-top:.75rem;font-size:.95rem">
          ${d.version?`<p><strong>Version:</strong> ${d.version}</p>`:''}
          ${d.details?`<p style="opacity:.9">${d.details}</p>`:''}
          ${d.link?`<a href="${d.link}" target="_blank" class="btn" style="margin-top:.5rem">Download</a>`:''}
        </div>`;
      card.onclick=()=>toggleCard(card);
      grid.appendChild(card);
    }
  }

  function applyFilters(){
    const q = (search?.value || '').trim().toLowerCase();
    let out = all.filter(d=>{
      const hay = `${d.title||''} ${d.description||''} ${d.details||''} ${(d.version||'')}`.toLowerCase();
      const passQ = !q || hay.includes(q);
      const cats = Array.isArray(d.categories)? d.categories : [];
      const passC = activeCats.size===0 || cats.some(c=>activeCats.has(c));
      return passQ && passC;
    });
    renderCards(out);
  }

  function renderCatFilters(cats){
    catRow.innerHTML = '';
    const uniq = [...new Set(cats.flat())].sort((a,b)=>a.localeCompare(b));
    for(const c of uniq){
      const chip = document.createElement('button');
      chip.className = 'chip';
      chip.textContent = c;
      chip.addEventListener('click', ()=>{
        if(activeCats.has(c)) activeCats.delete(c); else activeCats.add(c);
        chip.classList.toggle('active');
        applyFilters();
      });
      catRow.appendChild(chip);
    }
  }

  try{
    const res = await fetch('downloads.json', {cache:'no-store'});
    if(!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    if(!Array.isArray(data)) throw new Error('downloads.json must be an array');
    all = data;
    const allCats = data.map(d=>Array.isArray(d.categories)? d.categories : []);
    renderCatFilters(allCats);
    applyFilters();
    search?.addEventListener('input', ()=>applyFilters());
  }catch(e){
    grid.innerHTML = '<p style="color:#ef9a9a">Error loading downloads.json: '+e.message+'</p>';
  }
})();

// HowTo page: load from videos.json
(async function(){
  const container = document.getElementById('videosContainer');
  if(!container) return;
  const vSearch = document.getElementById('vid-search');
  const vCatRow = document.getElementById('vid-cats');
  const vCount = document.getElementById('vid-count');

  let all = [];
  let activeCats = new Set();

  function render(items){
    container.innerHTML = '';
    if(!items.length){
      container.innerHTML = '<p class="small" style="color:#ddd">No videos match your filters.</p>';
      vCount.textContent = '0';
      return;
    }
    vCount.textContent = String(items.length);
    for(const v of items){
      const cats = Array.isArray(v.categories) ? v.categories : [];
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `
        <h3 style="font-weight:800;font-size:1.05rem;margin-bottom:.25rem">${v.title??'Untitled'}</h3>
        <p class="small">${v.description??''}</p>
        <div style="margin-top:.25rem;display:flex;flex-wrap:wrap;gap:.35rem">
          ${cats.map(c=>`<span class="chip small">${c}</span>`).join('')}
        </div>
        <div class="card-body hidden" style="margin-top:.75rem">
          <div class="shell shell-70">
            <iframe class="w-full h-full" loading="lazy" src="https://www.youtube.com/embed/${v.youtubeId}" title="${v.title||'Video'}" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
          </div>
        </div>`;
      card.onclick=()=>toggleCard(card);
      container.appendChild(card);
    }
  }

  function applyFilters(){
    const q = (vSearch?.value || '').trim().toLowerCase();
    let out = all.filter(v=>{
      const hay = `${v.title||''} ${v.description||''}`.toLowerCase();
      const passQ = !q || hay.includes(q);
      const cats = Array.isArray(v.categories)? v.categories : [];
      const passC = activeCats.size===0 || cats.some(c=>activeCats.has(c));
      return passQ && passC;
    });
    render(out);
  }

  function renderCatFilters(cats){
    vCatRow.innerHTML = '';
    const uniq = [...new Set(cats.flat())].sort((a,b)=>a.localeCompare(b));
    for(const c of uniq){
      const chip = document.createElement('button');
      chip.className = 'chip';
      chip.textContent = c;
      chip.addEventListener('click', ()=>{
        if(activeCats.has(c)) activeCats.delete(c); else activeCats.add(c);
        chip.classList.toggle('active');
        applyFilters();
      });
      vCatRow.appendChild(chip);
    }
  }

  try{
    const res = await fetch('videos.json', {cache:'no-store'});
    if(!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    if(!Array.isArray(data)) throw new Error('videos.json must be an array');
    all = data;
    const allCats = data.map(v=>Array.isArray(v.categories)? v.categories : []);
    renderCatFilters(allCats);
    applyFilters();
    vSearch?.addEventListener('input', ()=>applyFilters());
  }catch(e){
    container.innerHTML = '<p style="color:#ef9a9a">Error loading videos.json.</p>';
  }
})();
