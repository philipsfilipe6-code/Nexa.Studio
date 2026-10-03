/* ===== JS: menu móvel, sanitização anti-XSS, validação, envio seguro ===== */
(function(){
  'use strict';
  /* ===== CONFIG: ÚNICO sítio a editar com os dados reais =====
     whatsapp: só números com indicativo (ex.: 2588XXXXXXXX) | email: e-mail oficial
     endpoint: URL do servidor no MESMO domínio (ex.: /.netlify/functions/contact) para envio com validação no back-end
     social: URLs completos https://… (vazio = link inactivo) */
  var CONFIG={whatsapp:'',email:'',endpoint:'/api/enviar',social:{instagram:'',linkedin:'',behance:'',dribbble:'',x:'',github:'',youtube:'',tiktok:'',whatsapp:''}};
  document.querySelectorAll('[data-net]').forEach(function(a){var u=CONFIG.social[a.dataset.net];if(/^https:\/\//.test(u)){a.href=u;a.target='_blank'}});
  var wa=document.querySelector('.wa');if(/\d{8,}/.test(CONFIG.whatsapp)){wa.href='https://wa.me/'+CONFIG.whatsapp.replace(/\D/g,'');wa.target='_blank';wa.hidden=false}
  // Páginas legais: foco no título ao abrir e Esc para fechar (acessibilidade)
  window.addEventListener('hashchange',function(){var t=document.querySelector(':target');if(t&&t.classList.contains('modal')){var h=t.querySelector('h2');h.setAttribute('tabindex','-1');h.focus()}});
  document.addEventListener('keydown',function(e){if(e.key==='Escape'&&document.querySelector('.modal:target'))location.hash='#topo'});
  // Menu móvel acessível
  // Tema claro/escuro: preferência guardada só neste navegador (try/catch: o armazenamento pode estar bloqueado)
  try{var sv=localStorage.getItem('nx-theme');if(sv)document.documentElement.setAttribute('data-theme',sv)}catch(e){}
  document.getElementById('tg').addEventListener('click',function(){
    var d=document.documentElement,c=d.getAttribute('data-theme')||'dark',n=c==='dark'?'light':'dark';
    d.setAttribute('data-theme',n);try{localStorage.setItem('nx-theme',n)}catch(e){}});
  // Revelação suave ao rolar + barra de progresso. Sem JS ou com movimento reduzido, tudo fica visível
  var bar=document.getElementById('bar');
  if(!matchMedia('(prefers-reduced-motion:reduce)').matches&&'IntersectionObserver' in window){
    document.documentElement.classList.add('js');
    var io=new IntersectionObserver(function(es){es.forEach(function(x){if(x.isIntersecting){x.target.classList.add('in');io.unobserve(x.target)}})},{threshold:.1});
    document.querySelectorAll('main .card,main .steps li,main h2,main details').forEach(function(el){el.classList.add('rv');io.observe(el)});
  }
  addEventListener('scroll',function(){var h=document.documentElement;bar.style.transform='scaleX('+(h.scrollTop/((h.scrollHeight-h.clientHeight)||1))+')'},{passive:true});
  // Brilho que segue o cursor nos cartões (efeito Linear); só actualiza variáveis CSS
  document.querySelectorAll('.card').forEach(function(c){c.addEventListener('pointermove',function(e){var r=c.getBoundingClientRect();c.style.setProperty('--mx',(e.clientX-r.left)+'px');c.style.setProperty('--my',(e.clientY-r.top)+'px')})});
  var mb=document.querySelector('.menu-btn'),mn=document.getElementById('menu');
  mb.addEventListener('click',function(){var o=mn.classList.toggle('open');mb.setAttribute('aria-expanded',o)});
  mn.addEventListener('click',function(){mn.classList.remove('open')});

  // Sanitização: remove tags e caracteres de controlo; o texto nunca é inserido como HTML
  function clean(s){
    // DOMParser não executa scripts nem carrega recursos; .textContent devolve só texto puro (anti-XSS)
    var t=new DOMParser().parseFromString(String(s),'text/html').body.textContent||'';
    return t.replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g,' ').replace(/[<>]/g,'').trim(); // remove controlo e < >
  }
  document.querySelectorAll('.err').forEach(function(d){d.setAttribute('role','alert');var i=document.getElementById(d.id.slice(2));if(i)i.setAttribute('aria-describedby',d.id)});
  document.addEventListener('keydown',function(e){if(e.key==='Escape'){mn.classList.remove('open');mb.setAttribute('aria-expanded',false)}});
  var f=document.getElementById('f'),out=document.getElementById('out'),t0=Date.now(),sending=false; // sending: trava duplo envio
  // Mostra feedback no div #out só com textContent; no sucesso reutiliza a classe .ok já existente
  function show(m,good){out.textContent='';if(good){var sp=document.createElement('span');sp.className='ok';sp.textContent=m;out.appendChild(sp)}else{out.textContent=m}}
  function err(id,m){document.getElementById('e-'+id).textContent=m||'';return !m}

  f.addEventListener('submit',function(e){
    e.preventDefault();
    out.textContent='';
    // Anti-bot: honeypot preenchido ou envio humanamente impossível (< 3s)
    if(f.site.value)return;
    if(Date.now()-t0<3000){out.textContent='Aguarde um instante e tente novamente.';return}
    var n=clean(f.nome.value),m=f.email.value.trim(),g=clean(f.msg.value),ok=true;
    ok=err('nome',n.length<2?'Indique o seu nome.':'')&&ok;
    ok=err('email',/^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(m)?'':'Indique um e-mail válido.')&&ok;
    ok=err('msg',g.length<20?'Escreva pelo menos 20 caracteres.':'')&&ok;
    ok=err('lgpd',f.lgpd.checked?'':'É necessário consentir para continuar.')&&ok;
    if(!ok)return;
    // Limite no cliente: 1 envio a cada 10 s, guardado em localStorage (try/catch: pode estar bloqueado)
    var LIM=10000,last=0;try{last=+localStorage.getItem('nx-last-send')||0}catch(x){}
    var wait=LIM-(Date.now()-last);
    if(wait>0){show('Aguarde '+Math.ceil(wait/1000)+'s antes de enviar outra mensagem.',false);return}
    if(sending)return; // ignora cliques enquanto há um envio em curso
    var data={nome:n,email:m,serv:clean(f.serv.value),msg:g,lgpd:true,site:f.site.value}; // dados já limpos
    sending=true;f.setAttribute('aria-busy','true');show('A enviar…',false); // aria-busy: leitores de ecrã sabem que está a enviar
    try{localStorage.setItem('nx-last-send',String(Date.now()))}catch(x){} // regista o instante do envio
    // Envio real: POST JSON ao backend, que valida e sanitiza outra vez
    fetch(CONFIG.endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data),credentials:'same-origin'})
      .then(function(r){return r.json().catch(function(){return{}}).then(function(j){if(!r.ok)throw j;return j})}) // lê o JSON e trata erro HTTP
      .then(function(){show('✔ Mensagem enviada. Respondemos em até 24 horas úteis.',true);f.reset()}) // sucesso
      .catch(function(j){show(j&&j.erro?j.erro:'Não foi possível enviar agora. Tente novamente ou fale connosco por WhatsApp.',false)}) // erro
      .then(function(){sending=false;f.removeAttribute('aria-busy')}); // liberta o formulário
  });
})();
