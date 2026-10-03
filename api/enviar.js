// /api/enviar.js — função serverless (Vercel): valida, limpa e envia o contacto por e-mail via Resend.
// Variáveis de ambiente (NUNCA no código): RESEND_API_KEY, MAIL_TO, MAIL_FROM, ALLOWED_ORIGIN (ex.: https://nexastudio.co.mz)

const SERVICOS = ['Website', 'Branding / UI-UX', 'App / Plataforma', 'E-commerce', 'Outro']; // lista fechada: rejeita valores inventados
const LIMITE = 6, JANELA = 60 * 60 * 1000; // máx. 5 envios por IP por hora
const registos = new Map(); // IP -> instantes dos envios. Em memória: serve de base; em produção use Upstash Redis/Vercel KV

// htmlspecialchars: converte & < > " ' ` em entidades, para o texto nunca virar HTML no e-mail (anti-XSS)
const esc = s => String(s).replace(/[&<>"'`]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));

// Remove tags e caracteres de controlo (inclui \r e \n nos campos de uma linha: evita injecção de cabeçalhos) e corta ao máximo
const limpar = (s, max, multilinha) =>
  String(s ?? '').replace(/<[^>]*>/g, ' ')
    .replace(multilinha ? /[\u0000-\u0009\u000B-\u001F\u007F]/g : /[\u0000-\u001F\u007F]/g, ' ')
    .trim().slice(0, max);

// Rate limit por IP: devolve true se o IP já atingiu o limite na janela
function limitado(ip) {
  const agora = Date.now();
  const lista = (registos.get(ip) || []).filter(t => agora - t < JANELA); // descarta registos antigos
  if (lista.length >= LIMITE) { registos.set(ip, lista); return true; }
  lista.push(agora); registos.set(ip, lista);
  if (registos.size > 5000) for (const [k, v] of registos) if (!v.some(t => agora - t < JANELA)) registos.delete(k); // evita crescer sem fim
  return false;
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');           // resposta nunca fica em cache
  res.setHeader('X-Content-Type-Options', 'nosniff');   // impede o navegador de adivinhar o tipo de conteúdo
  const responder = (codigo, corpo) => res.status(codigo).json(corpo); // resposta JSON uniforme

  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return responder(405, { erro: 'Método não permitido.' }); } // só POST
  const origem = req.headers.origin;
  if (process.env.ALLOWED_ORIGIN && origem !== process.env.ALLOWED_ORIGIN) return responder(403, { erro: 'Origem não permitida.' }); // bloqueia outros sites (CSRF)
  if (!String(req.headers['content-type'] || '').includes('application/json')) return responder(415, { erro: 'Tipo de conteúdo inválido.' });
  if (Number(req.headers['content-length'] || 0) > 10000) return responder(413, { erro: 'Pedido demasiado grande.' }); // limita o tamanho

  // No Vercel o primeiro valor de x-forwarded-for é o IP real do cliente
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'desconhecido';
  if (limitado(ip)) { res.setHeader('Retry-After', '3600'); return responder(429, { erro: 'Muitas mensagens enviadas. Tente mais tarde.' }); }

  const d = req.body && typeof req.body === 'object' ? req.body : null; // corpo já interpretado como JSON pelo Vercel
  if (!d) return responder(400, { erro: 'Pedido inválido.' });
  if (d.site) return responder(200, { ok: true }); // honeypot: bot recebe "sucesso" falso e nada é enviado

  const nome = limpar(d.nome, 80), email = limpar(d.email, 120), msg = limpar(d.msg, 1500, true);
  const serv = SERVICOS.includes(d.serv) ? d.serv : 'Outro';
  const emailOk = /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(email); // formato de e-mail seguro
  if (nome.length < 2 || !emailOk || msg.length < 20 || d.lgpd !== true) return responder(422, { erro: 'Dados inválidos. Verifique os campos.' }); // LGPD obrigatória

  const { RESEND_API_KEY, MAIL_TO, MAIL_FROM } = process.env;
  if (!RESEND_API_KEY || !MAIL_TO || !MAIL_FROM) { console.error('Configuração de e-mail em falta'); return responder(500, { erro: 'Serviço indisponível.' }); } // chave só no servidor

  // Corpo do e-mail: todo o texto do utilizador passa por esc()
  const html = `<h2>Novo pedido de proposta</h2><p><b>Nome:</b> ${esc(nome)}</p><p><b>E-mail:</b> ${esc(email)}</p>`
    + `<p><b>Serviço:</b> ${esc(serv)}</p><p style="white-space:pre-wrap">${esc(msg)}</p><hr><small>Consentimento LGPD: sim · ${new Date().toISOString()}</small>`;

  const ctrl = new AbortController(); const tempo = setTimeout(() => ctrl.abort(), 8000); // desiste ao fim de 8 s
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', signal: ctrl.signal,
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: MAIL_FROM, to: [MAIL_TO], reply_to: email, subject: `Pedido de proposta — ${nome}`.slice(0, 120), html, text: `${nome} <${email}> | ${serv}\n\n${msg}` })
    });
    if (!r.ok) { console.error('Resend respondeu', r.status); return responder(502, { erro: 'Não foi possível enviar agora.' }); } // não expõe detalhes
    return responder(200, { ok: true });
  } catch (e) {
    console.error('Falha no envio:', e.name); // regista só o tipo de erro (sem dados pessoais, por LGPD)
    return responder(502, { erro: 'Não foi possível enviar agora.' });
  } finally { clearTimeout(tempo); }
};
