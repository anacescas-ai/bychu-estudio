// ByChu Estúdio — servidorzinho da IA (Cloudflare Worker)
//
// O que ele faz:
//  - guarda a sua chave da API do Claude (como "segredo" na Cloudflare; ela NÃO fica neste código)
//  - só aceita pedidos vindos do site do estúdio e de quem entrou com um e-mail permitido
//  - repassa o pedido para o Claude e devolve a resposta em tempo real
//
// Configuração na Cloudflare (Settings → Variables and Secrets):
//  - ANTHROPIC_API_KEY  (tipo Secret): a chave da API
//  - EMAILS_PERMITIDOS  (tipo Text):   seu e-mail do Google (se forem vários, separe por vírgula)

const ORIGEM = "https://anacescas-ai.github.io";
const PROJETO_FIREBASE = "bychu-estudio";
const MODELOS = { sonnet: "claude-sonnet-5-5", haiku: "claude-haiku-5-5" };
const MAX_SAIDA = 32000;
const CHAVES_GOOGLE = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

let cacheChaves = null, cacheAte = 0;

function cors(extra = {}) {
  return {
    "Access-Control-Allow-Origin": ORIGEM,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
    ...extra,
  };
}
function erro(status, mensagem) {
  return new Response(JSON.stringify({ erro: mensagem }), {
    status, headers: cors({ "Content-Type": "application/json; charset=utf-8" }),
  });
}
function b64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
const json = bytes => JSON.parse(new TextDecoder().decode(bytes));

async function chavesGoogle() {
  if (cacheChaves && Date.now() < cacheAte) return cacheChaves;
  const r = await fetch(CHAVES_GOOGLE);
  if (!r.ok) throw new Error("não consegui buscar as chaves do Google");
  cacheChaves = (await r.json()).keys;
  const m = /max-age=(\d+)/.exec(r.headers.get("cache-control") || "");
  cacheAte = Date.now() + (m ? +m[1] * 1000 : 3600_000);
  return cacheChaves;
}

// Confere o "crachá" (ID token) que o Firebase dá a quem entrou com o Google.
async function verificarLogin(token) {
  const partes = (token || "").split(".");
  if (partes.length !== 3) throw new Error("sem login");
  const [h, p, s] = partes;
  const cabecalho = json(b64url(h)), corpo = json(b64url(p));
  if (cabecalho.alg !== "RS256") throw new Error("token estranho");
  const jwk = (await chavesGoogle()).find(k => k.kid === cabecalho.kid);
  if (!jwk) throw new Error("chave desconhecida");
  const chave = await crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", chave, b64url(s), new TextEncoder().encode(h + "." + p));
  if (!ok) throw new Error("assinatura inválida");
  const agora = Math.floor(Date.now() / 1000);
  if (corpo.aud !== PROJETO_FIREBASE) throw new Error("projeto errado");
  if (corpo.iss !== "https://securetoken.google.com/" + PROJETO_FIREBASE) throw new Error("emissor errado");
  if (!(corpo.exp > agora) || corpo.iat > agora + 300) throw new Error("login expirado");
  return corpo;
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
    if (req.method !== "POST") return erro(405, "Este endereço só serve o ByChu Estúdio.");
    if (req.headers.get("Origin") !== ORIGEM) return erro(403, "Origem não permitida.");

    let usuario;
    try {
      usuario = await verificarLogin((req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, ""));
    } catch (e) {
      return erro(401, "Entre com o Google no estúdio e tente de novo.");
    }
    const permitidos = String(env.EMAILS_PERMITIDOS || "").toLowerCase().split(",").map(x => x.trim()).filter(Boolean);
    if (!usuario.email_verified || !permitidos.includes(String(usuario.email || "").toLowerCase())) {
      return erro(403, "Essa conta do Google não tem permissão para usar a IA do estúdio.");
    }
    if (!env.ANTHROPIC_API_KEY) return erro(500, "Falta configurar a chave ANTHROPIC_API_KEY na Cloudflare.");

    let dados;
    try { dados = await req.json(); } catch { return erro(400, "Pedido inválido."); }
    const pedido = String(dados.pedido || "");
    if (!pedido.trim()) return erro(400, "O pedido está vazio.");
    if (pedido.length > 1_500_000) return erro(413, "O pedido está grande demais.");
    const modelo = MODELOS[dados.modelo] || MODELOS.sonnet;

    const resposta = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: modelo,
        max_tokens: MAX_SAIDA,
        stream: true,
        messages: [{ role: "user", content: pedido }],
      }),
    });
    if (!resposta.ok) {
      let msg = "";
      try { const j = await resposta.json(); msg = (j.error && j.error.message) || ""; } catch {}
      const dica = resposta.status === 401 ? " (a chave da API parece errada)"
        : resposta.status === 402 || /credit|billing|balance/i.test(msg) ? " (pode ser falta de crédito na conta da Anthropic)"
        : resposta.status === 429 ? " (muitos pedidos seguidos; espere um pouco)" : "";
      return erro(resposta.status, "A IA respondeu com erro" + dica + (msg ? ": " + msg : "."));
    }
    return new Response(resposta.body, {
      headers: cors({ "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache" }),
    });
  },
};
