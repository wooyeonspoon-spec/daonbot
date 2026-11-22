// 다온봇 토큰 중계 서버 (개발자만 운영). Client Secret 은 이 서버의 환경변수에만 둬요.
//  실행:  CLIENT_ID=... CLIENT_SECRET=... node relay.js
//  배포:  Render / Railway / Fly.io / 개인 VPS 어디든 OK (Node 18+). 반드시 https 로 서비스하세요.
//
//  v1.9.0 보안 보강
//   · 응답에 Cache-Control: no-store (토큰이 들어 있는 응답은 저장되면 안 돼요 - RFC 6749 §5.1)
//   · 진짜 접속자 IP 계산(X-Forwarded-For 위조 방지) + 전체 한도 + 같은 토큰 반복 호출 한도
//   · 스푼 서버로 보내는 요청에 시간 제한(멈춘 요청이 쌓여 서버가 죽는 것 방지)
//   · 값의 종류·길이 검사, 브라우저(Origin)에서 오는 호출 거절, 오류 내용에 서버 설정 값 노출 안 함
//   · 예상 못한 오류가 나도 서버가 죽지 않음
const http = require('http');
const crypto = require('crypto');
const { CLIENT_ID, CLIENT_SECRET } = process.env;
const REGION = (process.env.REGION || 'kr').toLowerCase();
if (!['kr', 'jp'].includes(REGION)) { console.error('REGION 은 kr 또는 jp 여야 해요.'); process.exit(1); }
const DEFAULT_REDIRECT = 'https://wooyeonspoon-spec.github.io/daonbot/connect/';
const REDIRECT_URI = process.env.REDIRECT_URI || DEFAULT_REDIRECT; // 앱이 쓰는 값과 같아야 해요
// 허용하는 redirect 주소 목록: Render 환경변수 값 + 현재 연결 화면 주소 (둘 중 하나와 같으면 통과)
const ALLOWED_REDIRECTS = new Set([REDIRECT_URI, DEFAULT_REDIRECT]);
const BASE = `https://${REGION}-openapi.spooncast.net`;
const READY = !!(CLIENT_ID && CLIENT_SECRET);
const VERSION = '1.9.1';
// 프록시(Render 등)가 몇 단계 앞에 있는지. 오른쪽에서 이 숫자번째 값이 '진짜 접속자'예요. (왼쪽 값은 접속자가 마음대로 적을 수 있어서 믿지 않아요)
const TRUST_PROXY_HOPS = Math.max(0, Number(process.env.TRUST_PROXY_HOPS ?? 1) || 0);
const UPSTREAM_TIMEOUT_MS = 20000;
const MAX_FIELD = 2048; // code / refresh_token / token 최대 길이
if (!READY) console.error('⚠️ CLIENT_ID / CLIENT_SECRET 환경변수가 없어요. Render > Environment 에서 넣어 주세요. (서버는 켜 두고 /health 는 응답해요)');
const AUTH = READY ? 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64') : '';

// ---------- 속도 제한 (메모리, 1분 단위) ----------
const perIp = new Map(), perToken = new Map(); let globalHits = 0;
const LIMIT_IP = 30, LIMIT_TOKEN = 12, LIMIT_GLOBAL = Number(process.env.GLOBAL_LIMIT_PER_MIN) || 600;
setInterval(() => { perIp.clear(); perToken.clear(); globalHits = 0; }, 60000).unref();
const bump = (map, key) => { const n = (map.get(key) || 0) + 1; map.set(key, n); return n; };
function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (TRUST_PROXY_HOPS > 0 && xff.length >= TRUST_PROXY_HOPS) return xff[xff.length - TRUST_PROXY_HOPS];
  return req.socket.remoteAddress || 'unknown';
}
const tokenKey = (s) => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 16); // 토큰 원문은 메모리에도 남기지 않아요

const HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', Pragma: 'no-cache', 'X-Content-Type-Options': 'nosniff' };
const isStr = (v, max = MAX_FIELD) => typeof v === 'string' && v.length > 0 && v.length <= max;

async function upstream(path, form) { // 스푼 서버로 전달 (Client Secret 은 여기서만 붙여요)
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST', redirect: 'error',
    headers: { Authorization: AUTH, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(), signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  return { status: r.status, text: await r.text() };
}

const server = http.createServer(async (req, res) => {
  const send = (c, o) => { res.writeHead(c, HEADERS); res.end(JSON.stringify(o)); };
  try {
    if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) return send(200, { ok: true, ready: READY, version: VERSION });
    if (!READY) return send(500, { error: 'server not configured' });
    if (req.method !== 'POST' || (req.url !== '/token' && req.url !== '/revoke')) return send(404, {});
    if (req.headers.origin) return send(403, { error: 'forbidden' }); // 다온봇 앱(Node)은 Origin 헤더를 보내지 않아요. 웹페이지에서 부르는 건 막아요.
    const ip = clientIp(req);
    if (++globalHits > LIMIT_GLOBAL || bump(perIp, ip) > LIMIT_IP) return send(429, { error: 'too many requests' });

    let body = '';
    for await (const c of req) { body += c; if (body.length > 4096) return send(413, {}); }
    let p; try { p = JSON.parse(body); } catch { return send(400, { error: 'bad request', reason: 'json' }); }
    if (!p || typeof p !== 'object' || Array.isArray(p)) return send(400, { error: 'bad request', reason: 'json' });

    if (req.url === '/revoke') { // 로그아웃할 때 앱이 보내요: 발급된 출입증을 무효로 만들어요 (스푼 POST /v1/oauth/revoke)
      if (!isStr(p.token)) return send(400, { error: 'bad request', reason: 'no_token' });
      if (bump(perToken, tokenKey(p.token)) > LIMIT_TOKEN) return send(429, { error: 'too many requests' });
      const r = await upstream('/v1/oauth/revoke', new URLSearchParams({ token: p.token }));
      res.writeHead(r.status, HEADERS); return res.end(r.text);
    }

    const form = new URLSearchParams();
    if (p.grant_type === 'authorization_code' && isStr(p.code) && isStr(p.redirect_uri, 300) && ALLOWED_REDIRECTS.has(p.redirect_uri)) {
      if (bump(perToken, tokenKey(p.code)) > 3) return send(429, { error: 'too many requests' }); // code 는 한 번만 써야 해요. 같은 code 로 계속 부르면 스푼이 그 연동의 토큰을 전부 폐기해요.
      form.set('grant_type', 'authorization_code'); form.set('code', p.code); form.set('redirect_uri', p.redirect_uri);
    } else if (p.grant_type === 'refresh_token' && isStr(p.refresh_token)) {
      if (bump(perToken, tokenKey(p.refresh_token)) > LIMIT_TOKEN) return send(429, { error: 'too many requests' });
      form.set('grant_type', 'refresh_token'); form.set('refresh_token', p.refresh_token);
    } else {
      // 이 두 가지 외에는 중계하지 않아요. 원인을 알 수 있게 reason 은 보내되, 서버 설정 값은 알려 주지 않아요.
      const reason = p.grant_type === 'authorization_code'
        ? (!isStr(p.code) ? 'no_code' : 'redirect_mismatch')
        : (p.grant_type === 'refresh_token' ? 'no_refresh_token' : 'bad_grant_type');
      return send(400, { error: 'bad request', reason });
    }
    const r = await upstream('/v1/oauth/token', form);
    res.writeHead(r.status, HEADERS); res.end(r.text);
  } catch (e) {
    if (!res.headersSent) send(502, { error: 'upstream error' }); else try { res.end(); } catch {}
  }
});
server.headersTimeout = 10000; server.requestTimeout = 15000; server.keepAliveTimeout = 5000; // 느리게 보내서 연결을 붙잡아 두는 공격 방지
process.on('uncaughtException', (e) => console.error('uncaught:', e && e.message));
process.on('unhandledRejection', (e) => console.error('unhandled:', e && e.message));
server.listen(process.env.PORT || 8080, '0.0.0.0', () => console.log('relay on', process.env.PORT || 8080, 'v' + VERSION));
