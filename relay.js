// 다온봇 토큰 중계 서버 (개발자만 운영). Client Secret 은 이 서버의 환경변수에만 둬요.
//  실행:  CLIENT_ID=... CLIENT_SECRET=... node relay.js
//  배포:  Render / Railway / Fly.io / 개인 VPS 어디든 OK (Node 18+). 반드시 https 로 서비스하세요.
const http = require('http');
const { CLIENT_ID, CLIENT_SECRET } = process.env;
const REGION = process.env.REGION || 'kr';
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3000/callback'; // 앱이 쓰는 값과 같아야 해요
const BASE = `https://${REGION}-openapi.spooncast.net`;
const READY = !!(CLIENT_ID && CLIENT_SECRET);
if (!READY) console.error('⚠️ CLIENT_ID / CLIENT_SECRET 환경변수가 없어요. Render > Environment 에서 넣어 주세요. (서버는 켜 두고 /health 는 응답해요)');

const hits = new Map(); // 아주 단순한 속도 제한: IP당 1분 30회
setInterval(() => hits.clear(), 60000).unref();

http.createServer(async (req, res) => {
  const send = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) return send(200, { ok: true, ready: READY });
  if (!READY) return send(500, { error: 'server not configured' });
  if (req.method !== 'POST' || req.url !== '/token') return send(404, {});
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  hits.set(ip, (hits.get(ip) || 0) + 1);
  if (hits.get(ip) > 30) return send(429, { error: 'too many requests' });
  let body = ''; for await (const c of req) { body += c; if (body.length > 4096) return send(413, {}); }
  let p; try { p = JSON.parse(body); } catch { return send(400, {}); }
  const form = new URLSearchParams();
  if (p.grant_type === 'authorization_code' && p.code && p.redirect_uri === REDIRECT_URI) {
    form.set('grant_type', 'authorization_code'); form.set('code', String(p.code)); form.set('redirect_uri', REDIRECT_URI);
  } else if (p.grant_type === 'refresh_token' && p.refresh_token) {
    form.set('grant_type', 'refresh_token'); form.set('refresh_token', String(p.refresh_token));
  } else return send(400, { error: 'bad request' }); // 이 두 가지 외에는 중계하지 않아요
  try {
    const r = await fetch(`${BASE}/v1/oauth/token`, { method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString() });
    res.writeHead(r.status, { 'Content-Type': 'application/json' }); res.end(await r.text());
  } catch (e) { send(502, { error: 'upstream error' }); }
}).listen(process.env.PORT || 8080, '0.0.0.0', () => console.log('relay on', process.env.PORT || 8080));
