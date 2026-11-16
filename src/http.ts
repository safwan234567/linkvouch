// Hosted mode: a stateless Streamable HTTP MCP endpoint at POST /mcp (what Claude's custom connectors use).
import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.ts';

/** Reads a whole-number setting from the environment, falling back when it is missing or not a sensible number. */
const envInt = (name: string, fallback: number, min = 0): number => {
  const n = Number(process.env[name]);
  return process.env[name] && Number.isInteger(n) && n >= min ? n : fallback;
};

const PORT = envInt('PORT', 3000, 1);
const LIMIT_PER_MIN = envInt('RATE_LIMIT_PER_MIN', 60, 1);
const REQUEST_TIMEOUT_MS = envInt('REQUEST_TIMEOUT_MS', 30_000, 1);
// How many reverse proxies sit in front of the server. This decides which address counts as "the client"
// for rate limiting. Too low: every user shares one limit. Too high: a client can fake its address.
const TRUST_PROXY_HOPS = envInt('TRUST_PROXY_HOPS', 1);
const MAX_TRACKED_CLIENTS = 10_000;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', TRUST_PROXY_HOPS);
app.use(express.json({ limit: '100kb' }));

// Small in-memory rate limit per client IP. Nothing about requests is stored or logged.
const hits = new Map<string, { n: number; reset: number }>();
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, 60_000).unref();
app.use('/mcp', (req, res, next) => {
  const ip = req.ip ?? 'unknown', now = Date.now();
  const h = hits.get(ip);
  if (!h || h.reset < now) {
    if (hits.size >= MAX_TRACKED_CLIENTS) hits.clear(); // keep memory bounded under a flood of addresses
    hits.set(ip, { n: 1, reset: now + 60_000 });
  } else if (++h.n > LIMIT_PER_MIN) { res.status(429).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Rate limit exceeded. Try again in a minute.' }, id: null }); return; }
  next();
});

app.post('/mcp', async (req, res) => {
  const server = createServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  // Upper limit on one request, so a slow check cannot hold a connection open indefinitely.
  const deadline = setTimeout(() => {
    if (!res.headersSent) res.status(504).json({ jsonrpc: '2.0', error: { code: -32000, message: 'The check took too long. Try again.' }, id: null });
  }, REQUEST_TIMEOUT_MS);
  res.on('close', () => { clearTimeout(deadline); transport.close(); server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error('request failed:', e instanceof Error ? e.message : e);
    if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
  }
});
const notAllowed = (_req: express.Request, res: express.Response) => { res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed. Use POST.' }, id: null }); };
app.get('/mcp', notAllowed);
app.delete('/mcp', notAllowed);

app.get('/', (_req, res) => { res.type('text/plain').send('LinkVouch MCP server. Connect an MCP client to POST /mcp.\n'); });
app.get('/healthz', (_req, res) => { res.json({ ok: true }); });

const listener = app.listen(PORT, () => console.log(`LinkVouch listening on http://localhost:${PORT}/mcp`));

// Hosts send SIGTERM before replacing the server on a new deploy: finish open requests, then exit.
process.on('SIGTERM', () => { listener.close(() => process.exit(0)); setTimeout(() => process.exit(0), 10_000).unref(); });
