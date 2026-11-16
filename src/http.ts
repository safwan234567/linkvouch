// Hosted mode: a stateless Streamable HTTP MCP endpoint at POST /mcp (what Claude's custom connectors use).
import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.ts';

const PORT = Number(process.env.PORT ?? 3000);
const LIMIT_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN ?? 60);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // one reverse proxy (Render/Railway/Fly) in front
app.use(express.json({ limit: '100kb' }));

// Small in-memory rate limit per client IP. Nothing about requests is stored or logged.
const hits = new Map<string, { n: number; reset: number }>();
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, 60_000).unref();
app.use('/mcp', (req, res, next) => {
  const ip = req.ip ?? 'unknown', now = Date.now();
  const h = hits.get(ip);
  if (!h || h.reset < now) hits.set(ip, { n: 1, reset: now + 60_000 });
  else if (++h.n > LIMIT_PER_MIN) { res.status(429).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Rate limit exceeded. Try again in a minute.' }, id: null }); return; }
  next();
});

app.post('/mcp', async (req, res) => {
  const server = createServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on('close', () => { transport.close(); server.close(); });
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

app.listen(PORT, () => console.log(`LinkVouch listening on http://localhost:${PORT}/mcp`));
