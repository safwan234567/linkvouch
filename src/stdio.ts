// Local mode: Claude Desktop / Claude Code start this process and talk to it over stdin/stdout.
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.ts';

await createServer().connect(new StdioServerTransport());
