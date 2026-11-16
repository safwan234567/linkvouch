# LinkGuard

[![CI](https://github.com/safwan234567/linkguard/actions/workflows/ci.yml/badge.svg)](https://github.com/safwan234567/linkguard/actions/workflows/ci.yml)

An MCP connector that lets Claude (or any MCP client) check links, scam messages, "official" websites and software packages **before** recommending them.

It was built for one problem in particular: **AI-recommendation poisoning**. Attackers plant content so that AI assistants recommend their fake login pages, fake support numbers, or malicious packages with invented names ("slopsquatting"). LinkGuard gives the assistant a way to check first.

> Status: early version (0.1). Heuristics, not a guarantee. See [Limits](#limits).

## Tools

| Tool | What it does |
|---|---|
| `vet_ai_recommendation` | Run before an assistant presents a link, package or support phone number. Confirms a link really belongs to the brand it claims, checks packages, and refuses to vouch for phone numbers. |
| `check_link` | Look-alike and typo domains (`paypa1…`), look-alike letters from other alphabets (`аpple.com`), the real domain used as a subdomain (`dbs.com.sg.evil.xyz`), the `@` trick, raw IP links, link shorteners, redirects, and domain age (via RDAP). Accepts defanged links (`hxxp://`, `[.]`). |
| `check_message` | Scam patterns in an SMS, email or chat (urgency, OTP or card requests, threats, prizes, payment requests) plus a check of every link. Includes Singapore rules: banks there do not send clickable links, and government links live on `.gov.sg`. |
| `verify_official_site` | Finds an organisation's official domain from a built-in brand list and Wikidata, and says whether a URL matches it. |
| `check_package` | npm and PyPI: does the package exist at all, is the name a near-typo of a popular package, how old is it, how many downloads, does it run install scripts. |

Every result has a `verdict` (`high_risk`, `suspicious`, `no_red_flags`, `known_official_domain`), a list of plain-language `findings`, and `advice`.

## Run it

Needs Node.js 24 or newer (it runs the TypeScript files directly, no build step).

```bash
npm install
```

```bash
npm test
```

`npm test` runs the offline tests and then the end-to-end tests, which need internet. `npm run test:unit` runs only the offline ones. `npm run typecheck` checks the TypeScript types. GitHub Actions runs all three on every push and pull request.

**Local (Claude Code / Claude Desktop):** the client starts the server itself.

```bash
claude mcp add linkguard -- node /absolute/path/to/linkguard/src/stdio.ts
```

**Hosted (Claude custom connector):** run the HTTP server somewhere public with HTTPS.

```bash
npm start
```

The endpoint is `POST /mcp` (stateless Streamable HTTP). On Render, Railway or Fly.io, set the start command to `npm start`; the server reads `PORT`. Then in Claude: Settings → Connectors → Add custom connector → `https://your-host/mcp`.

Optional environment variables:

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (default 3000) |
| `RATE_LIMIT_PER_MIN` | Requests per client IP per minute (default 60) |
| `LINKGUARD_CONTACT` | A URL added to the client name sent to public APIs (Wikimedia asks for this) |
| `GSB_API_KEY` | Google Safe Browsing key, adds a blocklist check. The Safe Browsing API is for non-commercial use; use Google's Web Risk API for a paid service. |

## How it stays safe itself

A tool that fetches user-supplied URLs is a classic target, so:

- **No internal requests (SSRF):** every hop of every redirect is resolved and refused if it points at a private, loopback, link-local, CGNAT or cloud-metadata address. Only `http`/`https` on ports 80, 443, 8080, 8443.
- **Pinned addresses (DNS rebinding):** each hop's name is looked up once, and the connection goes to exactly the address that was checked. A DNS server cannot answer "public" for the check and "internal" for the request.
- **No page content:** only the status code and `Location` header are read. Bodies are discarded.
- **Bounded:** 6-second timeouts, at most 5 redirects, at most 5 links per message, input length limits.
- **No storage:** nothing about requests is saved or logged. Rate limiting is in memory.
- **Read-only tools:** all tools are marked read-only.

## Limits

Please read these before relying on it.

- **`no_red_flags` is not "safe".** A brand-new scam on a clean-looking domain can pass every check.
- The brand list is short (about 35 brands, weighted to Singapore). Brands outside it get fewer checks.
- Companies own domains that are not in the list or on Wikidata, so `mismatch` means "not confirmed", not "definitely fake". Expect some false alarms, e.g. a legitimate site whose name contains a brand name.
- Wikidata is community-edited and name searches can return a different organisation with a similar name.
- Domain age is unavailable for registries without RDAP (including `.sg`).
- Package checks read registry metadata only. The code inside a package is not scanned.
- Links on unusual ports are not contacted at all (reported as `unusual_port`), so redirects and reachability are unknown for them.
- The hosted mode has no authentication yet. Anyone with the URL can use it (within the rate limit).

## Roadmap

- Larger, community-maintained brand list
- More ecosystems (crates.io, Go modules, Docker Hub) and browser-extension IDs
- OAuth and usage tiers for the hosted version
- A plain web page for people who do not use an MCP client

## Responsible use

LinkGuard only looks at public information (DNS, RDAP, HTTP status, public registries). Do not point it at systems you have no reason to check, and report real scams to the proper channel (in Singapore: ScamShield, 1799).

## Licence

MIT. See [LICENSE](LICENSE).
