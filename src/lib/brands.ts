// Brands that phishers commonly impersonate, with their real domains.
// Deliberately includes Singapore banks and government services.
export type Brand = { name: string; domains: string[]; keywords: string[] };

export const BRANDS: Brand[] = [
  { name: 'PayPal', domains: ['paypal.com', 'paypal.me'], keywords: ['paypal'] },
  { name: 'Google', domains: ['google.com', 'google.com.sg', 'gmail.com', 'youtube.com', 'goo.gl', 'google.dev'], keywords: ['google', 'gmail'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com', 'office365.com', 'azure.com'], keywords: ['microsoft', 'outlook', 'office365'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com'], keywords: ['apple', 'icloud'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.sg', 'amazon.co.uk', 'amazon.com.au', 'aws.amazon.com', 'amazonaws.com'], keywords: ['amazon'] },
  { name: 'Facebook', domains: ['facebook.com', 'fb.com', 'meta.com', 'messenger.com'], keywords: ['facebook'] },
  { name: 'Instagram', domains: ['instagram.com'], keywords: ['instagram'] },
  { name: 'WhatsApp', domains: ['whatsapp.com', 'wa.me'], keywords: ['whatsapp'] },
  { name: 'Netflix', domains: ['netflix.com'], keywords: ['netflix'] },
  { name: 'LinkedIn', domains: ['linkedin.com'], keywords: ['linkedin'] },
  { name: 'TikTok', domains: ['tiktok.com'], keywords: ['tiktok'] },
  { name: 'Telegram', domains: ['telegram.org', 't.me'], keywords: ['telegram'] },
  { name: 'Discord', domains: ['discord.com', 'discord.gg', 'discordapp.com'], keywords: ['discord'] },
  { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'], keywords: ['steam', 'steamcommunity', 'steampowered'] },
  { name: 'Roblox', domains: ['roblox.com'], keywords: ['roblox'] },
  { name: 'GitHub', domains: ['github.com', 'github.io', 'githubusercontent.com'], keywords: ['github'] },
  { name: 'OpenAI / ChatGPT', domains: ['openai.com', 'chatgpt.com'], keywords: ['openai', 'chatgpt'] },
  { name: 'Anthropic / Claude', domains: ['anthropic.com', 'claude.ai', 'claude.com'], keywords: ['anthropic', 'claude'] },
  { name: 'Binance', domains: ['binance.com'], keywords: ['binance'] },
  { name: 'Coinbase', domains: ['coinbase.com'], keywords: ['coinbase'] },
  { name: 'MetaMask', domains: ['metamask.io'], keywords: ['metamask'] },
  { name: 'DHL', domains: ['dhl.com'], keywords: ['dhl'] },
  { name: 'FedEx', domains: ['fedex.com'], keywords: ['fedex'] },
  // Singapore
  { name: 'DBS Bank', domains: ['dbs.com.sg', 'dbs.com', 'dbsbank.com'], keywords: ['dbs', 'dbsbank'] },
  { name: 'POSB', domains: ['posb.com.sg'], keywords: ['posb'] },
  { name: 'OCBC', domains: ['ocbc.com', 'ocbc.com.sg'], keywords: ['ocbc'] },
  { name: 'UOB', domains: ['uob.com.sg', 'uobgroup.com'], keywords: ['uob'] },
  { name: 'Singpass', domains: ['singpass.gov.sg'], keywords: ['singpass'] },
  { name: 'SingPost', domains: ['singpost.com'], keywords: ['singpost'] },
  { name: 'CPF Board', domains: ['cpf.gov.sg'], keywords: ['cpf'] },
  { name: 'IRAS', domains: ['iras.gov.sg'], keywords: ['iras'] },
  { name: 'Shopee', domains: ['shopee.sg', 'shopee.com', 'shopee.com.my', 'shopee.co.id'], keywords: ['shopee'] },
  { name: 'Lazada', domains: ['lazada.sg', 'lazada.com', 'lazada.com.my'], keywords: ['lazada'] },
  { name: 'Grab', domains: ['grab.com'], keywords: ['grab'] },
  { name: 'Singtel', domains: ['singtel.com'], keywords: ['singtel'] },
];

export const SG_BANK_WORDS = ['dbs', 'posb', 'ocbc', 'uob', 'citibank', 'hsbc', 'standard chartered', 'maybank', 'trust bank', 'gxs'];
export const SG_GOV_WORDS = ['singpass', 'cpf', 'iras', 'ica', 'mom', 'moh', 'lta', 'hdb', 'spf', 'police', 'gov.sg', 'govt', 'government'];

export const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'shorturl.at', 's.id', 'tiny.cc', 'rb.gy', 'buff.ly', 't.ly']);
export const RISKY_TLDS = new Set(['xyz', 'top', 'click', 'icu', 'cfd', 'sbs', 'rest', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'kim', 'work', 'quest', 'monster', 'lol']);

export function findBrandByName(name: string): Brand | undefined {
  const n = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  return BRANDS.find((b) => b.name.toLowerCase().replace(/[^a-z0-9]/g, '') === n || b.keywords.includes(n) ||
    b.name.toLowerCase().split(/\s*\/\s*|\s+/).some((w) => w.replace(/[^a-z0-9]/g, '') === n && n.length >= 3));
}
export function brandForDomain(domain: string): Brand | undefined {
  return BRANDS.find((b) => b.domains.includes(domain));
}
