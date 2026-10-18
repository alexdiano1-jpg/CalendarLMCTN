// Esegui UNA volta, loggandoti col master account, per ottenere MASTER_REFRESH_TOKEN.
const http = require('http');
const { google } = require('googleapis');
const c = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, 'http://localhost:4000');
console.log('Apri:\n' + c.generateAuthUrl({
  access_type: 'offline', prompt: 'consent',
  scope: ['https://www.googleapis.com/auth/calendar', 'https://www.googleapis.com/auth/drive'],
}));
http.createServer(async (req, res) => {
  const code = new URL(req.url, 'http://localhost:4000').searchParams.get('code');
  if (!code) return res.end('...');
  const { tokens } = await c.getToken(code);
  console.log('\nMASTER_REFRESH_TOKEN=' + tokens.refresh_token);
  res.end('Fatto, guarda il terminale.'); process.exit(0);
}).listen(4000);
