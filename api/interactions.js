// api/interactions.js — Vercel Node Serverless Function (no Next.js)
import nacl from 'tweetnacl';

const enc = new TextEncoder();
const fromHex = (hex) => Buffer.from(hex.replace(/^0x/, ''), 'hex');

export default async function handler(req, res) {
  try {
    const signature = req.headers['x-signature-ed25519'];
    const timestamp = req.headers['x-signature-timestamp'];
    const publicKeyHex = process.env.DISCORD_PUBLIC_KEY;

    if (!publicKeyHex) return res.status(500).send('missing DISCORD_PUBLIC_KEY');
    if (!signature || !timestamp) return res.status(401).send('missing signature headers');

    // Read RAW body (must verify BEFORE parsing)
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const bodyText = Buffer.concat(chunks).toString('utf8');

    const ok = nacl.sign.detached.verify(
      enc.encode(timestamp + bodyText),
      fromHex(signature),
      fromHex(publicKeyHex)
    );
    if (!ok) return res.status(401).send('bad signature');

    const json = JSON.parse(bodyText);

    // PING -> PONG
    if (json.type === 1) return res.status(200).json({ type: 1 });

    // Slash commands
    if (json.type === 2) {
      const name = json.data?.name;

      if (name === 'ping') {
        return res.status(200).json({ type: 4, data: { content: '🏓 Pong!' } });
      }

      if (name === 'say') {
        const text = json.data?.options?.find(o => o.name === 'text')?.value || '';
        return res.status(200).json({ type: 4, data: { content: text || 'Nothing to say 🤐' } });
      }

      if (name === 'help') {
        return res.status(200).json({ type: 4, data: { content: 'Commands: `/ping`, `/say <text>`, `/help`' } });
      }
    }

    res.status(400).send('unhandled');
  } catch (e) {
    res.status(500).send('internal error');
  }
}
