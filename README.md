# DarkMSG

Password-protected, end-to-end encrypted messaging for **two people**, served as a static web app
from GitHub Pages. Built for iPhone Safari (add it to the Home Screen), 90's terminal aesthetic.

**Live:** https://th3n0id.github.io/DarkMSG/

## How to use

1. Agree on a **long shared passphrase** with your peer (5+ random words). It is the only secret.
2. Both open the app and enter the passphrase. The header shows `LISTENING` while it waits.
3. When both are online the SYN / SYN-ACK / ACK handshake completes and the header shows
   `LINK ESTABLISHED`. Only then can you send.
4. Tap `[≡]` to compare the **CHANNEL FP** fingerprint out loud. Same passphrase = same fingerprint.
5. On iPhone: Safari → Share → **Add to Home Screen** for a full-screen app.

## How it works

- **No server.** Messages are relayed through a public MQTT broker over secure WebSockets. The
  broker only ever sees random-looking ciphertext on a random-looking topic.
- **Key derivation.** Passphrase → PBKDF2-SHA256 (300k rounds) → HKDF → channel topic, a room key
  (handshake only), and a storage key (local history).
- **Handshake.** Each connection generates an ephemeral ECDH P-256 key pair. SYN and SYN/ACK carry
  the public keys encrypted under the room key; both sides derive a fresh AES-256-GCM session key.
  ACK is the first packet under that key. This gives forward secrecy per connection and proves the
  peer is live.
- **Presence.** Encrypted heartbeats every 15 s. 45 s of silence = `LINK LOST`, and the handshake
  restarts automatically. Closing the app fires an MQTT last-will so the peer sees the drop.
- **History.** Stored on each phone in `localStorage`, encrypted with the storage key, capped at
  500 messages. `WIPE HISTORY` in settings clears it.

## Limits (read this)

- **Both must be online.** The public broker does not store messages for an offline peer. If the
  link is down, sending is disabled.
- **Passphrase strength is everything.** Anyone can subscribe to the public broker and collect
  ciphertext, then try passphrases offline. Use a long one.
- **Anyone with the passphrase is a peer.** There is no identity beyond the shared secret. If the
  app reports more than one client ID active, one of you reconnected, or someone else has the code.
- **Public brokers are best-effort.** The app rotates through `broker.emqx.io`, `broker.hivemq.com`
  and `test.mosquitto.org`. Both phones must land on the same relay, so if things look stuck, set
  the same custom relay URL on both phones in settings.
- iOS suspends background tabs; the app re-dials and re-handshakes when brought back to the front.

## Files

`index.html`, `style.css`, `app.js` — the whole app, no build step. `manifest.webmanifest` and the
`icon-*.png` files make it installable. `.nojekyll` keeps GitHub Pages from processing the files.

## Deploy

GitHub → repo **Settings → Pages → Build and deployment → Source: Deploy from a branch → `main` /
`/ (root)`**. The repo must be public on a free plan.
