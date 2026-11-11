# Aral Proxy

**Aral Proxy** — پنل پروکسی تلگرام (WEB) برای Cloudflare Workers، با رابط کاربری ارگانیک و پریمیوم (سبز ماچا · مرجانی · کرم).

Telegram WEB proxy for Cloudflare Workers — single-file deploy, zero cost, premium organic UI (matcha green `#328073` · coral `#D9826B` · cream `#F7F1E8` · dark brown `#3B3028`).

<p dir="rtl">
سریع‌ترین راه راه‌اندازی: فایل <code>worker.js</code> را در یک Cloudflare Worker قرار دهید، متغیر <code>ADMIN_KEY</code> را بسازید و پنل شما با لینک‌های آماده تلگرام در <code>/&lt;ADMIN_KEY&gt;</code> آماده است.
</p>

## ✨ Features

- 🚀 **One-file deploy** — paste `worker.js` into a Cloudflare Worker, no build step, no dashboard bindings, runs on the Free plan
- 🔗 **Six Telegram HTTPS ports** (443, 2053, 2083, 2087, 2096, 8443) — each port with its **own unique secret** and one-tap `tg://webproxy` connect links
- 📊 **Live status & logs** at `/<ADMIN_KEY>/status` — sessions, streams, traffic counters, recent events + on-demand Telegram DC reachability probe (`?probe=1`)
- 🎭 **Anti-censorship camouflage** — the public site (`/`) looks like a normal fashion storefront (ARAL Studio), resisting active probing
- 🌐 **Bilingual panel** (English / فارسی) — pure CSS language toggle, no JavaScript, no tracking
- 🖥️ **ARAL design language** — glass panels, cut-corner cards, glitch headline, mono badges, boot preloader, marquee watermark strip

## 🚀 Quick start

1. Create a Cloudflare Worker and paste the contents of `worker.js`. Deploy.
2. Worker → **Settings** → **Variables and Secrets** → add one variable:
   - Name: `ADMIN_KEY` — Value: a long random password (16+ letters/digits)
3. Open `https://<your-domain>/<ADMIN_KEY>` → your panel with ready Telegram links for every port.
4. Open `https://<your-domain>/<ADMIN_KEY>/status` → live statistics and DC probe.

Optional variables:

| Variable | Purpose |
| --- | --- |
| `SECRET` | Fixed 32-hex secret — set it to keep links stable even if you change `ADMIN_KEY` |
| `EXTRA_HOSTS` | Other hostnames attached to this worker, comma separated |
| `AD_TAG` | 32-hex sponsored-channel tag (ignored in Direct-DC mode) |
| `DECOY_URL` | Serve a different camouflage site from `/` |

> **Tip:** `workers.dev` addresses are often filtered — attach a custom domain to the worker for best results.

## 🪪 Brand & watermarks

- Telegram: [t.me/AralDev](https://t.me/AralDev)
- YouTube: [youtube.com/@Aral-Dev](https://youtube.com/@Aral-Dev)
- GitHub: [github.com/Aral-Dev](https://github.com/Aral-Dev)

All three are embedded in the panel chrome (topbar icons, marquee strip, footer cards) on every admin page.

## 📁 Project layout

```
worker.js   ← the whole thing (panel + proxy engine, ES module)
docs/       ← upstream architecture documentation
LICENSE     ← MIT
```

## 🙏 Credits

Upstream engine: **ProxyGosha** by Amir Marandi (MIT) — the proxy/protocol core (Direct-DC transport, Obfuscated2, session tokens) is unchanged. This fork ("Aral Proxy" v2.0.0-aral) rebrands the admin panel UI and restyles it with the green & coral organic palette.

---

© 2026 Aral Dev · [t.me/AralDev](https://t.me/AralDev)
