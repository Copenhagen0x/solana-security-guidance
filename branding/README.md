# Branding — generated demo asset

`sol-001-demo.html` is the **source** for the SOL-001 demo screenshot used on the README,
jelleo.com/guidance (hero + OG card), and the GitHub Marketplace listing (which renders the README).

## Regenerate (do this whenever the version or rule count changes)

```
chrome --headless=new --force-device-scale-factor=1 --window-size=1600,1000 \
  --virtual-time-budget=7000 --screenshot=sol-001-demo.png \
  file://$(pwd)/sol-001-demo.html
```

Then: copy `sol-001-demo.png` → `../assets/sol-001-demo.png` (this repo) and → the website's
`guidance-hero.png`. The 1200x630 OG card is the same PNG `object-fit:contain` on a #050504 page.

**Why this file exists:** the original demo image was a one-off PNG with no saved source, so it
silently went stale (shipped at v1.0.1 / 20 rules long after the standard reached 28). Keep the
footer (version + rule count) in sync here.
