# Consent

The consent page lives at the app root (`/`, `frontend/src/views/ConsentPage.vue`) and is
populated from `GET /api/consent` (mode, organizer name, support email, SSID, event name,
scanned CIDR). It is an **honest opt-in screen — explicitly the opposite of a deceptive captive
portal.**

## Consent modes (`THESTAFF_CONSENT_MODE`)

Not every device can open a web page — smart plugs, cameras, printers, TVs and other
headless/IoT gear have no browser. TheStaff therefore supports two consent bases:

- **`wifi` (default) — WiFi-password = consent.** Consent is established **out-of-band**:
  before anyone gets the password, the organizer informs them (venue **signage** + a verbal
  briefing) that *connecting any device to this network means it may be scanned for the
  challenge.* Possessing/using the password is the affirmative act. Headless/IoT devices are
  enrolled simply by being connected — the web page becomes purely **informational** (it still
  explains scope, data, and how to opt out by disconnecting). This is the right mode for
  testing IoT devices that can't show or accept an on-screen prompt.

- **`http` — per-device on-screen opt-in.** The page shows an unchecked consent checkbox that
  gates a "Join" button; only meaningful for devices with a browser.

**Ethical requirement for `wifi` mode:** the WiFi password must only be shared *after* people
are informed, so possession genuinely implies *informed* consent. The whole point is honesty —
signage + briefing are mandatory, not optional. For a device someone else owns, the person who
connects it (and had the password) is consenting on its behalf; only connect devices you're
authorized to.

## What the page must (and does) contain

1. **Plain header, organizer named** — "an opt-in security-awareness challenge by
   {organizer}", with no fake login/update chrome.
2. **What we do** — port scanning + version detection to find open ports, outdated software,
   and misconfigurations; **detection only**, no exploitation, no reading files/traffic.
3. **Scope** — in: devices on the challenge SSID/CIDR during the event; out: personal
   accounts, traffic content, off-network devices.
4. **Data handling** — what's collected, retained until event end then deleted, legal basis =
   explicit opt-in consent.
5. **Affirmative control** — an *unchecked* consent checkbox gating a "Join the challenge"
   button, with an equally prominent "Connect without joining" path. Access is never
   conditioned on consent.
6. **Opt out / withdraw** — disconnect any time; email the organizer to be removed mid-event.
7. **Accountability** — named organizer + support email.

## Principles (see also `ETHICS.md`)

- Prior, specific, affirmative, freely-given consent.
- No impersonation, no pre-ticked boxes, no coercion.
- Data minimization and deletion after the event.
- Findings are coaching opportunities; "accepted" (🔵) is a respected outcome.

## Records

Each opt-in is logged to the `ConsentRecord` table (timestamp, client IP, user agent) purely
to show an aggregate opt-in count and demonstrate that consent was collected. Wipe it with the
rest of the data at the end of the event.
