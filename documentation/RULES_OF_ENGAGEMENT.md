# Rules of Engagement (ROE)

Fill this in and keep it visible to your team **before** the event. TheStaff is a
detection-only, consent-based tool; this ROE is what keeps it ethical and lawful.

## 1. Authorization
- **Event / organizer:** _______________________________
- **Network owner authorization obtained from:** _______________________________
- **Date / time window of the engagement:** _______________________________

## 2. Scope
- **In scope:** devices that opt in by connecting to SSID `____________`
  on network `____________` (e.g. `192.168.50.0/24`), for the event window only.
- **Out of scope:** any device not on the challenge network; participants' personal
  accounts; the *content* of any network traffic; venue infrastructure you weren't
  authorized to touch.

## 3. Permitted techniques (detection only)
- Host discovery, port scanning, service/version detection, OS fingerprinting.
- CVE *identification* and **non-destructive** re-testing (port-open check, banner/version
  check, safe NSE detection scripts).

## 4. Prohibited
- **No exploitation.** No `exploit`/`dos`/`intrusive` NSE scripts, no `--script-args unsafe=1`,
  no password spraying / brute force, no traffic interception or MITM, no persistence.
- Any hands-on exploitation done *with* a participant is on **their** device, with **their**
  explicit agreement, and is not performed by TheStaff itself.

## 5. Consent
- The consent page (`/`) must be reachable and accurate. No deceptive captive-portal patterns,
  no pre-ticked boxes, and network access is **not** conditioned on opting in.
- Physical signage at the venue: *"This WiFi runs a security challenge — by connecting you
  agree to be scanned. Ask a host for details."*

## 6. Handling sensitive findings
- A critical finding (e.g. an actively exploitable service, or signs of an already-compromised
  device) → quietly notify the device owner immediately and prioritize helping them.
- Do not display or discuss a participant's findings with other participants.

## 7. Data
- Collected: IP, MAC/vendor, hostname, open ports, banners, likely CVEs, consent records.
- Retention: event duration only. Run the dashboard **Wipe** action and delete the `data/`
  volume afterward. Do not export or keep participant data.

## 8. Contacts
- **Lead / point of contact:** _______________________________
- **Support email shown to participants:** _______________________________

## 9. Anti-dark-pattern commitment
No impersonation, no fake "login/update" screens, plain language only, opt-out always available
(just disconnect), and findings framed as coaching — never shaming.
