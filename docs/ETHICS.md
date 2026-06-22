# Ethics, Consent & Authorized Use

`TheStaff` is a **consent-based, educational** security-awareness game for physical
dev/maker events (meetups, hackathons, game jams). It scans the devices of people who
**knowingly opt in** by joining a clearly-labelled challenge WiFi, and the goal is to help
each participant **improve the security posture of their own device**, coached by the
organizing team.

This tool is **not** a covert surveillance tool and must never be used as one.

## The rules (non-negotiable)

1. **Scan only your own dedicated event network.** Never point TheStaff at a network
   you do not own/operate, or at devices whose owners have not opted in.
2. **Explicit, informed consent.** Participants must be told — before they connect — that:
   - the network scans connected devices as part of a security game,
   - what is collected (IP, hostname, open ports, service/version, likely CVEs),
   - how to opt out (don't connect / disconnect / ask the team to remove their card),
   - that the team will coach them through fixing or knowingly accepting findings.
   The bundled **consent landing page** (route `/`) states this in plain language. It is an
   honest opt-in screen, **not** a deceptive captive portal.

   **Headless / IoT devices** (smart plugs, cameras, printers, TVs) can't show that page. For
   them, consent is the **WiFi password** itself (`THESTAFF_CONSENT_MODE=wifi`): you only
   hand out the password *after* informing people (signage + briefing) that joining means being
   scanned, so connecting a device is the consenting act. Whoever connects a device must be
   authorized to do so. See `docs/CONSENT.md` for the consent modes.
3. **Non-destructive by default.** Discovery, version detection, and CVE *re-testing* use
   light, non-exploitative checks (is the port open? does the banner still show the
   vulnerable version?). TheStaff does **not** run exploits or denial-of-service against
   guests. Any hands-on exploitation a team does with a participant is done **together, with
   that participant, on their own device, with their agreement.**
4. **Minimize and forget.** Data lives only for the event. Provide a "wipe" action and delete
   the database afterward. Don't export or retain participant data.
5. **No shaming.** Findings are coaching opportunities. "Accepted" (blue) is a legitimate,
   respected end-state — a participant may knowingly accept a risk.
6. **Signage.** Put physical signs at the venue: "This WiFi runs a security challenge — by
   connecting you agree to be scanned. Ask a host for details."

## Legal note

Network scanning law varies by jurisdiction. Running TheStaff against your **own**
event network with **participant consent** is the intended, defensible use. You are
responsible for ensuring your use is lawful where your event takes place. When in doubt,
get written authorization from the venue/organizers and keep consent visible.

## State colors (what they mean for a participant)

- 🔴 **Red — Open:** a finding is present and not yet addressed.
- 🟢 **Green — Solved:** the participant closed/patched it (verified by the healthcheck loop).
- 🔵 **Blue — Accepted:** the participant understands the finding and *chose* to accept it.
  This is a valid outcome, recorded with their acknowledgement.
