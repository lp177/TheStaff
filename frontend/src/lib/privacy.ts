/** Mask the last two octets of an IPv4 (or trailing groups of an IPv6) when
 *  privacy mode is on — e.g. 192.168.1.50 → 192.168.x.x. Pure: callers pass the
 *  current privacy flag. Returns "" for empty input so callers can `|| fallback`. */
export function maskIp(ip: string | null | undefined, enabled: boolean): string {
  const v = (ip ?? "").trim();
  if (!v) return "";
  if (!enabled) return v;
  const m4 = v.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (m4) return `${m4[1]}.${m4[2]}.x.x`;
  if (v.includes(":")) {
    const groups = v.split(":").filter(Boolean);
    if (groups.length > 2) return `${groups[0]}:${groups[1]}:x`;
  }
  return v;
}
