export type State = "open" | "solved" | "accepted";
export type WorstState = State | "clean";

export interface Cve {
  id: number;
  cve_id: string;
  cvss: number | null;
  severity: "critical" | "high" | "medium" | "low" | "none" | "unknown";
  summary: string | null;
  references: string[];
  is_exploit: boolean;
  category: string | null;
  fixed_version: string | null;
  source: string | null;
  state: State;
  first_seen: string | null;
  last_seen: string | null;
}

export interface Port {
  id: number;
  number: number;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
  cpe: string | null;
  state: State;
  cves: Cve[];
}

export interface Host {
  id: number;
  ip: string;
  mac: string | null;
  vendor: string | null;
  hostname: string | null;
  device_type: string;
  os_family: string | null;
  os_accuracy: number;
  manual?: boolean;
  state: State;
  worst_state: WorstState;
  counts: { open: number; solved: number; accepted: number; cve_open: number };
  first_seen: string | null;
  last_seen: string | null;
  ports: Port[];
}

export interface Snapshot {
  type: "snapshot";
  rev: number;
  hosts: Host[];
}

export interface TestCommand {
  tier: number;
  label: string;
  command: string;
}

export interface HealthcheckAttempt {
  tier: number;
  command: string;
  output: string;
  result: string;
}

export interface HealthcheckOutcome {
  result: string;
  tier: number;
  attempts: HealthcheckAttempt[];
}

export interface CveDetail extends Cve {
  host_ip: string | null;
  host_id: number | null;
  port: {
    id: number;
    number: number;
    protocol: string;
    service: string | null;
    product: string | null;
    version: string | null;
    cpe: string | null;
  } | null;
  test_commands: TestCommand[];
  remediation: string[];
}

export interface Status {
  mode: string;
  nmap_available: boolean;
  target_cidr: string;
  scan_interval_min: number;
  ws_clients: number;
  rev: number;
  event: string;
  organizer: string;
  public_ip: string | null;
}
