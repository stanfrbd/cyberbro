export interface EngineResult {
  [key: string]: unknown;
}
export interface ObservableResult {
  observable: string;
  type: string;
  [key: string]: unknown;
}
export interface Bootstrap {
  apiPrefix: string;
  engines: string[];
  enabledEngines: string[];
}
declare global {
  interface Window {
    CYBERBRO_CONFIG?: Bootstrap;
  }
}
export const engineNames: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  rdap_whois: "RDAP / Whois",
  reverse_dns: "Reverse DNS",
  threatfox: "ThreatFox",
  ipinfo: "IPinfo",
  mde: "Microsoft Defender",
  crowdstrike: "CrowdStrike",
  opencti: "OpenCTI",
  bad_asn: "Bad ASN",
  google_dns: "Google DNS",
  urlscan: "URLscan",
};
export function engineLabel(key: string): string {
  return (
    engineNames[key] ??
    key.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase())
  );
}
export function asRecord(value: unknown): EngineResult | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as EngineResult)
    : null;
}
const metadata = new Set(["observable", "type", "reversed_success"]);
export function engineEntries(
  row: ObservableResult,
): [string, EngineResult | null][] {
  return Object.entries(row)
    .filter(([key]) => !metadata.has(key))
    .map(([key, value]) => [key, asRecord(value)])
    .filter(([, value]) => value === null || Object.keys(value).length > 0) as [
    string,
    EngineResult | null,
  ][];
}
export type Signal = "signals" | "no-detections" | "unavailable";
export function signal(row: ObservableResult): Signal {
  const vt = asRecord(row.virustotal);
  const abuse = asRecord(row.abuseipdb);
  // These are source signals, never a combined risk score or a safety verdict.
  if (
    Number(vt?.total_malicious) > 0 ||
    Number(abuse?.abuseConfidenceScore) > 0
  )
    return "signals";
  if (typeof vt?.total_malicious === "number" && vt.total_malicious === 0)
    return "no-detections";
  return "unavailable";
}
export function signalLabel(value: Signal): string {
  return {
    signals: "Signals found",
    "no-detections": "No VT detections",
    unavailable: "Not assessed",
  }[value];
}
export function context(row: ObservableResult): {
  network: string;
  country: string;
} {
  const ip = asRecord(row.ipinfo);
  return {
    network: String(ip?.asn ?? "—"),
    country: String(ip?.country_name ?? "—"),
  };
}
export const demoEngines = [
  "virustotal",
  "abuseipdb",
  "ipinfo",
  "reverse_dns",
  "rdap_whois",
  "threatfox",
];
export const demoRows: ObservableResult[] = [
  {
    observable: "203.0.113.42",
    type: "IPV4",
    virustotal: {
      total_malicious: 12,
      detection_ratio: "12/94",
      community_score: -38,
    },
    abuseipdb: { abuseConfidenceScore: 98, totalReports: 124 },
    ipinfo: { asn: "AS64500 · Example Hosting", country_name: "Netherlands" },
    reverse_dns: { reverse_dns: ["edge-42.example.test"] },
    rdap_whois: { abuse_contact: "abuse@example.test" },
    threatfox: { note: "Synthetic response for interface preview" },
  },
  {
    observable: "login-update.example.test",
    type: "FQDN",
    virustotal: {
      total_malicious: 8,
      detection_ratio: "8/94",
      community_score: -12,
    },
    reverse_dns: { reverse_dns: ["203.0.113.42"] },
    rdap_whois: { registrar: "Example Registrar", creation_date: "2026-10-12" },
    threatfox: null,
  },
  {
    observable: "198.51.100.18",
    type: "IPV4",
    virustotal: { total_malicious: 0, detection_ratio: "0/94" },
    abuseipdb: { abuseConfidenceScore: 0, totalReports: 0 },
    ipinfo: { asn: "AS64501 · Example Network", country_name: "France" },
    reverse_dns: { reverse_dns: ["mail.example.test"] },
  },
  {
    observable: "https://cdn.example.test/payload",
    type: "URL",
    virustotal: { total_malicious: 21, detection_ratio: "21/94" },
    reverse_dns: { reverse_dns: ["192.0.2.80"] },
    rdap_whois: { registrar: "Example Registrar" },
  },
  {
    observable:
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    type: "SHA256",
    virustotal: { total_malicious: 0, detection_ratio: "0/72" },
    threatfox: null,
  },
  {
    observable: "192.0.2.80",
    type: "IPV4",
    virustotal: null,
    abuseipdb: null,
    ipinfo: { asn: "AS64502 · Example Cloud", country_name: "Germany" },
    reverse_dns: null,
  },
  {
    observable: "status.example.test",
    type: "FQDN",
    virustotal: { total_malicious: 0, detection_ratio: "0/94" },
    reverse_dns: { reverse_dns: ["198.51.100.18"] },
    rdap_whois: { registrar: "Example Registrar" },
  },
  {
    observable: "203.0.113.91",
    type: "IPV4",
    virustotal: { total_malicious: 3, detection_ratio: "3/94" },
    abuseipdb: { abuseConfidenceScore: 64, totalReports: 18 },
    ipinfo: { asn: "AS64500 · Example Hosting", country_name: "Netherlands" },
  },
  {
    observable: "files.example.test",
    type: "FQDN",
    virustotal: { total_malicious: 0, detection_ratio: "0/94" },
    rdap_whois: { registrar: "Example Registrar" },
  },
  {
    observable: "198.51.100.77",
    type: "IPV4",
    virustotal: { total_malicious: 0, detection_ratio: "0/94" },
    abuseipdb: { abuseConfidenceScore: 0 },
    ipinfo: { asn: "AS64501 · Example Network", country_name: "France" },
  },
  {
    observable: "https://portal.example.test/",
    type: "URL",
    virustotal: null,
    reverse_dns: null,
  },
  {
    observable: "2001:db8::42",
    type: "IPV6",
    virustotal: { total_malicious: 0, detection_ratio: "0/94" },
    ipinfo: { asn: "AS64502 · Example Cloud", country_name: "Germany" },
  },
];
