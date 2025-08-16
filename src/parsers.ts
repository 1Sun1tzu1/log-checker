export interface LogEntry {
  raw: string;
  ip: string | null;
  status?: number;
  ts?: number; // epoch ms
  method?: string;
  path?: string;
  ua?: string;
  tags?: string[];
}

export interface Anomaly {
  type: string;
  message: string;
  line?: string;
}

const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;
const STATUS_RE = /\s(\d{3})\s/;
const CLF_RE = /^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]*?) [^"]*" (\d{3}) (?:\d+|-) "(?:[^"]*)" "([^"]*)"/;
const SSH_FAILED_RE = /(Failed password|authentication failure|Invalid user|Login incorrect)/i;

function parseApacheDate(d: string): number | undefined {
  // Example: 10/Oct/2000:13:55:36 -0700
  // Convert to ISO-ish
  try {
    const m = d.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/);
    if (!m) return undefined;
    const [_, DD, MMM, YYYY, hh, mm, ss, tz] = m;
    const months: Record<string, string> = {Jan:"01",Feb:"02",Mar:"03",Apr:"04",May:"05",Jun:"06",Jul:"07",Aug:"08",Sep:"09",Oct:"10",Nov:"11",Dec:"12"};
    const iso = `${YYYY}-${months[MMM]}-${DD}T${hh}:${mm}:${ss}${tz.substring(0,3)}:${tz.substring(3)}`;
    return new Date(iso).getTime();
  } catch { return undefined; }
}

export function parseLine(line: string): LogEntry {
  const entry: LogEntry = { raw: line, ip: null, tags: [] };

  // Try Common Log Format (Apache/Nginx combined)
  const m = line.match(CLF_RE);
  if (m) {
    entry.ip = m[1];
    const ts = parseApacheDate(m[2]);
    if (ts) entry.ts = ts;
    entry.method = m[3];
    entry.path = m[4];
    entry.status = parseInt(m[5], 10);
    entry.ua = m[6];
    return entry;
  }

  // SSH style failures
  if (SSH_FAILED_RE.test(line)) {
    entry.ip = (line.match(IP_RE) || [null])[0];
    entry.tags!.push("failed_login");
    return entry;
  }

  // Generic fallbacks
  entry.ip = (line.match(IP_RE) || [null])[0];
  const sm = line.match(STATUS_RE);
  if (sm) entry.status = parseInt(sm[1], 10);
  const ua = line.match(/"(Mozilla|curl|Wget|Postman|python-requests|Go-http-client|sqlmap).*?"/i);
  if (ua) entry.ua = ua[0];
  return entry;
}

export function analyzeLogs(text: string) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  const entries = lines.map(parseLine);

  const anomalies: Anomaly[] = [];
  const failedByIP: Record<string, number> = {};
  const errorsByIP: Record<string, number> = {};
  const uaSet: Set<string> = new Set();
  const perMinute: Record<string, number> = {};
  const nightByIP: Record<string, number> = {};

  for (const e of entries) {
    const ip = e.ip || "unknown";

    // Failed login tags
    if (e.tags?.includes("failed_login") || /failed login/i.test(e.raw)) {
      failedByIP[ip] = (failedByIP[ip] || 0) + 1;
    }

    // HTTP errors
    if (typeof e.status === "number" && [403,404,500,502,503].includes(e.status)) {
      errorsByIP[ip] = (errorsByIP[ip] || 0) + 1;
      anomalies.push({ type: "HTTP Error", message: `HTTP ${e.status} from ${ip}`, line: e.raw });
    }

    // User agents
    if (e.ua) uaSet.add(e.ua);

    // Requests per minute (rate spikes)
    if (e.ts && e.ip) {
      const minuteBucket = Math.floor(e.ts / 60000);
      const key = `${e.ip}:${minuteBucket}`;
      perMinute[key] = (perMinute[key] || 0) + 1;

      // Night-time activity 00:00–05:00 (based on local parsing)
      const hour = new Date(e.ts).getHours();
      if (hour >= 0 && hour < 5) {
        nightByIP[ip] = (nightByIP[ip] || 0) + 1;
      }
    }
  }

  // Post-rules
  for (const [ip, cnt] of Object.entries(failedByIP)) {
    if (cnt >= 6) anomalies.push({ type: "Brute Force", message: `${cnt} failed logins from ${ip}` });
  }
  for (const [ip, cnt] of Object.entries(errorsByIP)) {
    if (cnt >= 12) anomalies.push({ type: "Error Spike", message: `${cnt} HTTP errors from ${ip}` });
  }

  // Suspicious agents (automation/tools)
  if ([...uaSet].some(ua => /curl|wget|postman|python-requests|go-http-client|sqlmap/i.test(ua))) {
    anomalies.push({ type: "Suspicious UA", message: "Automation/tool user-agents detected (curl/wget/Postman/etc.)" });
  }

  // Rate spikes: any ip-minute with > 120 reqs/min
  const maxPerIP: Record<string, number> = {};
  for (const [key, count] of Object.entries(perMinute)) {
    const ip = key.split(":")[0];
    if (!maxPerIP[ip] || count > maxPerIP[ip]) maxPerIP[ip] = count;
  }
  for (const [ip, max] of Object.entries(maxPerIP)) {
    if (max > 120) anomalies.push({ type: "Rate Spike", message: `${ip} peaked at ${max} req/min` });
  }

  // Night-time activity
  for (const [ip, cnt] of Object.entries(nightByIP)) {
    if (cnt >= 100) anomalies.push({ type: "Off-hours Activity", message: `${cnt} requests between 00:00–05:00 from ${ip}` });
  }

  return { entries, anomalies };
}
