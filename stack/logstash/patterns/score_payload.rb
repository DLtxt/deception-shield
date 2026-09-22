# Payload scoring for the Logstash ruby filter.
#
# Wireshark hands us the reassembled application payload. What matters for
# triage is not the bytes themselves but which known attack shapes appear in
# them, so each match contributes to a score and records the reason. An analyst
# sorting on the score sees exploitation attempts before scanner noise, and the
# recorded reasons explain why a payload ranked where it did.

# Weights reflect how rarely each pattern shows up in benign traffic. A shell
# pipe into an interpreter is close to conclusive; a directory traversal string
# is common in untargeted scans and scores lower.
SIGNATURES = [
  { name: "shell_pipe_execution",  weight: 40, re: /\|\s*(?:ba)?sh\b|\|\s*python[23]?\b/i },
  { name: "remote_payload_fetch",  weight: 30, re: /\b(?:wget|curl)\s+[^\s;|]*https?:\/\//i },
  { name: "reverse_shell",         weight: 40, re: /(?:nc|ncat|netcat)\s+(?:-[a-z]*e[a-z]*\s|\S+\s+\d+\s*-e)|\/dev\/tcp\//i },
  { name: "sql_injection",         weight: 25, re: /(?:union\s+(?:all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\)|benchmark\()/i },
  { name: "path_traversal",        weight: 15, re: /(?:\.\.[\/\\]){2,}|%2e%2e(?:%2f|%5c)/i },
  { name: "command_injection",     weight: 30, re: /[;&`]\s*(?:cat|ls|id|whoami|uname)\b|\$\(.*\)/i },
  { name: "log4shell",             weight: 45, re: /\$\{jndi:(?:ldaps?|rmi|dns|iiop):/i },
  { name: "webshell_upload",       weight: 35, re: /<\?php|eval\s*\(\s*(?:base64_decode|\$_(?:POST|GET|REQUEST))/i },
  { name: "credential_probe",      weight: 20, re: /(?:\/etc\/(?:passwd|shadow)|\bwin\.ini\b|\bboot\.ini\b)/i },
  { name: "iot_botnet_dropper",    weight: 40, re: /\b(?:mirai|mozi|gafgyt|tsunami)\b|busybox\s+(?:wget|tftp)/i },
  { name: "cve_probe_struts",      weight: 35, re: /%\{\(#_?=|ognl|struts\.valueStack/i },
  { name: "xxe_attempt",           weight: 30, re: /<!ENTITY\s+\S+\s+SYSTEM/i },
  { name: "encoded_powershell",    weight: 35, re: /powershell(?:\.exe)?\s+.*-e(?:nc|ncoded)?[a-z]*\s+[A-Za-z0-9+\/]{40,}/i },
  { name: "scanner_fingerprint",   weight: 5,  re: /\b(?:zgrab|masscan|nmap|nuclei|zmap|censys)\b/i },
]

# Ceiling keeps a payload that trips many low weight rules from outranking one
# that trips a single conclusive rule.
MAX_SCORE = 100

def register(params)
  @field = params["field"] || "payload_ascii"
end

def filter(event)
  payload = event.get(@field)
  return [event] if payload.nil? || payload.empty?

  # Normalise percent encoding once so a rule does not need an encoded variant.
  candidate = payload.dup
  begin
    decoded = candidate.gsub(/%([0-9A-Fa-f]{2})/) { [$1].pack("H2") }
    candidate = "#{candidate}\n#{decoded}" if decoded != candidate
  rescue StandardError
    # Malformed encoding is itself unremarkable; score the raw bytes instead.
  end

  score = 0
  reasons = []

  SIGNATURES.each do |sig|
    next unless candidate.match?(sig[:re])
    score += sig[:weight]
    reasons << sig[:name]
  end

  score = MAX_SCORE if score > MAX_SCORE

  event.set("[threat][payload_score]", score)
  event.set("[threat][payload_signatures]", reasons)
  event.set("[threat][triage]", triage_band(score))

  # A payload that matched nothing but is mostly non printable is likely binary
  # shellcode or a malformed protocol probe, both worth keeping visible.
  if reasons.empty?
    printable = payload.count("\x20-\x7e").to_f / payload.length
    if printable < 0.6
      event.set("[threat][triage]", "inspect")
      event.set("[threat][payload_signatures]", ["non_printable_payload"])
    end
  end

  [event]
end

def triage_band(score)
  case score
  when 0          then "benign"
  when 1..19      then "noise"
  when 20..49     then "suspicious"
  when 50..79     then "likely-malicious"
  else                 "critical"
  end
end
