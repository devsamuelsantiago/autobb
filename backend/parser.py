"""
AutoBB - scan4all Parser
Faz parse do output JSON do scan4all e normaliza as vulnerabilidades.
"""

from __future__ import annotations

import json
import re
from typing import Optional


# Mapeamento de severidade baseado em palavras-chave do scan4all/nuclei
SEVERITY_KEYWORDS = {
    "critical": ["critical"],
    "high": ["high"],
    "medium": ["medium"],
    "low": ["low"],
    "info": ["info", "informational"],
}


# Severidades relevantes — todas incluindo info
RELEVANT_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def parse_severity(raw: str) -> str:
    """Normaliza string de severidade."""
    raw_lower = raw.lower().strip()
    for sev, keywords in SEVERITY_KEYWORDS.items():
        if any(k in raw_lower for k in keywords):
            return sev
    return "info"


def parse_scan4all_output(raw_output: str) -> list:
    """
    Faz parse do output do scan4all.
    Retorna vulnerabilidades info, low, medium, high e critical.
    Linhas HTTP sem tag de severidade (URL brutas) são capturadas como info.
    """
    vulns = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
            vuln = _parse_json_entry(entry)
            if vuln and vuln["severity"] in RELEVANT_SEVERITIES:
                vulns.append(vuln)
            continue
        except json.JSONDecodeError:
            pass

        vuln = _parse_text_line(line)
        if vuln and vuln["severity"] in RELEVANT_SEVERITIES:
            vulns.append(vuln)

    return vulns


def _parse_json_entry(entry: dict) -> Optional[dict]:
    """Parse de entrada JSON do nuclei/scan4all."""
    info = entry.get("info", {})
    severity_raw = info.get("severity", "info")
    
    name = info.get("name") or entry.get("template-id", "unknown")
    host = entry.get("host") or entry.get("matched-at", "")
    details_parts = []

    if entry.get("matched-at"):
        details_parts.append(f"matched-at: {entry['matched-at']}")
    if entry.get("extracted-results"):
        details_parts.append(f"extracted: {', '.join(entry['extracted-results'])}")
    if info.get("description"):
        details_parts.append(f"desc: {info['description']}")

    return {
        "vuln_name": name,
        "host": host.replace("https://", "").replace("http://", "").split("/")[0],
        "severity": parse_severity(severity_raw),
        "details": " | ".join(details_parts),
    }


def _parse_text_line(line: str) -> Optional[dict]:
    """
    Parse de linha texto do nuclei/scan4all.
    O formato real emitido pelo scan4all é:
      [template-id] [protocolo] [severidade] host [extras]
    Exemplos:
      [weak-cipher-suites:tls-1.0] [ssl] [low] valmo.in:443 ["[tls10 ...]"]
      [waf-detect:akamai] [http] [info] https://superstoreapp.meesho.com:443
      [cve-2021-44228] [http] [critical] https://example.com
    """
    # Remove ANSI color codes antes de parsear
    clean = re.sub(r'\x1b\[[0-9;]*m', '', line)

    # Formato principal: [template] [proto] [severity] host [extras...]
    pattern = r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[(critical|high|medium|low|info)\]\s*(https?://\S+|\S+)"
    match = re.search(pattern, clean, re.IGNORECASE)

    if match:
        template = match.group(1)
        # protocolo = match.group(2)  # não usado
        severity  = match.group(3).lower()
        host_raw  = match.group(4)
        host = re.sub(r':\d+$', '', host_raw.replace("https://", "").replace("http://", "").split("/")[0])
        return {
            "vuln_name": template,
            "host": host,
            "severity": severity,
            "details": clean.strip(),
        }

    # Fallback: formato legado [severity] [template] host
    pattern_legacy = r"\[(critical|high|medium|low|info)\]\s*\[([^\]]+)\]\s*(https?://\S+|\S+)"
    match2 = re.search(pattern_legacy, clean, re.IGNORECASE)
    if match2:
        severity = match2.group(1).lower()
        template = match2.group(2)
        host_raw = match2.group(3)
        host = re.sub(r':\d+$', '', host_raw.replace("https://", "").replace("http://", "").split("/")[0])
        return {
            "vuln_name": template,
            "host": host,
            "severity": severity,
            "details": clean.strip(),
        }

    # Linhas HTTP brutas: URL [status] [método] [...tecnologias...]
    # Ex: https://x1creditcard.com/path [502] [GET] [CloudFront] [Amazon] [12345]
    url_match = re.match(r'^(https?://([^/\s]+)[^\s]*)\s+\[(\d{3})\]', clean)
    if url_match:
        url      = url_match.group(1)
        host_raw = url_match.group(2)
        status   = url_match.group(3)
        host     = re.sub(r':\d+$', '', host_raw)
        # Extrai tecnologias entre colchetes após o status
        techs = re.findall(r'\[([^\]\d][^\]]*)\]', clean[url_match.end():])
        tech_str = ", ".join(t for t in techs if t and not t.startswith('-'))
        return {
            "vuln_name": f"http-response:{status}",
            "host": host,
            "severity": "info",
            "details": f"url: {url} | status: {status}" + (f" | tech: {tech_str}" if tech_str else ""),
        }

    return None
