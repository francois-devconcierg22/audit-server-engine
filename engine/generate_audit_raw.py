#!/usr/bin/env python3
import json
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
REPORT = BASE / "reports/audit_server_v1"

FACTS_FILE = REPORT / "facts.filtered.json"
COVERAGE_FILE = REPORT / "coverage.json"
OUT_FILE = REPORT / "audit_server_v1.raw.json"

facts = json.loads(FACTS_FILE.read_text())
coverage = json.loads(COVERAGE_FILE.read_text())

# ---------------------------
# AI PROMPT — CANONIQUE
# ---------------------------
ai_prompt = {
    "role": "instruction",
    "audience": "client_non_technique",
    "objective": "Transformer un audit serveur brut en rapport client professionnel",
    "instructions": [
        "Rédiger une synthèse exécutive claire et rassurante",
        "Lister les actions prioritaires par ordre d’urgence",
        "Présenter les contrôles sous forme de tableau lisible",
        "Éviter le jargon technique inutile",
        "Expliquer simplement les éléments non mesurables",
        "Ne jamais afficher de JSON ou de données techniques brutes dans le rendu final"
    ],
    "tone": "professionnel, pédagogique, orienté décision",
    "output_language": "fr",
    "output_format": "rapport client structuré"
}

# ---------------------------
# FINDINGS — NORMALISATION
# ---------------------------
critical = []
warning = []
ok = []

if not facts["security_infra"]["firewall_present"]:
    critical.append({
        "code": "SEC_FIREWALL_ABSENT",
        "message": "Pare-feu inactif sur un serveur exposé à Internet",
        "impact": "Exposition directe aux attaques réseau",
        "recommended_action": "Activer un pare-feu (UFW) et restreindre les ports"
    })

open_ports = facts["security_infra"].get("open_ports", [])
if open_ports:
    warning.append({
        "code": "SEC_OPEN_PORTS",
        "message": "Ports ouverts à justifier",
        "details": open_ports,
        "recommended_action": "Fermer les ports non utilisés ou documenter leur usage"
    })

if facts["system"]["cpu_load_15m"] == "non_mesurable":
    warning.append({
        "code": "CPU_NOT_MEASURED",
        "message": "Charge CPU non mesurable",
        "reason": "Outil ou droit système manquant",
        "recommended_action": "Activer les métriques CPU pour le suivi"
    })

if facts["security_infra"]["ssh_root_login"] is False:
    ok.append("Accès SSH root désactivé")

if facts["security_infra"]["fail2ban_present"]:
    ok.append("Fail2ban actif")

if facts["system"]["disk_used_percent"] < 70:
    ok.append("Espace disque confortable")

# ---------------------------
# METRICS — HUMAN FRIENDLY
# ---------------------------
uptime_hours = facts["system"]["uptime_hours"]
uptime_days = uptime_hours // 24

metrics = {
    "system": {
        "os": f"{facts['system']['os_name']} {facts['system']['os_version']}",
        "uptime_hours": uptime_hours,
        "uptime_human": f"{uptime_days} jours",
        "disk_used_percent": facts["system"]["disk_used_percent"],
        "ram_free_percent": facts["system"]["ram_free_percent"],
        "cpu_load_15m": facts["system"]["cpu_load_15m"]
    },
    "security_infra": facts["security_infra"],
    "resilience": facts["resilience"],
    "logs": facts["logs"]
}

# ---------------------------
# FINAL RAW OBJECT
# ---------------------------
raw = {
    "ai_prompt": ai_prompt,
    "analysis": {
        "meta": {
            "audit_id": "audit_server_v1",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "scope": "server_infrastructure"
        },
        "coverage": coverage,
        "findings": {
            "critical": critical,
            "warning": warning,
            "ok": ok
        },
        "metrics": metrics,
        "recommendation_summary": {
            "priority": "high" if critical else "medium",
            "orientation": "Sécurisation immédiate requise" if critical else "Optimisations recommandées"
        }
    }
}

OUT_FILE.write_text(json.dumps(raw, indent=2, ensure_ascii=False))
print(f"[OK] RAW audit généré : {OUT_FILE}")
