#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
from pathlib import Path
from datetime import datetime
import yaml

NM = "non_mesurable"

# -----------------------------
# Helpers
# -----------------------------
def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def load_yaml(p: Path):
    return yaml.safe_load(p.read_text(encoding="utf-8"))

def is_nm(v):
    return v == NM or v is None

def as_int(v):
    try:
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return None
    except Exception:
        return None

def as_float(v):
    try:
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            return float(v)
        return None
    except Exception:
        return None

def flatten_requirements(profile_yaml):
    """
    profile_yaml['facts_required'] structure:
      domain:
        key: required|optional
    """
    req = []
    opt = []
    facts_required = profile_yaml.get("facts_required", {}) or {}
    for domain, keys in facts_required.items():
        if not isinstance(keys, dict):
            continue
        for k, status in keys.items():
            path = f"{domain}.{k}"
            if status == "required":
                req.append(path)
            else:
                opt.append(path)
    return req, opt

def get_value(facts, dotted_path: str):
    cur = facts
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

def set_value(out, dotted_path: str, value):
    cur = out
    parts = dotted_path.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value

# -----------------------------
# Severity rules (module-specific, deterministic)
# -----------------------------
def analyze_server(facts):
    findings = []

    # Firewall
    fw = get_value(facts, "security_infra.firewall_present")
    if fw is False:
        findings.append(("critical", "Pare-feu inactif (UFW): exposition réseau non filtrée sur VPS."))
    elif is_nm(fw):
        findings.append(("warning", "Pare-feu non mesurable: état UFW inconnu."))

    # Open ports
    ports = get_value(facts, "security_infra.open_ports")
    if isinstance(ports, list) and len(ports) > 0:
        # normalize to strings
        pset = set(str(p) for p in ports)
        unexpected = sorted(pset - set(["22", "80", "443", "2222"]))
        if unexpected:
            findings.append(("warning", f"Ports ouverts à justifier: {', '.join(unexpected)}."))
    elif is_nm(ports):
        findings.append(("warning", "Ports ouverts non mesurables."))

    # SSH root
    root = get_value(facts, "security_infra.ssh_root_login")
    if root is True:
        findings.append(("warning", "SSH root autorisé: augmenter la sécurité (désactiver + clés + sudo)."))
    elif is_nm(root):
        findings.append(("warning", "Statut SSH root non mesurable."))

    # Disk
    disk = as_int(get_value(facts, "system.disk_used_percent"))
    if disk is not None:
        if disk >= 90:
            findings.append(("critical", f"Disque saturé: {disk}% (risque d'arrêt services / logs)."))
        elif disk >= 80:
            findings.append(("warning", f"Disque élevé: {disk}% (seuil d’alerte recommandé >=80%)."))
    else:
        findings.append(("warning", "Utilisation disque non mesurable."))

    # RAM
    ram = as_int(get_value(facts, "system.ram_free_percent"))
    if ram is not None:
        if ram < 15:
            findings.append(("critical", f"Mémoire libre faible: {ram}% (risque OOM)."))
        elif ram < 30:
            findings.append(("warning", f"Mémoire libre modérée: {ram}%."))
    else:
        findings.append(("warning", "Mémoire libre non mesurable."))

    # Load
    load = as_float(get_value(facts, "system.cpu_load_15m"))
    if load is not None:
        if load > 1.5:
            findings.append(("critical", f"Charge 15 min élevée: {load}."))
        elif load > 1.0:
            findings.append(("warning", f"Charge 15 min notable: {load}."))
    else:
        findings.append(("warning", "Charge CPU 15 min non mesurable."))

    # OS interim warning (Ubuntu non-LTS heuristic)
    os_name = get_value(facts, "system.os_name")
    os_ver = get_value(facts, "system.os_version")
    if os_name == "ubuntu" and isinstance(os_ver, str) and os_ver.endswith(".04") is False:
        findings.append(("warning", f"Ubuntu {os_ver} semble être une version intermédiaire (non-LTS) : attention maintenance et cycles de support."))

    # Backups presence
    bkp = get_value(facts, "resilience.backups_present")
    if bkp is False:
        findings.append(("critical", "Sauvegardes absentes (ou non détectées)."))
    elif is_nm(bkp):
        findings.append(("warning", "Sauvegardes non mesurables."))
    else:
        # present but location unknown
        loc = get_value(facts, "resilience.backups_location")
        if is_nm(loc) or loc == "unknown":
            findings.append(("warning", "Sauvegardes détectées, mais localisation/externalisation non mesurée."))

    return findings

def analyze_web_security(facts):
    findings = []
    sslp = get_value(facts, "web_security.ssl_certificate_present")
    exp = as_int(get_value(facts, "web_security.ssl_certificate_expiry_days"))
    https_forced = get_value(facts, "web_security.https_forced")

    if sslp is False:
        findings.append(("critical", "Certificat SSL absent: site potentiellement indisponible/insécurisé."))
    elif is_nm(sslp):
        findings.append(("warning", "Présence certificat SSL non mesurable."))
    else:
        if exp is not None:
            if exp < 14:
                findings.append(("critical", f"Certificat SSL expire très bientôt: {exp} jours."))
            elif exp < 30:
                findings.append(("warning", f"Certificat SSL expire bientôt: {exp} jours."))
        else:
            findings.append(("warning", "Date d’expiration SSL non mesurable."))

    if https_forced is False:
        findings.append(("warning", "HTTPS non forcé (redirection HTTP→HTTPS absente)."))
    elif is_nm(https_forced):
        findings.append(("warning", "Forçage HTTPS non mesurable."))

    perms = get_value(facts, "web_security.web_root_permissions")
    if isinstance(perms, str) and perms != NM:
        if perms not in ["755", "750", "775"]:
            findings.append(("warning", f"Permissions web root atypiques: {perms} (attendu souvent 755)."))
    else:
        findings.append(("warning", "Permissions web root non mesurables."))

    wpcfgp = get_value(facts, "web_security.wp_config_permissions")
    if isinstance(wpcfgp, str) and wpcfgp != NM:
        # strict recommendations vary; flag overly open
        if wpcfgp in ["777", "775", "755", "744", "666", "664"]:
            findings.append(("warning", f"Permissions wp-config.php trop ouvertes: {wpcfgp} (viser 640/600)."))
    elif is_nm(wpcfgp):
        findings.append(("warning", "Permissions wp-config.php non mesurables."))

    return findings

def analyze_wordpress(facts):
    findings = []
    core = get_value(facts, "wordpress.core_version")
    if is_nm(core):
        findings.append(("warning", "WordPress non mesurable: WP-CLI/accès applicatif requis (mutualisé OK, VPS OK)."))
        return findings

    # Example checks (only if measurable)
    outdated = as_int(get_value(facts, "wordpress.outdated_plugins"))
    if outdated is not None and outdated > 0:
        findings.append(("warning", f"Plugins non à jour: {outdated}."))

    admins = as_int(get_value(facts, "wordpress.admin_count"))
    if admins is not None and admins == 0:
        findings.append(("critical", "Aucun compte admin détecté (anormal)."))

    return findings

def analyze_performance_resilience(facts):
    findings = []

    phpv = get_value(facts, "stack.php_version")
    if is_nm(phpv):
        findings.append(("warning", "Version PHP non mesurable."))
    myv = get_value(facts, "stack.mysql_version")
    if is_nm(myv):
        findings.append(("warning", "Version MySQL/MariaDB non mesurable."))

    rb = get_value(facts, "deployment.rollback_available")
    if is_nm(rb):
        findings.append(("warning", "Rollback non mesurable (snapshots/blue-green à vérifier)."))
    elif rb == "none":
        findings.append(("critical", "Aucun mécanisme de rollback détecté."))

    ext = get_value(facts, "backups.backups_externalized")
    if ext is False:
        findings.append(("critical", "Sauvegardes non externalisées (risque perte totale en cas d'incident disque)."))
    elif is_nm(ext):
        findings.append(("warning", "Externalisation des sauvegardes non mesurable."))

    return findings

def severity_score(level: str) -> int:
    return {"critical": 3, "warning": 2, "ok": 1}.get(level, 0)

# -----------------------------
# Markdown rendering
# -----------------------------
def md_list(items):
    if not items:
        return "- Aucun point à signaler."
    return "\n".join([f"- **{lvl.upper()}** — {msg}" for (lvl, msg) in items])

def compute_coverage(facts, req_paths, opt_paths):
    req_total = len(req_paths)
    opt_total = len(opt_paths)

    req_missing = []
    opt_missing = []
    for p in req_paths:
        v = get_value(facts, p)
        if v is None or is_nm(v):
            req_missing.append(p)

    for p in opt_paths:
        v = get_value(facts, p)
        if v is None or is_nm(v):
            opt_missing.append(p)

    req_ok = req_total - len(req_missing)
    opt_ok = opt_total - len(opt_missing)

    return {
        "required_total": req_total,
        "required_ok": req_ok,
        "required_missing": req_missing,
        "optional_total": opt_total,
        "optional_ok": opt_ok,
        "optional_missing": opt_missing,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--facts", default="facts/facts_all.json", help="Chemin vers facts_all.json")
    ap.add_argument("--profile", required=True, help="Chemin vers grids/audit_*.yaml")
    ap.add_argument("--outdir", default="reports", help="Dossier reports")
    args = ap.parse_args()

    facts_path = Path(args.facts)
    profile_path = Path(args.profile)
    outdir = Path(args.outdir)

    facts = load_json(facts_path)
    profile = load_yaml(profile_path)

    profile_name = profile.get("meta", {}).get("name", profile_path.stem)
    profile_slug = profile_path.stem

    req_paths, opt_paths = flatten_requirements(profile)
    coverage = compute_coverage(facts, req_paths, opt_paths)

    # Filtered facts = keep only domains referenced in profile
    filtered = {}
    for p in req_paths + opt_paths:
        v = get_value(facts, p)
        set_value(filtered, p, v if v is not None else NM)

    # Deterministic analysis by profile type (based on filename)
    findings = []
    if "audit_server" in profile_slug:
        findings = analyze_server(facts)
    elif "audit_web_security" in profile_slug:
        findings = analyze_web_security(facts)
    elif "audit_wordpress" in profile_slug:
        findings = analyze_wordpress(facts)
    elif "audit_performance_resilience" in profile_slug:
        findings = analyze_performance_resilience(facts)

    # Sort findings by severity
    findings_sorted = sorted(findings, key=lambda x: severity_score(x[0]), reverse=True)

    # Build report markdown
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append(f"# {profile_name}")
    lines.append("")
    lines.append(f"_Généré le {now}_")
    lines.append("")
    lines.append("## 1. Couverture de mesure")
    lines.append("")
    lines.append(f"- **Requis mesurés** : {coverage['required_ok']}/{coverage['required_total']}")
    lines.append(f"- **Optionnels mesurés** : {coverage['optional_ok']}/{coverage['optional_total']}")
    if coverage["required_missing"]:
        lines.append("")
        lines.append("### Points requis non mesurables (bloquants)")
        lines.append("")
        lines.extend([f"- `{p}`" for p in coverage["required_missing"]])
    if coverage["optional_missing"]:
        lines.append("")
        lines.append("### Points optionnels non mesurables")
        lines.append("")
        lines.extend([f"- `{p}`" for p in coverage["optional_missing"]])
    lines.append("")
    lines.append("## 2. Constats (sévérité)")
    lines.append("")
    lines.append(md_list(findings_sorted))
    lines.append("")
    lines.append("## 3. Données retenues (facts filtrés)")
    lines.append("")
    lines.append("Les données ci-dessous sont strictement limitées au périmètre du module.")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(filtered, indent=2, ensure_ascii=False))
    lines.append("```")
    lines.append("")
    lines.append("## 4. Recommandations (actions)")
    lines.append("")
    # Simple recommendation set, deterministic
    if any(lvl == "critical" for lvl, _ in findings_sorted):
        lines.append("- Prioriser les points **CRITICAL** avant toute optimisation.")
    if "audit_server" in profile_slug:
        lines.append("- Activer un pare-feu (UFW) et restreindre les ports exposés au strict nécessaire.")
        lines.append("- Qualifier la stratégie de sauvegarde (externalisation + rétention + test de restauration).")
    if "audit_web_security" in profile_slug:
        lines.append("- Forcer HTTPS et surveiller l’expiration du certificat (alerte automatique).")
        lines.append("- Durcir les permissions et vérifier les fichiers sensibles (wp-config.php).")
    if "audit_wordpress" in profile_slug:
        lines.append("- Mettre à jour core/plugins/thèmes et contrôler les comptes administrateurs.")
    if "audit_performance_resilience" in profile_slug:
        lines.append("- Vérifier versions PHP/MySQL, activer OPcache, qualifier cache applicatif si pertinent.")
        lines.append("- Mettre en place un rollback réel (snapshots/blue-green) selon RTO attendu.")
    lines.append("")

    # Write outputs
    report_dir = outdir / profile_slug
    report_dir.mkdir(parents=True, exist_ok=True)

    (report_dir / "facts.filtered.json").write_text(json.dumps(filtered, indent=2, ensure_ascii=False), encoding="utf-8")
    (report_dir / "coverage.json").write_text(json.dumps(coverage, indent=2, ensure_ascii=False), encoding="utf-8")
    (report_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] Profil appliqué: {profile_slug}")
    print(f"[OK] Report: {report_dir / 'report.md'}")
    print(f"[OK] Facts filtrés: {report_dir / 'facts.filtered.json'}")
    print(f"[OK] Coverage: {report_dir / 'coverage.json'}")

if __name__ == "__main__":
    main()
