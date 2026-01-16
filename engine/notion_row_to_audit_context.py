#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import sys
import yaml

# ============================================================
# Normalisation des clés (apostrophes, guillemets, espaces)
# ============================================================

def normalize_key(s: str) -> str:
    return (
        (s or "")
        .strip()
        .replace("’", "'")
        .replace("“", '"')
        .replace("”", '"')
    )

# ============================================================
# Valeurs autorisées (ALIGNÉES AVEC LE SCHÉMA VALIDÉ)
# ============================================================

ALLOWED_VALUES = {
    "Type de site": ["vitrine", "ecommerce", "applicatif"],
    "Technologie principale": ["WordPress", "Symfony", "Laravel", "Node.js", "Aucune"],
    "Type d'hebergement": ["VPS", "Mutualise", "Cloud managé", "Dedie"],
    "Mode d'audit": ["lecture seule", "complet"],
    "Tolerance a l'indisponibilite": ["faible", "moyen", "eleve"],
    "Statut audit": ["en attente", "en cours", "termine", "refuse"],
}

# Normalisation des clés du référentiel
ALLOWED_VALUES = {
    normalize_key(k): v for k, v in ALLOWED_VALUES.items()
}

# ============================================================
# Chargement CSV
# ============================================================

def load_client_row(csv_path: str) -> dict:
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            if not row:
                raise ValueError("CSV vide")
            # Normalisation des clés CSV
            return {normalize_key(k): v.strip() for k, v in row.items()}
    except FileNotFoundError:
        raise FileNotFoundError(f"Fichier CSV introuvable : {csv_path}")

# ============================================================
# Validation stricte
# ============================================================

def check_allowed(field: str, value: str, allowed: list):
    if value not in allowed:
        raise ValueError(
            f"Valeur interdite pour '{field}': '{value}' (autorisées: {allowed})"
        )

def validate_row(row: dict):
    for field, allowed in ALLOWED_VALUES.items():
        if field not in row:
            raise KeyError(f"Champ manquant dans le CSV : '{field}'")
        if not row[field]:
            raise ValueError(f"Champ vide : '{field}'")
        check_allowed(field, row[field], allowed)

# ============================================================
# Génération audit_context.yaml
# ============================================================

def generate_context(row: dict) -> dict:
    return {
        "site": {
            "type": row["Type de site"],
            "technologie": row["Technologie principale"],
            "hebergement": row["Type d'hebergement"],
        },
        "audit": {
            "mode": row["Mode d'audit"],
            "downtime_tolerance": row["Tolerance a l'indisponibilite"],
            "status": row["Statut audit"],
        },
        "meta": {
            "source": "csv",
        },
    }

# ============================================================
# Main
# ============================================================

def main():
    if len(sys.argv) != 3:
        print("Usage: python notion_row_to_audit_context.py <client_row.csv> <output.yaml>")
        sys.exit(1)

    csv_path = sys.argv[1]
    output_path = sys.argv[2]

    row = load_client_row(csv_path)
    validate_row(row)
    context = generate_context(row)

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(context, f, sort_keys=False, allow_unicode=True)

    print(f"[OK] audit_context.yaml généré : {output_path}")

if __name__ == "__main__":
    main()
