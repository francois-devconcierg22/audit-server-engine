# SCHEMA_VALIDATION — Notion ↔ Audit Grid (v1)

## Source of Truth
- Audit grid: grids/audit_grid_v1.yaml
- Select referential: data/notion_selects.csv
- Notion database: <DB_NAME> (<DB_ID>)

## Validation Table

| Champ grille (key) | Libellé Notion attendu | Type attendu | Type réel Notion | Options attendues | Options réelles | Statut | Action |
|---|---|---|---|---|---|---|---|
| type_site | Type de site | select | select | vitrine,ecommerce,blog,application | vitrine,ecommerce,blog,application | OK | - |
| techno | Technologie principale | select | select | WordPress,Symfony,Laravel,Node.js,Aucune | WordPress,Symfony,Laravel,Node.js,Aucune | OK | - |
| hosting | Type d'hebergement | select | select | VPS,Mutualise,Cloud managé,Dedie | VPS,Mutualise,Cloud managé,Dedie | OK | - |
| audit_mode | Mode d'audit | select | select | lecture seule,complet | lecture seule,complet | OK | - |
| tolerance | Tolerance a l'indisponibilite | select | select | aucune,faible,acceptable | aucune,faible,acceptable | OK | - |
| audit_status | Statut audit | select | select | en attente,en cours,termine,refuse | en attente,en cours,termine,refuse | OK | - |

## Notes de normalisation
- Les libellés sont sensibles à la casse / accents / apostrophes.
- Aucune option n’est ajoutée à la main dans Notion.
- Toute évolution passe par: CSV référentiel → script → validation.

### downtime_tolerance — RTO mapping (figé)

- faible : RTO < 10 minutes
- moyen  : RTO < 2 heures
- eleve  : RTO > 2 heures

Ce mapping est contractuel et utilisé par le moteur de décision.
Aucune interprétation humaine n’est autorisée.
