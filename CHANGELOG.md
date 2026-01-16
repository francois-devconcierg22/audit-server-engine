# Changelog

## [1.0.0] — 2026-01-16

### Added
- Générateur d’audit brut **AI-ready** (`generate_audit_raw.py`)
- Inclusion d’un bloc `ai_prompt` auto-portant pour IA
- Grilles d’audit serveur, sécurité web, WordPress, performance
- Collecteurs système et infrastructure
- Schéma de validation des facts

### Changed
- Suppression complète du rendu serveur (HTML / PDF)
- Séparation stricte : collecte / analyse / narration

### Removed
- Templates HTML
- CSS de rendu
- Génération PDF côté serveur

### Notes
Cette version marque le gel du format RAW destiné à une transformation
externe (IA, Make, outils tiers).  
Le serveur n’effectue aucune mise en forme.
