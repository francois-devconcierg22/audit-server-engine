# Audit Server Engine

Moteur d’audit serveur déterministe produisant un résultat **AI-ready**  
(conçu pour être transformé en rapport client via IA ou Make).

---

## 🎯 Objectif

- Collecter des faits techniques serveur
- Appliquer des grilles d’audit versionnées
- Générer un **fichier brut auto-portant** destiné à une IA
- Aucune mise en forme côté serveur (pas de HTML / PDF)

Le serveur produit la **vérité technique**.  
La narration client est déléguée à l’IA.

---

## 🧱 Architecture

```text
collectors/        # collecte facts (Bash)
facts/             # facts runtime (non versionnés)
grids/             # grilles d’audit YAML
schemas/           # schémas de validation
engine/            # logique d’audit & génération RAW
reports/           # résultats d’audit (non versionnés)
tools/             # scripts d’orchestration
