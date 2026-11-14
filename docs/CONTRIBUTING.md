# Guide de Contribution — `dtnpm-app-basket`

Ce guide présente les règles de développement et les exigences de sécurité pour l'application DTN Basket de `dtnpm-app-basket`.

---

## 1. Principes Fondamentaux

- **Zéro Panic / Zéro Unwrap** : Aucun appel `.unwrap()` ou `.expect()` en code de production.
- **Sécurité Réseau et Anti-SSRF** :
  - Tout accès réseau externe doit passer par le résolveur de sécurité `SafeDnsResolver`.
  - Les redirections doivent être résolues manuellement pour bloquer le DNS Rebinding.
  - L'accès aux réseaux privés nécessite l'opt-in explicite `allow_private_ips = true`.
- **Traçabilité Architecturale (ADR)** :
  - Tout changement protocolaire ou d'architecture de service doit faire l'objet d'un fichier ADR sous `adr/` et être indexé dans `adr/README.md`.

---

## 2. Vérification Locale

```bash
cargo fmt --all -- --check
cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic
cargo test --offline --all-features
./scripts/check-security.sh --strict
```
