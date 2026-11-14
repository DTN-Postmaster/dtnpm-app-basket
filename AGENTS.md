# Agent Guide — `dtnpm-app-basket`

## 🎯 Mission
Fournir le service mandataire DTN Basket (`dtnbasket`) et l'utilitaire en ligne de commande associé (`dtnbasket-cli`) selon la spécification `draft-f4jxq-dtn-basket-00`, permettant la récupération asynchrone, tolérante aux délais et coupures, de ressources distantes (HTTP, HTTPS, Gemini) et locales à travers le réseau DTN.

---

## 🛡️ Référentiels et Exigences de Sécurité

### 1. Cyber Resilience Act (CRA) & Sécurité par Défaut
- **Résolution DNS & Protection Anti-SSRF (Server-Side Request Forgery)** :
  - Tout fetcher externe DOIT utiliser le résolveur de sécurité `SafeDnsResolver` qui inspecte les adresses IP avant établissement de la connexion TCP.
  - Les plages d'adresses privées (RFC 1918), adresses locales de lien (RFC 3927 / APIPA), loopbacks (`127.0.0.0/8`, `::1`), adresses de broadcast et métadonnées cloud (`169.254.169.254`) sont STRICTEMENT BLOQUÉES par défaut.
  - Les redirections automatiques sont désactivées : chaque redirection HTTP est interceptée et ré-évaluée par `SafeDnsResolver` pour neutraliser toute attaque par rebond DNS (DNS Rebinding / TOCTOU).
  - Pour le protocole Gemini, la connexion s'effectue directement sur le `SocketAddr` préalablement validé.
- **Opt-in Explicite pour les Déploiements Intranet / Labo** :
  - L'accès à des serveurs ou services situés sur des réseaux privés N'EST POSSIBLE QUE si l'utilisateur l'autorise explicitement via l'option de configuration `allow_private_ips = true`.
- **Prévention d'Attaque par Amplification DTN (`reply_to`)** :
  - L'autorité de destination des réponses (`reply_to`) doit impérativement correspondre au nœud émetteur de la requête (`source`), sauf si l'administrateur a explicitement activé `allow_third_party_reply_to = true`.
- **Supply-Chain & VEX** :
  - Audit `cargo-audit` et `cargo-deny` ; déclaration VEX `not_affected` pour `RUSTSEC-2026-0459`.
  - Actions CI épinglées par SHA-1 à 40 caractères.
- **Politique de sécurité** : Consignée dans [SECURITY.md](SECURITY.md).

### 2. Bornage Réseau et Sécurité du Système de Fichiers
- **Timeouts et Plafonds Mémoire** :
  - Timeouts stricts sur les connexions et transferts HTTP/Gemini.
  - Lecture d'en-tête Gemini bornée via `.take(1027)` pour interdire tout blocage ou déni de service mémoire.
  - Plafond de taille maximale de streaming par ressource et budget d'allocation par lot.
- **Recherche de Fichiers Sécurisée (`perform_search`)** :
  - Vérification systématique des métadonnées (`symlink_metadata`) pour refuser de suivre les liens symboliques pointant hors du répertoire approuvé.
  - Calcul asynchrone des condensats de fichiers (`tokio::task::spawn_blocking`).
  - Aucun chemin système sensible (tel que `/var/log` ou `/etc`) ne doit figurer dans les exemples de configuration fournis.

---

## 🦀 Standards d'Ingénierie Rust

1. **Règle Zéro Panic / Zéro Unwrap** :
   - Tout le code sous `src/` doit être 100% exempt de `.unwrap()`, `.expect()` et de macro `panic!`.
   - Linter strict : `-D warnings -D clippy::unwrap_used -D clippy::panic`.
2. **ADRs Obligatoires** :
   - Toute décision architecturale Basket doit être consignée sous `adr/` et indexée dans [adr/README.md](adr/README.md).

---

## ⚡ Commandes Critiques de Vérification

- `cargo fmt --all -- --check`
- `cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic`
- `cargo test --offline --all-features`
- `./scripts/check-security.sh --strict`
- `./scripts/check-coverage.sh --summary-only`
