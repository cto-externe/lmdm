# LMDM — Console WebUI

La console web LMDM est embarquée dans le même binaire que le serveur API. Stack : Templ (HTML Go-typé) + HTMX (interactivité progressive) + Tailwind CSS (utilitaires). Aucune toolchain Node, aucun bundler JavaScript : un seul binaire à déployer.

## Vue d'ensemble

- Le serveur LMDM expose simultanément l'API REST sur `/api/v1/*` et la WebUI sur `/web/*` — même port, même processus.
- Auth unifiée : la même flotte JWT alimente les deux. L'API utilise le header `Authorization: Bearer`, la WebUI utilise un cookie `lmdm_session` (HttpOnly + Secure + SameSite=Strict).
- Tous les assets statiques (HTMX, CSS, favicon) sont embarqués via `go:embed` — zéro fichier additionnel à déployer.

## Installation

```
sudo apt install lmdm-server   # ou le binaire packagé pour ta distro
sudo systemctl start lmdm-server
```

Pose un reverse proxy TLS devant. Exemple Caddy :

```
lmdm.exemple.fr {
    reverse_proxy localhost:8080
}
```

L'application gère les cookies `Secure` automatiquement quand TLS est activé. Pour du dev local sans TLS, set `LMDM_WEB_DEV=1` (HSTS désactivé, cookies non-Secure pour permettre `http://localhost`).

## Configuration

Variables d'environnement reconnues :

| Variable | Description | Défaut |
|---|---|---|
| `LMDM_WEB_DEV` | Mode dev : assets servis depuis `internal/webui/assets/` au lieu de l'embed, cookies non-Secure, HSTS off | `0` |
| `LMDM_WEB_CSRF_KEY` | Clé HMAC (hex, ≥ 64 caractères) pour signer les tokens CSRF. Empty → générée au démarrage et logguée en warn (PAS multi-instance-safe). | (généré) |
| `LMDM_WEB_ASSETS_DIR` | Override du dossier static : si non vide, sert les fichiers depuis ce dossier au lieu du FS embarqué | (embed) |

Génère une clé CSRF stable :

```
openssl rand -hex 32
```

Et exporte-la dans la unit systemd ou dans ton secret manager.

## Première connexion

Crée un admin via le CLI (la WebUI ne propose pas encore de bootstrap) :

```
sudo /opt/lmdm/lmdm-user create-admin --email admin@mairie.fr
```

Le CLI affiche un mot de passe temporaire. Connecte-toi à `https://lmdm.exemple.fr/web/login`. Au premier login, le compte demande la configuration du TOTP via la CLI (la flow d'enrollment WebUI arrivera dans le plan #2).

## Pages disponibles (MVP — plan #1)

- **Login + MFA TOTP** — flow cookie-based.
- **Dashboard** — placeholder. Les widgets stats arrivent dans le plan #3.
- **Postes** — liste read-only avec filtres (nom d'hôte, état, type), pagination 25/50/100 par page, polling automatique toutes les 30 s pour rafraîchir l'état.

À venir (plans #2 et #3) :
- Profils (catalogue, création, assignation)
- Déploiements (lancement, suivi canary, rollback)
- Patch management (planification cron + politique reboot)
- Détail device (inventaire, santé, conformité)
- Journal d'audit, gestion utilisateurs, paramètres tenant

## Internationalisation

Le MVP livre uniquement le français. L'infrastructure i18n est en place pour ajouter une autre langue : déposer un fichier `internal/webui/i18n/locales/<code>.json` avec les mêmes clés que `fr.json`, recompiler. Le middleware lit la préférence dans le cookie `lmdm_locale` (à venir) ou le header `Accept-Language`, fallback FR.

## Sécurité

- **Cookies** : `lmdm_session` (JWT 15 min, HttpOnly, Secure, SameSite=Strict) ; `lmdm_refresh` (token 7 jours, HttpOnly, Secure, SameSite=Strict) ; `lmdm_csrf` (HMAC-signed, accessible JS pour HTMX, SameSite=Strict).
- **CSRF** : double-submit-cookie. Toutes les mutations (`POST`/`PATCH`/`DELETE` sous `/web/*`) requièrent le header `X-CSRF-Token` qui matche le cookie. HTMX l'injecte automatiquement.
- **CSP stricte** : `default-src 'self'`, `frame-ancestors 'none'`. `'unsafe-inline'` reste sur `script-src` et `style-src` parce que Tailwind injecte des styles inline et le layout pose un petit script CSRF dans `<head>` ; un follow-up post-MVP exploitera des nonces pour s'en passer.
- **Rate limit** : 5 tentatives de login par IP par 5 min, en mémoire. Les déploiements multi-instance auront besoin d'une backend Redis (post-MVP).
- **Headers** : HSTS (prod), X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy same-origin.

## Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| Login boucle (POST 200 puis GET 401) | Le reverse proxy ne forward pas `X-Forwarded-Proto: https` → cookie `Secure` rejeté | Configure le proxy pour forwarder le scheme |
| Tous les tokens invalidés au restart | `LMDM_WEB_CSRF_KEY` non set → clé éphémère regénérée | Pose la clé en env, idéalement dans le secret manager |
| 403 sur les POST | Cookie `lmdm_csrf` absent ou différent du header `X-CSRF-Token` | Vide les cookies, recharge `/web/login` |
| 429 Too Many Requests sur login | Rate limit (5/IP/5min) | Patiente 5 minutes ou redémarre le serveur |
| Page blanche / no CSS | `make tailwind` pas exécuté à la build | `make webui-build` puis rebuild le binaire |

## Architecture interne

Voir `internal/webui/`:
- `server.go` — Mount des routes `/web/*`, chaîne de middlewares, embed des assets
- `handlers/` — `auth.go`, `dashboard.go`, `devices.go`
- `templates/` — pages `.templ` (compilées en `_templ.go`)
- `components/` — composants Templ réutilisables (nav, button, flash, pagination)
- `csrf/`, `ratelimit/`, `security/`, `i18n/` — middlewares et helpers
- `assets/` — `htmx.min.js`, `app.css` (Tailwind build), `favicon.ico` embarqués
