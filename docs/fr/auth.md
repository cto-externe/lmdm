# Authentification console et RBAC

## 1. Bootstrap — génération des clés

Avant le premier démarrage, générer la paire de clés JWT (ECDSA P-256) et la clé maître AES-256 :

```bash
make keys
# ou directement :
go run ./cmd/lmdm-keygen --out deploy/secrets
```

Trois fichiers sont créés dans `deploy/secrets/` :
- `jwt-priv.pem` — clé privée JWT (chmod 0600, NE JAMAIS commit)
- `jwt-pub.pem` — clé publique, pour un futur endpoint JWKS
- `enc-key.b64` — clé maître AES-256 (chmod 0600, utilisée pour chiffrer les secrets TOTP)

Le dossier `deploy/secrets/` est gitignoré.

## 2. Création du premier administrateur

```bash
export LMDM_PG_DSN='postgres://lmdm:lmdm@localhost:5432/lmdm?sslmode=disable'
export LMDM_ENC_KEY_PATH=deploy/secrets/enc-key.b64

go run ./cmd/lmdm-user create-admin --email admin@exemple.fr
```

Le CLI :
1. Demande un mot de passe (min 12 caractères, pas de règle de complexité — préférer une passphrase longue)
2. Crée le compte en base avec le rôle `admin`
3. Génère un secret TOTP et l'affiche avec l'URI `otpauth://...`
4. Scannez l'URI (ou copiez le secret) dans votre application TOTP : FreeOTP, Aegis, 1Password, Bitwarden, etc.

Le secret TOTP est affiché **une seule fois**. Stocké chiffré en base avec AES-256-GCM par la suite.

## 3. Connexion à l'API

La connexion est en 2 étapes : mot de passe, puis code TOTP à 6 chiffres.

```bash
# Étape 1 — mot de passe
curl -X POST http://localhost:8080/api/v1/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@exemple.fr","password":"..."}'
# Réponse : { "step_up_token": "eyJ...", "needs_mfa_verify": true }

# Étape 2 — code TOTP
curl -X POST http://localhost:8080/api/v1/auth/mfa/verify \
     -H 'Content-Type: application/json' \
     -d '{"step_up_token":"eyJ...","code":"123456"}'
# Réponse : { "access_token": "...", "refresh_token": "...", "expires_at": 1718...}
```

- `access_token` : JWT ES256, durée de vie **15 minutes**.
- `refresh_token` : chaîne opaque, durée de vie **7 jours**, **rotated à chaque usage** (réutilisation détectée → toute la famille est révoquée).

Pour appeler un endpoint protégé :

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8080/api/v1/devices
```

## 4. Rôles et permissions

| Permission | Viewer | Operator | Admin |
|---|:-:|:-:|:-:|
| Lire devices, inventaire, conformité, updates | ✓ | ✓ | ✓ |
| Lire les profils | ✓ | ✓ | ✓ |
| Assigner un profil à un device |  | ✓ | ✓ |
| Appliquer des patches (`POST /updates/apply`) |  | ✓ | ✓ |
| Créer des tokens d'enrôlement agent |  | ✓ | ✓ |
| Créer un profil |  |  | ✓ |
| Gérer les utilisateurs (CRUD) |  |  | ✓ |

## 5. Gestion des utilisateurs

**Créer un opérateur ou viewer** (depuis la console admin authentifiée) :

```bash
curl -X POST http://localhost:8080/api/v1/users \
     -H "Authorization: Bearer $ADMIN_ACCESS" \
     -H 'Content-Type: application/json' \
     -d '{"email":"tech@exemple.fr","role":"operator","password":"motdepassefort12"}'
```

Le nouvel utilisateur devra enrôler son TOTP à sa première connexion (le flow `POST /auth/login` → `POST /auth/mfa/enroll` → `POST /auth/mfa/verify`).

**Réinitialiser un mot de passe** :

```bash
curl -X POST http://localhost:8080/api/v1/users/{id}/reset-password \
     -H "Authorization: Bearer $ADMIN_ACCESS"
# Réponse : { "temporary_password": "..." }
```

Le mot de passe temporaire est retourné **une seule fois** ; transmettre hors bande. Toutes les sessions de l'utilisateur sont révoquées. L'utilisateur devra changer son mot de passe à la prochaine connexion.

**Désactiver un utilisateur** :

```bash
curl -X PATCH http://localhost:8080/api/v1/users/{id} \
     -H "Authorization: Bearer $ADMIN_ACCESS" \
     -H 'Content-Type: application/json' \
     -d '{"active":false}'
```

Effet immédiat : login refusé + sessions révoquées. Pour réactiver : `{"active":true}`.

**Débloquer un compte verrouillé (5 échecs → 15 min de lockout)** :

```bash
go run ./cmd/lmdm-user unlock tech@exemple.fr
```

## 6. Sécurité

- Mots de passe hashés avec **argon2id** (paramètres OWASP 2026 : 64 MiB × 2 passes × 1 thread)
- Secrets TOTP chiffrés au repos avec **AES-256-GCM**
- JWT signés avec **ECDSA P-256** (algorithme ES256)
- Refresh tokens opaques SHA-256 avec **rotation et détection de réutilisation** : si un refresh déjà tourné est réutilisé, toute sa famille est révoquée et toutes les sessions de l'utilisateur sont terminées
- Rate limit : 10 tentatives de login / IP / 10 min ; 60 refresh / IP / min
- Account lockout : 5 échecs consécutifs → compte verrouillé 15 min
- Audit log : tous les events d'authentification (login, logout, mfa, locked, password change/reset) + toutes les mutations API (profile create/assign, token create, updates apply)
- Tenant row-level security : `lmdm.tenant_id` scope PostgreSQL sur toutes les tables

## 7. Révocation d'urgence

Compte compromis :

```bash
go run ./cmd/lmdm-user deactivate user@exemple.fr
```

Effet immédiat : login refusé, refresh tokens révoqués, access tokens en cours expirent sous 15 min (pas plus).

Pour une rotation complète des clés (sans ré-émettre chaque refresh manuellement), régénérer la keypair JWT et redémarrer le serveur : toutes les sessions existantes deviennent invalides instantanément.
