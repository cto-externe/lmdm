# mTLS transport et PKI X.509

## 1. Vue d'ensemble

LMDM chiffre et authentifie mutuellement **tous les canaux** entre le serveur, les agents et la console (gRPC, NATS, REST) via une PKI X.509 dédiée. L'objectif : un agent ne peut pas parler au serveur sans certificat signé par la CA LMDM, et le serveur ne peut pas être usurpé — les deux pairs présentent un certificat valide au handshake TLS.

Architecture PKI :

```
        LMDM Root CA (ca.crt + ca.key)
               │
       ┌───────┴────────┐
       │                │
  server.crt        agent.crt  (un par poste, émis à l'enrôlement)
       │                │
  serveur          agent Linux
```

- **CA LMDM** auto-générée au bootstrap, ou fournie par l'opérateur (voir §3).
- **Serveur** : cert TLS avec SAN `DNS:<hostname>` + `IP:127.0.0.1,::1`, signé par la CA.
- **Agents** : cert TLS émis à l'enrôlement via CSR, CN = device ID, durée de vie 1 an.
- **TLS 1.3** uniquement, avec échange de clés post-quantique hybride **X25519MLKEM768** (voir §5).

Cette couche est **complémentaire** à la signature post-quantique du `SignedAgentCert` (Ed25519 + ML-DSA) qui reste délivrée en parallèle — voir §8 sur la défense en profondeur.

## 2. Bootstrap — génération de la CA et des clés

```bash
make keys
# ou directement :
go run ./cmd/lmdm-keygen --out deploy/secrets --server-dns <hostname>
```

Fichiers produits dans `deploy/secrets/` :

| Fichier | Rôle | Perms |
|---|---|:-:|
| `ca.crt` | CA LMDM (distribuer aux agents) | 0644 |
| `ca.key` | CA LMDM privée (serveur uniquement, NE JAMAIS distribuer) | 0600 |
| `server.crt` | Cert TLS serveur signé par la CA | 0644 |
| `server.key` | Clé privée TLS serveur | 0600 |
| `jwt-priv.pem` | Clé privée JWT ES256 (console admin) | 0600 |
| `jwt-pub.pem` | Clé publique JWT (futur JWKS) | 0644 |
| `enc-key.b64` | Clé maître AES-256 (secrets TOTP) | 0600 |

Options de `lmdm-keygen` :

- `--server-dns <hostname>` (répétable) : SAN DNS du cert serveur, par défaut `localhost`
- `--server-ip <addr>` (répétable) : SAN IP, par défaut `127.0.0.1`, `::1`
- `--server-cn <name>` : CN du cert serveur, par défaut `lmdm-server`

Le dossier `deploy/secrets/` est gitignoré. En production, monter la CA privée (`ca.key`) uniquement sur le serveur, jamais sur les agents.

## 3. CA externe (override)

Pour utiliser une CA fournie par l'opérateur (PKI interne, Vault, HSM, etc.), exporter :

```bash
export LMDM_CA_CERT_PATH=/etc/lmdm/pki/ca.crt
export LMDM_CA_KEY_PATH=/etc/lmdm/pki/ca.key
```

Le serveur utilise ces chemins au lieu des valeurs par défaut (`deploy/secrets/ca.crt` / `ca.key`). Dans ce cas, ne pas lancer `make keys` — la CA préexistante est réutilisée, et `lmdm-keygen` peut être appelé avec une CA déjà en place pour générer uniquement les cert serveur et JWT/enc.

Contraintes sur la CA externe :

- Cert X.509 avec `CA:TRUE`, `keyUsage = digitalSignature, keyCertSign`
- Clé privée compatible (EC P-256 recommandé, RSA 3072+ accepté)
- Durée de vie cohérente avec le parc (>= 5 ans typique)

## 4. Enrôlement agent

L'agent ne reçoit **jamais** de clé privée du serveur. Le flow :

1. L'opérateur émet un token d'enrôlement (`lmdm-token` ou API REST).
2. L'agent génère localement une keypair ECDSA P-256 + une CSR (certificate signing request).
3. L'agent envoie token + CSR au serveur via gRPC.
4. Le serveur vérifie le token, signe la CSR avec la CA, retourne le cert X.509 + `SignedAgentCert` proto (double signature PQ).
5. L'agent stocke `agent.crt` + `agent.key` + `ca.crt` dans `--data-dir`.

Commande :

```bash
lmdm-agent enroll \
    --server=lmdm.exemple.fr:50051 \
    --token=<plaintext-token> \
    --ca-cert=/path/to/ca.crt \
    --data-dir=/var/lib/lmdm
```

Le flag `--ca-cert` est **obligatoire** : l'agent doit vérifier le cert serveur avant d'envoyer son token (trust on first install, via déploiement Ansible/image système). La clé privée de l'agent est générée localement et **ne quitte jamais le poste** — conformité §7.3 du spec.

## 5. TLS 1.3 et échange de clés post-quantique

LMDM impose **TLS 1.3 uniquement** (côté serveur et côté agents). Les versions antérieures sont refusées.

Échange de clés par ordre de préférence :

1. **X25519MLKEM768** — hybride post-quantique (ML-KEM-768 + X25519), résistant aux attaques "harvest now, decrypt later". Standard NIST FIPS 203 + draft IETF.
2. **X25519** — fallback classique si le pair ne supporte pas l'hybride PQ.
3. **P-256** — fallback ultime pour compatibilité.

Le mode hybride garantit que si l'une des deux primitives (X25519 *ou* ML-KEM) est cassée, la session reste confidentielle grâce à l'autre. Les agents Go 1.26 négocient X25519MLKEM768 par défaut (rolled out upstream en Go 1.24).

## 6. Renouvellement automatique

L'agent embarque un `agenttls.Renewer` lancé dans le runner principal. Tick **quotidien** : si le cert expire dans **moins de 30 jours**, l'agent appelle le RPC `RenewCertificate` via le canal mTLS courant (le cert qui va expirer sert d'auth pour sa propre succession).

Flow :

1. Agent génère une **nouvelle keypair** + CSR (rotation complète, pas de réutilisation de la clé privée).
2. Agent appelle `RenewCertificate(CSR)` sur le gRPC authentifié par le cert courant.
3. Serveur vérifie que le device ID du cert mTLS correspond au CN de la CSR, signe, retourne.
4. Agent remplace atomiquement `agent.crt` + `agent.key` sur disque.

En cas d'échec (serveur injoignable, cert déjà révoqué, etc.), le renew est retenté à chaque tick suivant — tant que le cert n'est pas expiré, l'agent continue de fonctionner normalement. Pas de backoff exponentiel : tick quotidien stable pendant les 30 derniers jours laisse jusqu'à 30 tentatives avant expiration.

## 7. Révocation

Compromission d'un poste, départ d'un agent du parc, perte de matériel : l'admin révoque le cert via l'API REST.

```bash
curl -X POST http://localhost:8080/api/v1/devices/<device-id>/revoke \
     -H "Authorization: Bearer $ADMIN_ACCESS" \
     -H 'Content-Type: application/json' \
     -d '{"reason":"lost laptop — employee offboarding"}'
```

Permission requise : `devices.revoke` — **Admin uniquement** (ni Operator, ni Viewer).

Effets immédiats (synchrones) :

1. Insertion du `serial_number` dans la table `revoked_certificates` (migration 0013), avec `revoked_at` + `reason`.
2. Broadcast NATS sur le sujet `fleet.broadcast.cert_revoked` → toutes les instances du serveur (horizontal scale) invalident leur cache en mémoire.
3. Le prochain handshake TLS présenté avec ce cert est rejeté par le callback `VerifyPeerCertificate` — effet immédiat, pas besoin d'attendre l'expiration.

Le device passe en statut `revoked` et ne peut plus établir de session mTLS. Pour ré-admettre le poste, il faut ré-enrôler (nouveau token + `lmdm-agent enroll`).

## 8. Défense en profondeur : double signature

LMDM conserve le `SignedAgentCert` proto (Ed25519 + ML-DSA-65, voir §6 du spec) **en parallèle** du cert X.509 classique. Objectif : survivre à une rupture cryptographique future.

| Couche | Algorithme | Rôle |
|---|---|---|
| X.509 TLS | ECDSA P-256 | Authentification de transport, standard industriel |
| `SignedAgentCert` proto | Ed25519 + ML-DSA-65 | Identité logique, résistante aux attaques quantiques |

Si un adversaire quantique casse ECDSA P-256 :
- Les sessions TLS passées peuvent être déchiffrées si l'attaquant a enregistré le trafic ET cassé X25519 — **mitigé par X25519MLKEM768** (voir §5).
- L'identité de l'agent reste vérifiable via la signature ML-DSA du `SignedAgentCert`.

Cette redondance a un coût (~3.3 KB supplémentaires par agent signé) mais donne une marge de sécurité sur 10-20 ans — la durée de vie réaliste d'un parc LMDM.

## 9. Dépannage

**Inspecter un cert agent** :

```bash
openssl x509 -in /var/lib/lmdm/tls/agent.crt -text -noout
```

Vérifier : `Issuer: CN=LMDM Root CA`, `Subject: CN=<device-id>`, `Not After: <date>`, extensions `keyUsage` et `extendedKeyUsage = clientAuth`.

**Vérifier la chaîne de confiance** :

```bash
openssl verify -CAfile /var/lib/lmdm/tls/ca.crt /var/lib/lmdm/tls/agent.crt
# -> /var/lib/lmdm/tls/agent.crt: OK
```

Si `unable to get local issuer certificate` : la CA chargée côté agent ne correspond pas à celle qui a signé le cert — re-distribuer `ca.crt`.

**Debug handshake TLS** :

```bash
GODEBUG=tls=1 lmdm-agent run --data-dir=/var/lib/lmdm ...
```

Affiche le détail de la négociation TLS (version, cipher suite, groupe d'échange de clés). Vérifier que `CurveID` affiche bien X25519MLKEM768 en prod.

**Lister les certs révoqués** côté serveur :

```sql
SELECT serial_number, revoked_at, reason
FROM revoked_certificates
ORDER BY revoked_at DESC
LIMIT 20;
```

**Forcer un renew** (ex: cert suspecté corrompu, tests) : supprimer `agent.crt` + `agent.key`, relancer `lmdm-agent enroll` avec un nouveau token. L'ancien cert reste valide jusqu'à révocation explicite ou expiration — si le poste change d'identité, révoquer manuellement l'ancien.

**Handshake refusé avec `bad certificate`** côté agent : vérifier que le cert serveur a bien le hostname cible en SAN (`openssl x509 -in server.crt -text -noout | grep -A1 "Subject Alternative Name"`). Régénérer avec `lmdm-keygen --server-dns <hostname>` si nécessaire.
