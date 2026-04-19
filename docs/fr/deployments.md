# Déploiements canary et rollback

## 1. Vue d'ensemble

LMDM applique les profils de sécurité **en deux temps** pour limiter le rayon
d'explosion d'une mauvaise configuration :

1. **Canary** — le profil est d'abord poussé sur **un seul device** désigné comme
   canary. L'agent applique, exécute les health checks post-application puis
   confirme via NATS.
2. **Validation** — selon le mode choisi (`manual`, `semi_auto` ou `auto`), le
   serveur attend une décision admin, un timer, ou rollout immédiat.
3. **Rollout** — si validé, le profil est poussé en parallèle sur le reste des
   devices ciblés. Un seuil d'abort (10 % par défaut) interrompt le rollout si
   trop de devices échouent.

En cas d'échec du canary (apply en erreur, health check rouge, timeout NATS),
le rollout n'est **jamais déclenché** et l'agent canary rollback automatiquement
à son snapshot pré-application.

## 2. Machine à états

Un déploiement traverse l'un des chemins suivants entre 9 statuts persistés en
base (`deployments.status`) :

```
                   ┌─────────┐
                   │ planned │
                   └────┬────┘
                        │ Engine.Start (push canary)
                        ▼
                ┌────────────────┐
                │ canary_running │
                └───┬────────┬───┘
       success     │        │     failure / timeout / health KO
                   ▼        ▼
            ┌───────────┐  ┌───────────────┐
            │ canary_ok │  │ canary_failed │ ── (état terminal)
            └─────┬─────┘  └───────────────┘
                  │
                  │ mode=auto                    mode=manual / semi_auto
                  │                                       │
                  │                                       ▼
                  │                           ┌──────────────────────┐
                  │                           │ awaiting_validation  │
                  │                           └──────┬───────────┬───┘
                  │                       admin OK  │           │ admin rollback
                  │                                 │           ▼
                  │   ┌─────────────────────────────┘   ┌──────────────┐
                  │   │                                 │ rolled_back  │
                  ▼   ▼                                 └──────────────┘
              ┌──────────────┐
              │ rolling_out  │ ── push parallèle sur les targets restants
              └──────┬───────┘
                     │
        success      │      ≥ 10 % d'échecs
        ┌────────────┴────────────┐
        ▼                         ▼
 ┌────────────┐         ┌──────────────────┐
 │ completed  │         │ partially_failed │
 └────────────┘         └──────────────────┘
```

Les transitions interdites (ex : un `Validate` reçu en `canary_running`) sont
des no-op loggés WARN — jamais de panic ni de corruption d'état.

## 3. Modes de validation

Trois modes au choix lors de la création du déploiement :

| Mode | Comportement après `canary_ok` |
|---|---|
| `manual` | Bloque indéfiniment en `awaiting_validation`. Un admin doit appeler `POST /deployments/{id}/validate` (ou `/rollback`) pour avancer. |
| `semi_auto` | Bloque en `awaiting_validation` avec un timer (`validation_timeout_s`, défaut **30 min = 1800 s**). À l'expiration, validation automatique → `rolling_out`. Un admin peut intervenir avant l'expiration. |
| `auto` | Aucune attente : transition directe `canary_ok` → `rolling_out` dès la confirmation canary. À réserver aux profils non-critiques ou aux environnements de test. |

Le mode par défaut (si non précisé) est `manual`.

## 4. Watchdog agent et rollback automatique

Côté agent, chaque application de profil suit un protocole strict pour rester
cohérent même en cas de crash, perte réseau ou timeout NATS :

1. **Snapshot** — l'agent capture l'état pré-application (paquets, services,
   sysctl, fichiers).
2. **Persistance pending** — le snapshot + le `deployment_id` sont écrits dans
   un bucket BoltDB local (`pending` bucket). Atomique, survit au crash.
3. **Apply** — exécution des actions. En cas d'échec → rollback immédiat depuis
   le snapshot, pending nettoyé, `CommandResult{success=false, rolled_back=true}`
   publié.
4. **Health checks** — après apply, exécution des checks (built-in + custom). Un
   échec déclenche le même rollback que ci-dessus.
5. **Ack JetStream** — l'agent attend l'ack du serveur dans une fenêtre de
   **10 s**. Si l'ack n'arrive pas (timeout NATS, partition réseau), l'agent
   rollback localement mais **ne nettoie pas le pending** : le serveur ne sait
   pas si l'application a réussi, et l'état BoltDB sert au sweep de redémarrage.
6. **Sweep au démarrage** — au boot de l'agent, tout pending plus vieux que
   **5 minutes** est considéré comme stale (l'agent a probablement crashé en
   cours d'apply). L'agent rollback depuis le snapshot persisté et publie un
   `CommandResult{rolled_back=true}` au serveur.

Conséquence pratique : un agent qui crash en plein apply, redémarre 30 minutes
plus tard, retrouvera son snapshot pre-apply, restaurera l'état initial, et
notifiera le serveur qui marquera le device en `rolled_back` dans
`deployment_results`.

## 5. Health checks

Après chaque `Apply`, l'agent exécute la batterie de health checks définie dans
le profil. Si un check échoue, l'apply est considéré comme un échec et l'agent
rollback automatiquement.

**4 checks built-in** (toujours exécutés, indépendants du profil) :

| Check | Vérifie |
|---|---|
| `system.nats_reachable` | L'agent peut publier sur le bus NATS du serveur |
| `system.dbus_active` | `systemctl is-active dbus` |
| `system.networking_active` | `systemctl is-active NetworkManager` ou `systemd-networkd` |
| `system.ssh_active` | `systemctl is-active sshd` ou `ssh` (selon distro) |

**5 types de checks custom** (déclarés dans le profil YAML, champ
`health_checks`) :

| Type | Paramètres | Critère |
|---|---|---|
| `HTTPGetCheck` | `url`, `expected_status` (défaut 200), `timeout_s` (défaut 5) | Status HTTP attendu reçu dans le timeout |
| `TCPConnectCheck` | `host`, `port`, `timeout_s` | TCP handshake réussit |
| `ProcessCheck` | `name` | Au moins un PID correspond (parsing `/proc`) |
| `ServiceCheck` | `unit` | `systemctl is-active <unit>` retourne `active` |
| `CommandCheck` | `command` (argv), `expected_exit` (défaut 0), `timeout_s` | Exit code attendu |

Un check `ProcessCheck` ou `ServiceCheck` qui retourne `Passed=false` est traité
comme un échec applicatif → rollback. Un type inconnu retourne
`Passed=false, Detail="unknown check type"`.

## 6. API REST

5 endpoints sur `http://localhost:8080/api/v1/deployments`. Toutes les requêtes
nécessitent un `Authorization: Bearer $ACCESS_TOKEN` (voir
[auth.md](auth.md)).

| Endpoint | Méthode | Permission |
|---|---|---|
| `/api/v1/deployments` | POST | `deployments.manage` (Operator/Admin) |
| `/api/v1/deployments` | GET | `deployments.read` (Viewer/Operator/Admin) |
| `/api/v1/deployments/{id}` | GET | `deployments.read` |
| `/api/v1/deployments/{id}/validate` | POST | `deployments.manage` |
| `/api/v1/deployments/{id}/rollback` | POST | `deployments.manage` |

### Créer un déploiement

```bash
curl -X POST http://localhost:8080/api/v1/deployments \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{
       "profile_id": "0c5a9f10-...-...",
       "canary_device_id": "8e1b...-...",
       "target_device_ids": [
         "8e1b...-...",
         "9f2c...-...",
         "ab3d...-..."
       ],
       "validation_mode": "semi_auto",
       "validation_timeout_s": 1800,
       "failure_threshold_pct": 10
     }'
```

Notes :
- Le `canary_device_id` **doit** apparaître dans `target_device_ids`.
- Champs optionnels : `validation_mode` (défaut `manual`),
  `validation_timeout_s` (défaut 1800 s = 30 min),
  `failure_threshold_pct` (défaut 10).
- Réponse 201 avec l'objet déploiement complet (status `planned`, puis le
  Engine passe à `canary_running` et publie l'`ApplyProfileCommand` au canary).

### Lister les déploiements

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     'http://localhost:8080/api/v1/deployments?status=awaiting_validation'
```

Le filtre `status` est optionnel. Sans filtre, tous les déploiements du tenant
sont retournés (ordre `created_at DESC`).

### Détailler un déploiement

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8080/api/v1/deployments/$DEPLOY_ID
```

Renvoie le déploiement + le tableau `results` (une ligne par device, canary en
premier). Chaque résultat porte `status` (`pending`, `applying`, `success`,
`failed`, `rolled_back`), un `error_message` éventuel, et les timestamps
`applied_at` / `rolled_back_at`.

### Valider (déclencher le rollout)

```bash
curl -X POST http://localhost:8080/api/v1/deployments/$DEPLOY_ID/validate \
     -H "Authorization: Bearer $ACCESS_TOKEN"
```

Transition `awaiting_validation` → `rolling_out`. Pas de body. Erreur 409 si le
déploiement n'est pas en `awaiting_validation`. Une entrée d'audit
`deployment.validated` est écrite.

### Forcer un rollback

```bash
curl -X POST http://localhost:8080/api/v1/deployments/$DEPLOY_ID/rollback \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"reason":"profil incompatible avec le parc Lenovo"}'
```

Le `reason` est optionnel mais recommandé (stocké dans `deployments.reason`,
visible dans l'audit). Tous les devices déjà appliqués reçoivent un
`RollbackCommand` ; les devices restants sont marqués `rolled_back` sans recevoir
le profil. Audit : `deployment.rolled_back_by_admin`.

## 7. Stratégie de rollout

Une fois en `rolling_out`, le serveur publie en **parallèle** un
`ApplyProfileCommand` à chaque device cible (hors canary, déjà appliqué). Pas de
phasage par lots au MVP — c'est le `failure_threshold_pct` qui borne le risque.

**Seuil d'abort** : si le pourcentage de devices en `failed` ou `rolled_back`
dépasse `failure_threshold_pct` (défaut 10) sur le sous-ensemble qui a déjà
répondu, le rollout est arrêté. Le déploiement passe alors en
`partially_failed`. Les devices déjà appliqués avec succès **ne sont pas**
rollback automatiquement (à l'admin de décider via `POST /rollback`).

À la fin du rollout :
- 100 % de succès → `completed`
- ≥ 1 échec mais sous le seuil → `completed` (les échecs restent visibles dans
  `deployment_results`)
- échecs au-dessus du seuil → `partially_failed`

## 8. Dépannage

### Forcer un rollback admin

Si un déploiement est bloqué (canary OK mais l'admin a un doute, ou rollout
partiellement raté), un `POST /rollback` avec un `reason` clair est la bonne
réponse. L'opération est idempotente : un déploiement déjà `rolled_back` ou
`completed` retourne 409.

### Inspecter les résultats par device

```sql
SELECT device_id, is_canary, status, error_message,
       applied_at, rolled_back_at
FROM deployment_results
WHERE deployment_id = '...'
ORDER BY is_canary DESC, device_id;
```

La colonne `snapshot_id` référence le snapshot policy persisté côté agent — sert
au support pour corréler avec les logs agent.

### Agent bloqué en `applying`

Symptôme : le `deployment_results` du device reste en `applying` indéfiniment,
pas d'event de l'agent.

Causes possibles :
1. **Timeout NATS côté agent** : l'agent a appliqué mais l'ack JetStream n'est
   pas remonté (le rollback local a eu lieu, mais le `CommandResult` reste à
   publier au prochain reboot).
2. **Crash agent en plein apply** : le pending state BoltDB sera traité au
   redémarrage de l'agent (sweep des stale > 5 min) ; le `CommandResult` arrivera
   alors avec `rolled_back=true`.
3. **Agent offline** : le device est éteint ou déconnecté. Le
   `ApplyProfileCommand` reste en queue NATS jusqu'à expiration du stream.

**Action** : laisser 5-10 minutes pour le sweep agent, puis si toujours bloqué,
forcer un `POST /rollback` côté serveur. L'admin pourra ensuite recréer un
déploiement sur un parc cible plus restreint.

### Inspecter le pending côté agent

Sur le device concerné :

```bash
# le bucket BoltDB de l'agent
ls -la /var/lib/lmdm-agent/state.db
# inspection : utiliser bbolt CLI si disponible
sudo bbolt buckets /var/lib/lmdm-agent/state.db
sudo bbolt keys /var/lib/lmdm-agent/state.db pending
```

Une clé `pending` non vide après plus de 5 min sans activité agent indique un
état stale qui sera nettoyé au prochain redémarrage.

### Voir l'audit trail

```sql
SELECT ts, actor_user_id, action, target_id, metadata
FROM audit_events
WHERE action LIKE 'deployment.%'
  AND target_id = '...'
ORDER BY ts;
```

Les actions trackées : `deployment.created`, `deployment.validated`,
`deployment.rolled_back_by_admin`.
