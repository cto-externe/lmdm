# Patch management — Guide opérateur

## Vue d'ensemble

LMDM détecte périodiquement les mises à jour disponibles via `apt list --upgradable` (ou `dnf`) et publie un `PatchReport` vers le serveur. En complément de cette détection continue, trois nouvelles fonctionnalités sont disponibles :

1. **Schedules d'application côté serveur** — `patch_schedules` permet de planifier l'application automatique des patches via une expression cron.
2. **Politique de reboot hybride** — trois valeurs configurables au niveau tenant, overridables par device.
3. **Agent de reboot session-aware** — l'agent vérifie les sessions actives avant de redémarrer, avec compteur de report et forçage automatique.

---

## Reboot policy — les 3 valeurs

| Valeur | Comportement |
|---|---|
| `admin_only` | L'agent ne reboot **jamais** de lui-même. L'admin déclenche manuellement via `POST /devices/{id}/reboot`. C'est la valeur **par défaut**. |
| `immediate_after_apply` | Après un apply de patches réussi avec `reboot_required=true`, l'agent enchaîne immédiatement un reboot (skip si utilisateur actif — voir [Comportement agent](#comportement-agent--session-check--defer-counter)). |
| `next_maintenance_window` | L'agent attend la prochaine fenêtre de maintenance définie par le champ `maintenance_window` (expression cron, ex. `"0 22 * * 2"` = mardi 22h00). |

**Ordre de résolution de la policy :**

1. `device.reboot_policy_override` (si non-null) — prend la priorité
2. `tenant.reboot_policy` — valeur de fallback tenant

Le même ordre s'applique à `maintenance_window` vs `maintenance_window_override`.

---

## Maintenance window — syntaxe

Le champ `maintenance_window` utilise le format cron standard à 5 champs :

```
minute heure jour-du-mois mois jour-de-la-semaine
```

Exemples :

| Expression | Signification |
|---|---|
| `0 22 * * 2` | Mardi à 22h00 |
| `0 3 * * *` | Tous les jours à 3h00 |
| `0 5 * * 0` | Dimanche à 5h00 |
| `30 1 * * 1,3,5` | Lundi, mercredi, vendredi à 1h30 |

> **Attention — timezone :** Le serveur opère en **UTC**. Penser au décalage horaire (Paris hiver = UTC+1, été = UTC+2).
> Exemple : pour cibler minuit heure de Paris en hiver, utiliser `0 23 * * *`.
>
> Follow-up post-MVP : gestion timezone par tenant via `tenant.timezone`.

---

## Planifier une application

Permission requise : `patch_schedules.manage` (rôle Admin ou Operator).

```bash
# Schedule à appliquer toutes les nuits à 3h, sécurité uniquement, sur tout le tenant
curl -X POST http://lmdm-server/api/v1/patch-schedules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cron_expr": "0 3 * * *",
    "filter_security_only": true
  }'

# Schedule sur un device précis (override d'une fenêtre globale)
curl -X POST http://lmdm-server/api/v1/patch-schedules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cron_expr": "0 5 * * 0",
    "device_id": "AAAA...",
    "filter_include_packages": ["nginx", "openssl"]
  }'
```

Le scheduler côté serveur ticke toutes les **60 secondes**. Contrainte : 1 schedule max par scope `(tenant, device)`.

---

## Configurer la reboot policy au niveau tenant

```bash
curl -X PATCH http://lmdm-server/api/v1/tenants/current/reboot-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reboot_policy": "next_maintenance_window", "maintenance_window": "0 22 * * 2"}'
```

---

## Override par device

```bash
# Forcer un device en admin_only (poste serveur métier)
curl -X PATCH http://lmdm-server/api/v1/devices/{id}/reboot-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reboot_policy_override": "admin_only", "maintenance_window_override": null}'

# Restaurer le défaut tenant : passer null sur les deux champs
curl -X PATCH http://lmdm-server/api/v1/devices/{id}/reboot-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reboot_policy_override": null, "maintenance_window_override": null}'
```

---

## Déclencher un reboot admin

Permission requise : `devices.reboot`.

```bash
curl -X POST http://lmdm-server/api/v1/devices/{id}/reboot \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "kernel_update", "grace_period_seconds": 300, "force": false}'
```

Paramètres :

- `reason` — chaîne libre enregistrée dans l'audit log.
- `grace_period_seconds` — délai entre le `wall` broadcast et le reboot effectif. Défaut : **300** (5 minutes).
- `force` — si `true`, ignore la vérification de session ET le compteur de reports (`defer_count`). Le reboot est immédiat.

---

## Comportement agent — session check + defer counter

Avant chaque reboot non-forcé, l'agent effectue les étapes suivantes :

1. **Vérification de session** — appel à `loginctl list-sessions` (fallback : `who`). Si une session interactive est détectée : le reboot est différé et le compteur `pending_reboot_defer_count` est incrémenté en BoltDB.
2. **Compteur de reports** — après `max_defer_count` reports consécutifs (défaut : **3**), l'agent **force le reboot** avec un `wall` broadcast 5 minutes avant.
3. **Publication du rapport** — l'agent publie un `RebootReport` sur `status.device.{id}.reboot-report` à chaque tentative.

Outcomes possibles dans le `RebootReport` :

| Outcome | Signification |
|---|---|
| `rebooted` | Reboot effectué avec succès |
| `deferred_user_active` | Session active détectée, reboot différé |
| `forced_after_max_defers` | Seuil `max_defer_count` atteint, reboot forcé |
| `error` | Erreur lors de la tentative de reboot |

Le serveur met à jour `devices.pending_reboot_defer_count` et l'`audit_log` à la réception de chaque `RebootReport`.

---

## Missed window — tolérance 24h

- Si le serveur était **indisponible** au moment où un schedule devait s'exécuter, il le rattrape **dans les 24 heures** suivant son retour en ligne.
- Au-delà de 24h de retard : le run est skippé et `skipped_runs_count` est incrémenté (visible via `GET /api/v1/patch-schedules/{id}`).
- Pas de catch-up en rafale : un schedule manqué = au mieux 1 run de rattrapage.

---

## Troubleshooting

### Le schedule n'a pas tiré

Vérifier `last_run_status` via :

```bash
GET /api/v1/patch-schedules/{id}
```

| Valeur `last_run_status` | Cause probable |
|---|---|
| `publish_error` | Problème NATS ou erreur de parsing cron |
| `skipped_missed_window` | Schedule en retard de plus de 24h |

### Le device ne reboot pas

Vérifier `pending_reboot_defer_count` sur le device :

```bash
GET /api/v1/devices/{id}
```

Si `pending_reboot_defer_count > 0`, des sessions utilisateurs actives ont empêché le reboot lors des tentatives précédentes. Forcer via :

```bash
curl -X POST http://lmdm-server/api/v1/devices/{id}/reboot \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"force": true}'
```

### Logs agent

```bash
journalctl -u lmdm-agent | grep reboot
```

Termes à rechercher : `defer limit reached`, `user session active`, `reboot deferred`.

### Audit trail

La table `audit_log` enregistre les événements suivants :

- `device.reboot`
- `tenant.policy.updated`
- `device.policy_override.updated`
- `patch_schedule.create`
- `patch_schedule.delete`

---

## Limitations MVP

- **Pas de groupes de devices** — les overrides s'appliquent par device individuel uniquement (le resolver est conçu pour être étendu).
- **Pas de dialog GUI postpone** — broadcast `wall` uniquement (un follow-up GTK/Qt est noté pour permettre à l'utilisateur de différer interactivement).
- **Maintenance window UTC seulement** — pas de gestion timezone par tenant (post-MVP : `tenant.timezone`).
- **Pas de policy `auto_immediate_for_security`** — impossible de forcer un reboot hors fenêtre uniquement pour les patches de sécurité.
- **Pas de schedules concurrents par scope** — 1 row max par `(tenant, device)`.
- **NixOS non supporté** — `DetectUpdates` refuse silencieusement sur NixOS.
