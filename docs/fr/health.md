# Health monitoring

## 1. Vue d'ensemble

L'agent LMDM collecte toutes les **6 heures** la santé matérielle de chaque poste et publie un `HealthSnapshot` sur NATS. Le serveur consomme et stocke en time series. Un score global calculé côté agent permet de classer les machines en :

- 🟢 **GREEN** — tout va bien
- 🟠 **ORANGE** — un sous-composant montre des signes de fatigue, à surveiller
- 🔴 **RED** — défaillance imminente ou critique, intervention nécessaire

Les sources collectées :

| Source | Outil | Fréquence |
|---|---|---|
| Disques SATA | `smartctl -j` (smartmontools) | 6h |
| Disques NVMe | `nvme smart-log -o json` (nvme-cli) | 6h |
| Batterie | sysfs (`/sys/class/power_supply/`) | 6h |
| Températures CPU/GPU | sysfs hwmon (`/sys/class/hwmon/`) | 6h |
| Firmware updates | `fwupdmgr get-updates --json` (fwupd) | 6h |

## 2. Score global

Le score global du device = pire des sous-scores. Si **un seul** disque est en RED, l'overall est RED, indépendamment du reste.

Un sous-composant absent (pas de batterie sur un desktop, pas de fwupd installé) **n'entre pas** dans le calcul — il ne pénalise pas le score.

## 3. Détail par composant

### Disques SATA (smartctl)

| Condition | Score |
|---|:-:|
| `smart_status.passed = false` | 🔴 RED |
| Reallocated sectors > 0 (attribut SMART id 5) | 🔴 RED |
| Pending sectors > 0 (id 197) | 🔴 RED |
| Uncorrectable errors > 0 (id 198) | 🔴 RED |
| Last self-test failed | 🔴 RED |
| Température ≥ 65°C | 🔴 RED |
| Température 55-64°C | 🟠 ORANGE |
| Sinon | 🟢 GREEN |

L'agent parse les attributs SMART **par ID** (5, 187, 188, 197, 198), pas par nom — les fabricants varient sur les noms mais les IDs sont normalisés. L'exit code de smartctl est un bitmask : seuls les bits "command line error" (0), "device open failed" (1) et "read failed" (2) sont fatals ; les autres bits (logged, failing past, etc.) sont informatifs et n'empêchent pas le parsing.

### Disques NVMe (nvme smart-log)

| Condition | Score |
|---|:-:|
| `critical_warning != 0` (bitmask : spare bas, temp dépassée, fiabilité dégradée, RO, volatile fail) | 🔴 RED |
| `media_errors ≥ 10` | 🔴 RED |
| `percentage_used ≥ 100` | 🔴 RED |
| `percentage_used 80-99` | 🟠 ORANGE |
| `media_errors 1-9` | 🟠 ORANGE |
| `available_spare < available_spare_threshold` | 🟠 ORANGE |
| Sinon | 🟢 GREEN |

Note : `percentage_used` peut **dépasser 100** sur un disque très usé (over-provisioning épuisé) — c'est conforme au standard NVMe.

### Batterie (sysfs)

| Condition | Score |
|---|:-:|
| `health_pct < 50` | 🔴 RED |
| `health_pct 50-79` | 🟠 ORANGE |
| `cycle_count > 1000` | 🟠 ORANGE |
| Sinon | 🟢 GREEN |

`health_pct = (energy_full / energy_full_design) × 100`, ou `(charge_full / charge_full_design) × 100` en fallback si le BIOS n'expose que les unités de charge (µAh) et pas l'énergie (µWh).

Pas de batterie présente ⇒ l'agent ne génère pas de section batterie, et le score n'est pas pénalisé.

### Températures CPU (hwmon)

| Condition | Score |
|---|:-:|
| Température ≥ seuil critique (du capteur, ou 95°C par défaut) | 🔴 RED |
| Température ≥ seuil warning (du capteur, ou 85°C par défaut) | 🟠 ORANGE |
| Sinon | 🟢 GREEN |

L'agent lit `/sys/class/hwmon/hwmon*/temp*_input` (en millidegrés Celsius) et utilise les seuils `temp*_max` (warning) et `temp*_crit` (critique) quand disponibles. Les capteurs nommés `nvme` sont ignorés (déjà couverts par le SMART NVMe). Les capteurs GPU sont remontés mais pas scorés (pas de seuil cross-vendor stable au MVP).

### Firmware updates (fwupd)

| Condition | Score |
|---|:-:|
| Au moins une update avec `urgency: critical` | 🔴 RED |
| Au moins une update avec `urgency: high` | 🟠 ORANGE |
| Sinon | 🟢 GREEN |

L'agent vérifie d'abord `systemctl is-active fwupd.service` ; si inactif, il skip (pas d'erreur). Si fwupd est absent (pas installé), même comportement. Le MVP fait **détection seulement** ; l'application des firmwares se fera dans un plan séparé.

## 4. API REST

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8080/api/v1/devices/<device-id>/health
```

Permission requise : `inventory.read` (donc Viewer/Operator/Admin tous y ont accès).

Réponse :

```json
{
  "observed_at": "2026-04-18T10:00:00Z",
  "snapshot": {
    "deviceId": {"id": "..."},
    "timestamp": "2026-04-18T10:00:00Z",
    "disks": [...],
    "battery": {...},
    "temperatures": {...},
    "firmwareUpdates": [...],
    "overallScore": "HEALTH_SCORE_GREEN"
  }
}
```

`404 Not Found` si le device n'a jamais reporté.

## 5. Dépendances système

L'agent suppose ces 3 paquets installés (à poser par `install.sh`) :

- `smartmontools` (fournit `smartctl`)
- `nvme-cli` (fournit `nvme`)
- `fwupd` (fournit `fwupdmgr`, optionnel — l'absence ne bloque pas)

Si un outil manque au runtime, l'agent log un WARN et skip la catégorie. Le score global est calculé sur ce qui a pu être collecté.

## 6. Rétention

Les snapshots sont conservés pendant **90 jours** par défaut. Au-delà, un job
goroutine côté serveur (tick 24h) supprime automatiquement les rows plus
anciennes — ~1500 snapshots/an/device en JSONB seraient ingérables sans purge.

Configurer via la variable d'environnement :

```
LMDM_HEALTH_RETENTION_DAYS=90
```

À 0 ou non défini, la valeur par défaut s'applique. Pour désactiver complètement
la purge (déconseillé), passer une valeur très grande (ex: `36500` pour 100 ans).

## 7. Dépannage

**Forcer une collecte immédiate** : redémarrer l'agent. Le runner publie un snapshot tout de suite au démarrage, puis tick toutes les 6h.

**Voir le dernier snapshot brut côté serveur** :
```sql
SELECT ts, overall_score, snapshot
FROM health_snapshots
WHERE device_id = '...'
ORDER BY ts DESC
LIMIT 1;
```

**Vérifier la dénormalisation** sur la liste devices :
```sql
SELECT id, hostname, last_health_at, last_health_score,
       battery_health_pct, fwupd_updates_count
FROM devices
WHERE tenant_id = '...';
```
