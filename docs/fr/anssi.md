# Guide opérateur — Profils ANSSI-BP-028

## 1. Vue d'ensemble

Le guide ANSSI-BP-028 v2.0 (« Recommandations de configuration d'un système GNU/Linux »,
03/10/2022) définit 80 recommandations organisées en **quatre niveaux de durcissement** :

| Niveau | Symbole | Usage cible |
|--------|---------|-------------|
| Minimal | **M** | Niveau de base applicable à tous les systèmes GNU/Linux |
| Intermédiaire | **I** | Systèmes traitant des données sensibles ou personnelles |
| Renforcé | **R** | Postes d'administration, serveurs critiques, réseaux exposés |
| Élevé | **E** | Environnements hautement sensibles, OIV, postes dédiés |

**Principe cumulatif** : chaque niveau inclut toutes les recommandations des niveaux
inférieurs. Le profil `anssi-renforce` contient donc toutes les recommandations M, I et R.
Les profils LMDM sont autonomes (pas d'héritage entre fichiers YAML) : chaque profil
embarque l'intégralité des politiques correspondant à son niveau.

---

## 2. Choisir son niveau

```
Poste bureautique standard, données non sensibles ?
  └─ Minimal       anssi-minimal.yml

Traitement de données personnelles (RGPD) ou données sensibles internes ?
  └─ Intermédiaire  anssi-intermediaire.yml

Poste d'administration, serveur critique, réseau exposé ou DMZ ?
  └─ Renforcé      anssi-renforce.yml

Environnement haute sécurité, OIV/OSE, poste dédié opérations sensibles ?
  └─ Élevé         anssi-eleve.yml
```

En cas de doute, privilégier le niveau supérieur : le principe de défense en profondeur
recommandé par l'ANSSI favorise le sur-durcissement plutôt que le sous-durcissement.

---

## 3. Importer un profil

Les profils ANSSI sont des fichiers YAML standard LMDM. Importez-les via l'API REST :

```bash
# Exemple avec le profil minimal
curl -X POST http://lmdm-server/api/v1/profiles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  --data-binary @profiles/anssi/anssi-minimal.yml
```

Remplacez `anssi-minimal.yml` par le fichier correspondant au niveau souhaité :
- `profiles/anssi/anssi-minimal.yml`
- `profiles/anssi/anssi-intermediaire.yml`
- `profiles/anssi/anssi-renforce.yml`
- `profiles/anssi/anssi-eleve.yml`

**Obtention du token :** les tokens d'authentification sont issus de l'enrôlement mTLS.
Consultez [mtls.md](mtls.md) pour la procédure complète d'enrôlement, de renouvellement
et de révocation des certificats.

---

## 4. Assigner à un device ou un groupe

Une fois le profil importé, récupérez son identifiant depuis la réponse de l'API
(`id` dans le JSON retourné), puis assignez-le :

```bash
# Assigner à un device individuel
curl -X POST http://lmdm-server/api/v1/profiles/{id}/assign/{deviceID} \
  -H "Authorization: Bearer $TOKEN"

# L'identifiant du profil et du device sont des UUID retournés par l'API
```

L'agent LMDM sur le device récupère le profil au prochain cycle de synchronisation
et applique les politiques. Le statut de conformité est visible dans la console web
sous l'onglet du device concerné.

---

## 5. Déploiement canary recommandé

Avant tout déploiement en production, appliquer la procédure suivante :

1. Appliquer le profil sur **un poste de test représentatif** de la cible.
2. Vérifier l'absence de régression : services critiques, accès réseau, authentification.
3. Valider la conformité via le script de smoke test :
   ```bash
   sudo ./scripts/anssi-check.sh minimal
   # Remplacer minimal par intermediaire, renforce ou eleve selon le profil
   ```
4. Consulter le compliance report dans la console web (onglet device → Compliance).
5. Si le résultat est satisfaisant, procéder au rollout progressif par groupe de devices.

Pour la procédure complète de déploiement canary, de rollback automatique et de
surveillance des déploiements, consultez [deployments.md](deployments.md).

---

## 6. Variables dans les profils

Les profils ANSSI utilisent le moteur de templates LMDM. Les variables disponibles
dans les actions `file_template` sont :

| Variable | Valeur | Disponibilité |
|----------|--------|---------------|
| `{{.Hostname}}` | Nom d'hôte du device | Toujours disponible |
| `{{.DeviceID}}` | UUID du device | Toujours disponible |
| `{{.TenantID}}` | Identifiant du tenant | Toujours disponible |
| `{{.SiteID}}` | Identifiant du site | Vide en MVP |
| `{{.GroupIDs}}` | Liste des groupes du device | Vide en MVP |

Exemple d'utilisation dans un `file_template` personnalisé :

```yaml
- type: file_template
  params:
    path: /etc/motd
    template: |
      Ce système appartient au tenant {{.TenantID}}.
      Device : {{.Hostname}} ({{.DeviceID}})
      Profil de sécurité : ANSSI-BP-028 Renforcé
    mode: "0644"
```

---

## 7. Hook `post_apply_command`

Le hook `post_apply_command` est disponible sur les actions `file_content`,
`file_template` et `package_ensure`. Il est exécuté via `sh -c` immédiatement
après l'application de l'action.

**Comportement :**
- Timeout par défaut : **60 secondes** (configurable via `post_apply_timeout`)
- Sortie stdout et stderr capturée et journalisée
- Code de retour non-zéro → déclenchement du rollback automatique du profil

**Exemples présents dans les profils ANSSI :**

```yaml
# R8/R9/R12/R14 — Rechargement sysctl après écriture de la configuration
- type: file_content
  params:
    path: /etc/sysctl.d/99-lmdm-anssi.conf
    content: |
      kernel.dmesg_restrict = 1
      # ...
    post_apply_command: sysctl -p /etc/sysctl.d/99-lmdm-anssi.conf
    post_apply_timeout: 30s

# R71/R72 — Redémarrage rsyslog après modification de la configuration
- type: file_content
  params:
    path: /etc/rsyslog.d/99-lmdm-anssi.conf
    content: |
      $FileCreateMode 0640
      # ...
    post_apply_command: systemctl restart rsyslog
    post_apply_timeout: 30s

# R75 — Mise à jour de la base d'aliases après modification
- type: file_content
  params:
    path: /etc/aliases
    content: |
      root: admins@localhost
    post_apply_command: newaliases
    post_apply_timeout: 30s
```

**Exemples supplémentaires pour des politiques personnalisées :**

```yaml
# Rechargement d'un profil AppArmor après déploiement
post_apply_command: "apparmor_parser -r /etc/apparmor.d/local-lmdm"

# Rechargement rsyslog après ajout d'une règle de journalisation
post_apply_command: "systemctl reload rsyslog"

# Mise à jour de GRUB après modification des paramètres noyau
post_apply_command: update-grub
```

---

## 8. Vérification de conformité

### Smoke test rapide

```bash
# Vérification locale sur le device
sudo ./scripts/anssi-check.sh minimal
sudo ./scripts/anssi-check.sh intermediaire
sudo ./scripts/anssi-check.sh renforce
sudo ./scripts/anssi-check.sh eleve
```

Le script vérifie les points de contrôle principaux : présence des fichiers de
configuration, valeurs sysctl actives, services activés/désactivés, paquets requis.

### Audit complet

Pour un audit de conformité exhaustif au format SCAP, utilisez **OpenSCAP** avec
les profils ComplianceAsCode/content alignés sur les niveaux M/I/R/E (post-MVP).
La commande de référence :

```bash
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_anssi_bp28_minimal \
  /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

---

## 9. Dépannage

### Le profil n'a pas été appliqué

1. Vérifier les journaux de l'agent sur le device :
   ```bash
   journalctl -u lmdm-agent --since "1 hour ago"
   ```
2. Consulter le compliance report dans la console web :
   UI → Devices → \[device\] → Compliance → dernière synchronisation.
3. Vérifier la connectivité de l'agent au serveur LMDM (mTLS actif, certificat valide).

### Rollback manuel

En cas de dysfonctionnement après application d'un profil, déclencher un rollback
via l'API (rôle Admin requis) :

```bash
curl -X POST http://lmdm-server/api/v1/deployments/{id}/rollback \
  -H "Authorization: Bearer $TOKEN"
```

L'identifiant du déploiement est visible dans la console web sous
Deployments → \[device\] → historique.

### Règle non conforme persistante

Si une politique reste non conforme malgré l'application du profil, un outil externe
(Puppet, Ansible, Chef) a probablement écrasé le fichier après application par LMDM.

Vérifier :
```bash
# Identifier l'outil qui gère le fichier
systemctl status puppet cfengine3 ansible-pull 2>/dev/null
# Vérifier les logs récents de modification
ausearch -f /etc/sysctl.d/99-lmdm-anssi.conf 2>/dev/null | tail -20
```

Résoudre le conflit en excluant le fichier du gestionnaire de configuration externe
ou en intégrant LMDM dans la chaîne d'orchestration.

---

## 10. Limitations

| Recommandation(s) | Limitation | Contournement |
|-------------------|-----------|---------------|
| R1–R4 | Configuration matérielle et firmware — LMDM ne peut pas accéder au BIOS/UEFI | Configuration manuelle lors de l'installation physique |
| R5 | Mot de passe GRUB — nécessite un hash spécifique par machine | Intégrer dans l'Image Builder (post-MVP) |
| R6 | Secure Boot et protection `initramfs` — requiert clés de signature propres | Mise en œuvre via shim signé (hors périmètre LMDM) |
| R15–R27 | Options de compilation noyau — rebuilder le noyau est impossible post-installation | Utiliser `linux-hardened` ou un noyau compilé sur mesure |
| R28 | Partitionnement — uniquement réalisable à l'installation | Prévoir le schéma de partitions dans l'Image Builder (post-MVP) |
| R30 | Gestion des comptes utilisateurs — propre à chaque parc | Gérer via un annuaire (LDAP/AD) couplé à LMDM |
| R46–R49 | SELinux — non natif sur Debian/Ubuntu | LMDM privilégie AppArmor (R37/R45) ; pour SELinux, utiliser RHEL/Fedora |
| R65 | Sandboxing systemd — directives déployées, application aux services individuels manuelle | Créer des drop-in `.conf` via `file_content` par service |
| R66 | MFA — installation de `libpam-google-authenticator` automatisée, activation par compte manuelle | Procédure d'enrôlement TOTP à documenter par l'équipe sécurité |

Pour la liste exhaustive avec statut détaillé de chaque recommandation,
consultez la [matrice de couverture complète](anssi-coverage.md).
