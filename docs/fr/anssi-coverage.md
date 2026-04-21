# Matrice de couverture ANSSI-BP-028 v2.0

Ce document recense les 80 recommandations du guide ANSSI-BP-028 v2.0
(« Recommandations de configuration d'un système GNU/Linux », 03/10/2022)
et indique leur statut de couverture dans les profils LMDM.

## Légende

| Symbole | Signification |
|---------|---------------|
| ✅ Implémentée | Couverte par au moins un profil LMDM |
| ⚠️ Partielle | Couverte avec des réserves ou étapes manuelles restantes |
| 🚫 Hors scope MDM | Ne peut pas être appliquée par un MDM (matériel, compilation noyau, partitionnement) |

**Profils :** `minimal+` signifie « ce niveau et tous les niveaux supérieurs ».

---

## Matrice

| Reco | Titre | Niveaux ANSSI | Statut LMDM | Profil | Notes |
|------|-------|---------------|-------------|--------|-------|
| R1 | Choisir et configurer son matériel | M-I-R-E | 🚫 Hors scope MDM | — | Sélection et configuration matérielle physique, hors périmètre logiciel |
| R2 | Configurer le BIOS/UEFI | M-I | 🚫 Hors scope MDM | — | Configuration firmware ; nécessite accès physique ou outil OEM |
| R3 | Activer le démarrage sécurisé UEFI | M-I | 🚫 Hors scope MDM | — | Secure Boot requiert clés signées et shim ; hors portée MDM post-installation |
| R4 | Remplacer les clés préchargées | M-I-R-E | 🚫 Hors scope MDM | — | Gestion des clés UEFI — opération firmware hors portée LMDM |
| R5 | Configurer un mot de passe pour le chargeur de démarrage | M-I | 🚫 Hors scope MDM | — | Le hash GRUB nécessite une valeur spécifique à chaque machine ; aucun `file_template` ni `file_content` présent dans les profils actuels — à implémenter via Image Builder |
| R6 | Protéger les paramètres de ligne de commande du noyau et l'`initramfs` | M-I-R-E | 🚫 Hors scope MDM | — | Signature de l'`initramfs` et verrouillage de la ligne de commande noyau requièrent Secure Boot avec clés propres |
| R7 | Activer l'IOMMU | M-I-R | ✅ Implémentée | intermédiaire+ | `file_content` sur `/etc/default/grub.d/lmdm-anssi-iommu.cfg` avec `GRUB_CMDLINE_LINUX iommu=force` |
| R8 | Paramétrer les options de configuration de la mémoire | M-I | ✅ Implémentée | minimal+ | `sysctl` + persistance dans `/etc/sysctl.d/99-lmdm-anssi.conf` (dmesg_restrict, kptr_restrict, randomize_va_space…) |
| R9 | Paramétrer les options de configuration du noyau | M-I | ✅ Implémentée | minimal+ | `sysctl` : `kernel.pid_max`, `net.core.bpf_jit_harden` |
| R10 | Désactiver le chargement des modules noyau | M-I-R | ⚠️ Partielle | renforcé+ | Blacklist de modules superflus (fs, réseau, USB) via `kernel_module_blacklist` ; `kernel.modules_disabled=1` commenté car irréversible sans redémarrage — activation manuelle requise après validation |
| R11 | Activer et configurer le LSM Yama | M-I | ✅ Implémentée | minimal+ | `sysctl kernel.yama.ptrace_scope=1` |
| R12 | Paramétrer les options de configuration du réseau IPv4 | M-I | ✅ Implémentée | minimal+ | `sysctl` complet : forwarding, redirects, ARP, TCP syncookies, rp_filter… |
| R13 | Désactiver le plan IPv6 | M-I | ✅ Implémentée | intermédiaire+ | `sysctl net.ipv6.conf.all.disable_ipv6=1` + persistance sysctl.d |
| R14 | Paramétrer les options de configuration des systèmes de fichiers | M-I | ✅ Implémentée | minimal+ | `sysctl` : `fs.suid_dumpable`, `fs.protected_fifos/regular/symlinks/hardlinks` |
| R15 | Paramétrer les options de compilation pour la gestion de la mémoire | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau (CONFIG_CC_STACKPROTECTOR_STRONG…) — nécessite recompilation |
| R16 | Paramétrer les options de compilation pour les structures de données du noyau | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R17 | Paramétrer les options de compilation pour l'allocateur mémoire | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R18 | Paramétrer les options de compilation pour la gestion des modules noyau | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R19 | Paramétrer les options de compilation pour les évènements anormaux | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau (KASLR, RANDOMIZE_MEMORY…) — nécessite recompilation |
| R20 | Paramétrer les options de compilation pour les primitives de sécurité du noyau | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R21 | Paramétrer les options de compilation pour les `plugins` du compilateur | M-I-R-E | 🚫 Hors scope MDM | — | Options GCC plugins (LATENT_ENTROPY, STRUCTLEAK…) — nécessite recompilation |
| R22 | Paramétrer les options de compilation pour la pile réseau | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R23 | Paramétrer les options de compilation pour divers comportements du noyau | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R24 | Paramétrer les options de compilation spécifiques aux architectures 32 bits | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R25 | Paramétrer les options de compilation spécifiques aux architectures x86_64 bits | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R26 | Paramétrer les options de compilation spécifiques aux architectures ARM | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R27 | Paramétrer les options de compilation spécifiques aux architectures ARM 64 bits | M-I-R-E | 🚫 Hors scope MDM | — | Options de compilation noyau — nécessite recompilation |
| R28 | Partitionnement type | M-I | 🚫 Hors scope MDM | — | Partitionnement réalisé à l'installation uniquement ; à intégrer dans un Image Builder (post-MVP) |
| R29 | Restreindre les accès au dossier `/boot` | M-I-R | ✅ Implémentée | intermédiaire+ | `file_content` cron daily : `chmod 700 /boot` + vérification AIDE en niveaux R/E |
| R30 | Désactiver les comptes utilisateur inutilisés | M-I | 🚫 Hors scope MDM | — | Gestion des comptes utilisateurs propre à chaque parc — hors périmètre d'un profil générique MDM |
| R31 | Utiliser des mots de passe robustes | M-I | ✅ Implémentée | minimal+ | `libpam-pwquality` + `/etc/security/pwquality.conf` (minlen=12/16, minclass=3/4 selon niveau) |
| R32 | Expirer les sessions utilisateur locales | M-I | ✅ Implémentée | intermédiaire+ | `file_content` `/etc/profile.d/lmdm-anssi-tmout.sh` : `TMOUT=900` (I/R), `TMOUT=600` (E) |
| R33 | Assurer l'imputabilité des actions d'administration | M-I | ✅ Implémentée | intermédiaire+ | `file_content` `/etc/profile.d/lmdm-anssi-history.sh` : `HISTSIZE`, `HISTTIMEFORMAT` |
| R34 | Désactiver les comptes de service | M-I | ✅ Implémentée | intermédiaire+ | `file_content` cron daily : détection des comptes système avec shell valide via `awk` sur `/etc/passwd` |
| R35 | Utiliser des comptes de service uniques et exclusifs | M-I | ✅ Implémentée | intermédiaire+ | Couvert par le même contrôle R34 (vérification shell par compte système) |
| R36 | Modifier la valeur par défaut de UMASK | M-I-R | ✅ Implémentée | minimal+ | `file_content` `/etc/profile.d/lmdm-anssi-umask.sh` : `umask 0077` |
| R37 | Utiliser des fonctionnalités de contrôle d'accès obligatoire MAC | M-I-R | ✅ Implémentée | renforcé+ | `file_content` cron daily : `aa-enforce /etc/apparmor.d/*` pour passer tous les profils AppArmor en mode enforce |
| R38 | Créer un groupe dédié à l'usage de `sudo` | M-I-R | ✅ Implémentée | minimal+ | `/etc/sudoers.d/lmdm-anssi` + directives renforcées en R/E (`log_input`, `log_output`, `syslog=auth`) |
| R39 | Modifier les directives de configuration `sudo` | M-I | ✅ Implémentée | minimal+ | `requiretty`, `use_pty`, `env_reset`, `noexec`, `passwd_tries=3` dans `/etc/sudoers.d/lmdm-anssi` |
| R40 | Utiliser des utilisateurs cibles non-privilégiés pour les commandes `sudo` | M-I | ✅ Implémentée | intermédiaire+ | `/etc/sudoers.d/lmdm-anssi-advanced` : `Defaults log_output` + documentation du principe Runas |
| R41 | Limiter l'utilisation de commandes nécessitant la directive `EXEC` | M-I-R | ✅ Implémentée | intermédiaire+ | Cron daily vérifiant les règles `NOEXEC`/`!exec` dans sudoers ; `noexec` activé par défaut (R38/R39) |
| R42 | Bannir les négations dans les spécifications `sudo` | M-I | ✅ Implémentée | minimal+ | `Defaults noexec` dans `/etc/sudoers.d/lmdm-anssi` |
| R43 | Préciser les arguments dans les spécifications `sudo` | M-I | ⚠️ Partielle | minimal+ | Les directives globales sont posées mais les règles métier (per-user EXEC list) restent à définir par l'opérateur |
| R44 | Éditer les fichiers de manière sécurisée avec `sudo` | M-I | ✅ Implémentée | minimal+ | `Defaults !visiblepw`, `use_pty` dans `/etc/sudoers.d/lmdm-anssi` |
| R45 | Activer les profils de sécurité `AppArmor` | M-I-R | ✅ Implémentée | minimal+ | `package_ensure` (apparmor, apparmor-utils, apparmor-profiles-extra) + `service_ensure enabled` ; mode enforce via `/etc/default/apparmor` en R/E |
| R46 | Activer `SELinux` avec la politique `targeted` | M-I-R-E | 🚫 Hors scope MDM | — | SELinux non supporté nativement sur Debian/Ubuntu ; LMDM privilégie AppArmor (R37/R45). Pour SELinux, utiliser une distribution RHEL/Fedora |
| R47 | Confiner les utilisateurs interactifs non privilégiés | M-I-R-E | 🚫 Hors scope MDM | — | Confinement SELinux — hors scope sur Debian/Ubuntu (voir R37/R45 AppArmor) |
| R48 | Paramétrer les variables `SELinux` | M-I-R-E | 🚫 Hors scope MDM | — | Variables SELinux — hors scope sur Debian/Ubuntu |
| R49 | Désinstaller les outils de débogage de politique `SELinux` | M-I-R-E | 🚫 Hors scope MDM | — | Outils SELinux — hors scope sur Debian/Ubuntu |
| R50 | Restreindre les droits d'accès aux fichiers et aux répertoires sensibles | M-I-R | ✅ Implémentée | minimal+ | Cron daily : `chmod 640 /etc/shadow`, `chmod 640 /etc/gshadow`, `chmod 644 /etc/passwd/group`, `chown root:shadow` |
| R51 | Changer les secrets et droits d'accès dès l'installation | M-I-R | ✅ Implémentée | renforcé+ | Cron daily : détection de fichiers sensibles (`*.key`, `*password*`, `*secret*`) dans `/tmp` et `/var/tmp` |
| R52 | Restreindre les accès aux `sockets` et aux `pipes` nommées | M-I-R | ✅ Implémentée | intermédiaire+ | Cron daily : `find / -xdev \( -type s -o -type p \) -perm -0002` avec log via `logger` |
| R53 | Éviter les fichiers ou répertoires sans utilisateur ou sans groupe connu | M-I | ✅ Implémentée | minimal+ | Cron weekly : `find / -xdev \( -nouser -o -nogroup \)` avec log via `logger` |
| R54 | Activer le `sticky bit` sur les répertoires inscriptibles | M-I | ✅ Implémentée | minimal+ | Cron weekly : `find / -xdev -type d -perm -0002 -a ! -perm -1000 -exec chmod +t` |
| R55 | Séparer les répertoires temporaires des utilisateurs | M-I | ✅ Implémentée | intermédiaire+ | `package_ensure libpam-tmpdir` + `tmpfiles.d` configuré |
| R56 | Éviter l'usage d'exécutables avec les droits spéciaux `setuid` et `setgid` | M-I | ✅ Implémentée | minimal+ | Cron weekly : recensement des binaires setuid/setgid via `find` + `logger` |
| R57 | Éviter l'usage d'exécutables avec les droits spéciaux `setuid root` et `setgid root` | M-I-R | ✅ Implémentée | renforcé+ | Cron daily : recensement distinct des binaires setuid root (perm -4000) et setgid (perm -2000) |
| R58 | N'installer que les paquets strictement nécessaires | M-I | ✅ Implémentée | minimal+ | `APT::Get::AllowUnauthenticated false` + suppression des paquets inutiles (telnet, rsh, talk, xinetd) via `package_ensure absent` |
| R59 | Utiliser des dépôts de paquets de confiance | M-I | ✅ Implémentée | minimal+ | `Acquire::AllowInsecureRepositories false`, `AllowDowngradeToInsecureRepositories false` dans apt.conf.d |
| R60 | Utiliser des dépôts de paquets durcis | M-I-R | ✅ Implémentée | renforcé+ | `Acquire::Check-Valid-Until true`, `APT::Authentication::TrustCDROM false` dans apt.conf.d renforcé |
| R61 | Effectuer des mises à jour régulières | M-I | ✅ Implémentée | minimal+ | `package_ensure unattended-upgrades` + `service_ensure enabled` + `/etc/apt/apt.conf.d/20auto-upgrades` |
| R62 | Désactiver les services non nécessaires | M-I | ✅ Implémentée | minimal+ | `service_ensure disabled` : avahi-daemon, cups, bluetooth, rpcbind |
| R63 | Désactiver les fonctionnalités des services non essentielles | M-I | ✅ Implémentée | intermédiaire+ | `service_ensure disabled` étendu : nfs-common, autofs (en plus de R62) |
| R64 | Configurer les privilèges des services | M-I-R | ✅ Implémentée | renforcé+ | Cron daily : `systemctl list-units --type=service --state=running` pour détecter les services tournant en root |
| R65 | Cloisonner les services | M-I-R | ⚠️ Partielle | renforcé+ | Template de directives systemd (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`…) déployé via `file_content` ; application aux services individuels reste à la charge de l'opérateur via drop-in |
| R66 | Durcir les composants de cloisonnement | M-I-R-E | ⚠️ Partielle | élevé | `package_ensure libpam-google-authenticator` installé ; activation TOTP manuelle requise par utilisateur privilégié (google-authenticator + PAM sshd/sudo) |
| R67 | Sécuriser les authentifications distantes par PAM | M-I | ✅ Implémentée | minimal+ | `package_ensure libpam-faillock` + `/etc/security/faillock.conf` (deny=5, unlock_time=900) |
| R68 | Protéger les mots de passe stockés | M-I | ✅ Implémentée | minimal+ | Combinaison R67 (faillock) + R31 (pwquality) assurant le durcissement des mots de passe stockés |
| R69 | Sécuriser les accès aux bases utilisateur distantes | M-I | ✅ Implémentée | intermédiaire+ | `file_content /etc/nsswitch.conf` : bases locales prioritaires (`files` avant toute source distante) |
| R70 | Séparer les comptes système et d'administrateur de l'annuaire | M-I | ✅ Implémentée | intermédiaire+ | Couvert par `/etc/nsswitch.conf` avec `shadow: files` (comptes système locaux uniquement) |
| R71 | Mettre en place un système de journalisation | M-I-R | ✅ Implémentée | minimal+ | `package_ensure rsyslog` + `service_ensure enabled` + `/etc/rsyslog.d/99-lmdm-anssi.conf` (FileCreateMode 0640, auth.log, kern.log) |
| R72 | Mettre en place des journaux d'activité de service dédiés | M-I-R | ✅ Implémentée | minimal+ | Couvert par la configuration rsyslog (auth, authpriv, kern) + auditd en niveaux I+ |
| R73 | Journaliser l'activité système avec `auditd` | M-I-R | ✅ Implémentée | intermédiaire+ | `package_ensure auditd` + `service_ensure enabled` + règles auditd (modules noyau, /etc/, mount, syscalls suspects, chmod/chown en R+) |
| R74 | Durcir le service de messagerie locale | M-I | ✅ Implémentée | minimal+ | `/etc/aliases` avec redirection postmaster/root/daemon/nobody vers administrateur local |
| R75 | Configurer un alias de messagerie des comptes de service | M-I | ✅ Implémentée | minimal+ | `/etc/aliases` + `post_apply_command: newaliases` pour prise en compte immédiate |
| R76 | Sceller et vérifier l'intégrité des fichiers | M-I-R-E | ✅ Implémentée | renforcé+ | `package_ensure aide` + cron daily : initialisation et vérification AIDE ; configuration FIPSR+sha512 étendue en niveau E |
| R77 | Protéger la base de données des scellés | M-I-R-E | ✅ Implémentée | renforcé+ | `logrotate.d/lmdm-anssi-r77` : rotation 90 jours, compression, droits 0640 (journaux) et 0600 (audit) |
| R78 | Cloisonner les services réseau | M-I-R | ✅ Implémentée | intermédiaire+ | `nftables_rules` : politique drop par défaut input/forward, règles SSH avec rate limiting renforcé en R/E, journalisation des rejets en R/E |
| R79 | Durcir et surveiller les services exposés | M-I | ✅ Implémentée | intermédiaire+ | Cron daily : `ss -tlnp` avec log via `logger` pour inventaire des ports en écoute |
| R80 | Réduire la surface d'attaque des services réseau | M-I | ✅ Implémentée | minimal+ | `package_ensure absent` : nis, rsh-server, telnetd, tftpd, ftpd |

---

## Résumé

| Catégorie | Nombre |
|-----------|--------|
| Total recommandations | **80** |
| ✅ Implémentées | **51** |
| ⚠️ Partielles | **4** |
| 🚫 Hors scope MDM | **25** |

### Recommandations partielles — détail

| Reco | Raison |
|------|--------|
| R10 | `kernel.modules_disabled=1` commenté : irréversible sans redémarrage, activation manuelle après validation |
| R43 | Directives globales posées ; les règles sudoers par utilisateur/commande restent à définir par l'opérateur |
| R65 | Template systemd sandboxing déployé ; application aux services individuels via drop-in reste manuelle |
| R66 | `libpam-google-authenticator` installé ; activation TOTP par utilisateur privilégié reste manuelle |

### Recommandations hors scope — synthèse

- **R1–R6** : configuration matérielle, BIOS/UEFI, Secure Boot, protection ligne de commande noyau
- **R15–R27** : options de compilation noyau (nécessitent un noyau recompilé, ex. `linux-hardened`)
- **R28** : partitionnement (phase d'installation uniquement — à intégrer dans Image Builder, post-MVP)
- **R30** : gestion des comptes utilisateurs propre au parc — hors profil générique
- **R46–R49** : SELinux — non natif sur Debian/Ubuntu ; AppArmor (R37/R45) est l'alternative LMDM
