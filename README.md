# 🚀 NetlogonSecureChannelChecker


**Ayi NEDJIMI Consultants - WinToolsSuite**

## Vue d'ensemble

NetlogonSecureChannelChecker est un outil de vérification et de diagnostic du canal sécurisé Netlogon (secure channel) entre une machine jointe au domaine et ses contrôleurs de domaine. Il détecte les problèmes d'authentification, les configurations non sécurisées et les vulnérabilités critiques comme Zerologon.


## Importance du Secure Channel

Le **Secure Channel Netlogon** est essentiel pour :
- **Authentification machine** : Authentification de la machine auprès du domaine
- **Changement de mot de passe** : Rotation automatique du mot de passe machine
- **Communication sécurisée** : Chiffrement des échanges avec les DC
- **Trust relationship** : Maintien de la relation d'approbation

Un secure channel rompu empêche :
- L'authentification des utilisateurs du domaine
- L'application des GPO
- L'accès aux ressources réseau
- La communication avec les contrôleurs de domaine


## ✨ Fonctionnalités principales

### 1. Test du Secure Channel
Vérifie l'intégrité de la relation d'approbation avec le domaine :
- **État du canal** : OK, rompu, ou erreur de connectivité
- **Domaine** : Nom du domaine auquel la machine est jointe
- **Connectivité DC** : Vérification de l'accès aux contrôleurs de domaine
- **Trust LSA Secret** : Validation du secret d'authentification

### 2. Vérification de configuration
Audit des paramètres de sécurité Netlogon dans le registre :
- **RequireSignOrSeal** : Signature ou chiffrement requis
- **RequireStrongKey** : Protection contre Zerologon (CVE-2020-1472)
- **SignSecureChannel** : Signature des communications
- **SealSecureChannel** : Chiffrement des communications

### 3. Détection des vulnérabilités
Identifie les configurations dangereuses :
- **Zerologon (CVE-2020-1472)** : RequireStrongKey désactivé
- **Canal non signé** : SignSecureChannel désactivé
- **Canal non chiffré** : SealSecureChannel désactivé
- **Sign/Seal non requis** : RequireSignOrSeal désactivé

### 4. Monitoring des événements
Analyse l'Event Log pour détecter les échecs récents :
- **Event ID 5719** : Échec de communication avec un DC
- Détection des problèmes de secure channel passés

### 5. Guide de réparation
Instructions pour réparer un secure channel rompu via `nltest`.


## Architecture technique

### Composants
1. **Interface graphique** : Win32 native avec ListView
2. **API NetAPI32** : I_NetLogonControl2 pour test secure channel
3. **Registry API** : Lecture des paramètres Netlogon
4. **Event Log API** : Analyse des événements système
5. **RAII** : AutoHandle pour gestion des ressources
6. **Threading** : std::thread pour opérations longues

### Flux de fonctionnement

#### Test Secure Channel
```
1. Récupération du nom de domaine
   ↓
2. Vérification si machine jointe au domaine
   ↓
3. Appel I_NetLogonControl2(NETLOGON_CONTROL_TC_QUERY)
   ↓
4. Analyse du code retour :
   - NERR_Success → Trust OK
   - ERROR_NO_LOGON_SERVERS → Pas de DC
   - ERROR_NO_TRUST_LSA_SECRET → Trust rompu
   ↓
5. Lecture des paramètres de sécurité
   ↓
6. Génération d'alertes si configurations dangereuses
```

#### Vérification Configuration
```
1. Lecture du registre :
   HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
   ↓
2. Extraction des valeurs :
   - RequireSignOrSeal
   - RequireStrongKey
   - SignSecureChannel
   - SealSecureChannel
   ↓
3. Évaluation de sécurité pour chaque paramètre
   ↓
4. Affichage avec recommandations
```


## Compilation

### Prérequis
- Visual Studio 2017 ou plus récent avec les outils C++
- Windows SDK

### Compilation automatique
```batch
go.bat
```

Le script :
1. Détecte automatiquement Visual Studio
2. Configure l'environnement de compilation
3. Compile avec les librairies réseau (netapi32.lib)
4. Propose de lancer l'exécutable

### Compilation manuelle
```batch
cl.exe /EHsc /O2 /W3 /std:c++17 /D UNICODE /D _UNICODE NetlogonSecureChannelChecker.cpp /link netapi32.lib wevtapi.lib advapi32.lib comctl32.lib /OUT:NetlogonSecureChannelChecker.exe
```


# 🚀 Tester le secure channel

# 🚀 Réparer le secure channel

# 🚀 Vérifier après réparation

# 🚀 Tester

# 🚀 Réparer

# 🚀 Réparer en forçant le changement de mot de passe

## 🚀 Utilisation

### Interface graphique
1. **Tester Secure Channel** : Vérifie l'état actuel de la relation d'approbation
2. **Vérifier Config** : Audit des paramètres de sécurité Netlogon
3. **Réparer (Guide)** : Affiche les instructions pour réparer le canal
4. **Exporter** : Sauvegarde les résultats au format CSV

### Privilèges requis
- **Administrateur** : Obligatoire pour appeler I_NetLogonControl2 et lire le registre Netlogon
- Lancer l'outil en tant qu'administrateur


## Logging

Tous les événements sont enregistrés dans :
```
%TEMP%\WinTools_NetlogonSecureChannelChecker_log.txt
```

Format des logs :
```
2025-10-20 14:30:45 | === NetlogonSecureChannelChecker démarré ===
2025-10-20 14:30:46 | Début test secure channel Netlogon
2025-10-20 14:30:47 | Secure channel OK
2025-10-20 14:30:48 | ALERTE: RequireStrongKey désactivé (vulnérable Zerologon)
2025-10-20 14:31:02 | Vérification configuration Netlogon
2025-10-20 14:31:03 | Vérification configuration terminée
```


## 🔒 Paramètres de sécurité Netlogon

### RequireSignOrSeal
- **Chemin** : `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
- **Valeur** : `RequireSignOrSeal` (DWORD)
- **Recommandation** : 1 (activé)
- **Impact** : Force la signature ou le chiffrement des communications

### RequireStrongKey
- **Chemin** : `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
- **Valeur** : `RequireStrongKey` (DWORD)
- **Recommandation** : 1 (activé) - **CRITIQUE**
- **Impact** : Protection contre l'attaque Zerologon (CVE-2020-1472)
- **Danger** : Si désactivé, un attaquant peut prendre contrôle du DC en quelques secondes

### SignSecureChannel
- **Chemin** : `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
- **Valeur** : `SignSecureChannel` (DWORD)
- **Recommandation** : 1 (activé)
- **Impact** : Signature des communications pour prévenir les attaques MITM

### SealSecureChannel
- **Chemin** : `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
- **Valeur** : `SealSecureChannel` (DWORD)
- **Recommandation** : 1 (activé)
- **Impact** : Chiffrement des communications pour confidentialité


## Codes d'erreur et leur signification

### NERR_Success (0)
**Statut** : Secure channel OK
**Action** : Aucune

### ERROR_NO_LOGON_SERVERS (0x0000051F)
**Statut** : Aucun contrôleur de domaine accessible
**Causes possibles** :
- Problème réseau
- DC éteints ou inaccessibles
- DNS mal configuré
- Firewall bloquant

**Actions** :
1. Vérifier connectivité réseau : `ping <DC>`
2. Vérifier résolution DNS : `nslookup <domaine>`
3. Vérifier firewall

### ERROR_NO_TRUST_LSA_SECRET (0x000006FA)
**Statut** : Relation d'approbation rompue
**Causes possibles** :
- Mot de passe machine désynchronisé
- Compte machine supprimé dans AD
- Restauration d'un snapshot ancien

**Actions** :
1. Réparer le secure channel : `nltest /sc_reset:<domaine>`
2. Si échec, réjoindre le domaine
3. Vérifier que le compte machine existe dans AD


## Réparation du Secure Channel

### Méthode 1 : nltest (Recommandé)
```batch
nltest /sc_query:<domaine>

nltest /sc_reset:<domaine>

nltest /sc_query:<domaine>
```

### Méthode 2 : PowerShell
```powershell
Test-ComputerSecureChannel

Test-ComputerSecureChannel -Repair

Test-ComputerSecureChannel -Repair -Credential (Get-Credential)
```

### Méthode 3 : Rejoindre le domaine
Si les méthodes ci-dessus échouent :
1. Désjoindre le domaine (passer en Workgroup)
2. Redémarrer
3. Rejoindre le domaine
4. Redémarrer


## Vulnérabilité Zerologon (CVE-2020-1472)

### Description
Zerologon est une vulnérabilité critique du protocole Netlogon permettant à un attaquant non authentifié de :
- Réinitialiser le mot de passe du compte machine du DC
- Obtenir les privilèges Domain Admin
- Compromettre tout le domaine Active Directory

### Exploitation
```
1. Attaquant envoie des requêtes Netlogon avec IV=0
2. Exploitation de la faiblesse cryptographique (AES-CFB8)
3. Changement du mot de passe machine du DC à une valeur vide
4. Authentification comme DC compromise
5. Dump des secrets NTDS.dit (tous les hashes du domaine)
```

### Protection
**Activer RequireStrongKey** :
```batch
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
```

**Via GPO** :
```
Configuration ordinateur > Modèles d'administration > Système > Netlogon
> "Require strong key protection for secure channel data"
> Activé
```

### Détection
L'outil détecte si RequireStrongKey est désactivé et génère une alerte **CRITIQUE**.


## Event ID 5719

### Signification
Échec de communication avec un contrôleur de domaine.

### Causes courantes
1. **DC indisponible** : DC éteint ou redémarrant
2. **Problème réseau** : Latence, paquets perdus
3. **Trust rompu** : Secure channel cassé
4. **DNS** : Mauvaise résolution du nom du DC
5. **Firewall** : Ports Netlogon bloqués

### Ports utilisés par Netlogon
- **TCP/UDP 445** : SMB/CIFS
- **TCP/UDP 135** : RPC Endpoint Mapper
- **TCP 49152-65535** : RPC dynamique


## 🚀 Cas d'usage

### 1. Diagnostic d'authentification impossible
Un utilisateur ne peut pas se connecter au domaine.

**Scénario** :
```
1. Lancer NetlogonSecureChannelChecker
2. Tester Secure Channel
3. Résultat : Trust rompu (ERROR_NO_TRUST_LSA_SECRET)
4. Exécuter : nltest /sc_reset:<domaine>
5. Problème résolu
```

### 2. Audit de sécurité post-patch
Après installation des patchs Zerologon, vérifier la protection.

**Scénario** :
```
1. Vérifier Config
2. Vérifier RequireStrongKey = Activé
3. Si désactivé → Activer immédiatement
4. Exporter rapport pour conformité
```

### 3. Monitoring proactif des DC
Surveillance quotidienne des serveurs critiques.

**Scénario** :
```
1. Script planifié exécutant l'outil
2. Export CSV automatique
3. Analyse des alertes
4. Intervention si anomalie détectée
```

### 4. Investigation incident de sécurité
Après détection d'une compromission, vérifier l'intégrité Netlogon.

**Scénario** :
```
1. Test Secure Channel sur tous les DC
2. Vérifier Event ID 5719 récents
3. Analyser si RequireStrongKey a été modifié
4. Restaurer configuration sécurisée
5. Forcer changement de tous les mots de passe machine
```


## Bonnes pratiques

### Pour les administrateurs
1. **Monitoring régulier** : Tester le secure channel hebdomadairement
2. **Activation RequireStrongKey** : Sur TOUS les DC et machines
3. **Audit des Event ID 5719** : Alertes automatiques
4. **Documentation** : Procédure de réparation formalisée
5. **Tests réguliers** : Simuler une réparation sur machine de test

### Pour la sécurité
1. **Zerologon Protection** : RequireStrongKey obligatoire via GPO
2. **Sign/Seal obligatoire** : Activer RequireSignOrSeal
3. **Audit des modifications** : Surveiller changements de registre Netlogon
4. **Segmentation** : Isoler les DC sur VLAN dédié
5. **Baseline** : Établir une configuration de référence


## Limitations

1. **Lecture seule** : L'outil ne répare pas automatiquement (guide uniquement)
2. **Privilèges élevés** : Nécessite admin pour I_NetLogonControl2
3. **Machine jointe** : Fonctionne uniquement sur machine membre du domaine
4. **API limitée** : I_NetLogonControl2 fournit des informations basiques


## Améliorations futures

- [ ] Réparation automatique du secure channel (optionnel)
- [ ] Test de tous les DC du domaine
- [ ] Monitoring en temps réel avec alertes
- [ ] Export JSON pour SIEM
- [ ] Historique des tests avec graphiques
- [ ] Détection de tentatives d'exploitation Zerologon
- [ ] Intégration avec Azure AD / Hybrid Join


## Références

- [Zerologon CVE-2020-1472](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
- [Netlogon Secure Channel](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-domain-and-forest-trusts-work)
- [Test-ComputerSecureChannel](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-computersecurechannel)
- [Nltest Command Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
- [Event ID 5719](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc735303(v=ws.10))


## Support

**Ayi NEDJIMI Consultants**
Pour toute question ou assistance technique.

- --

**Version** : 1.0
**Date** : 2025-10-20
**Licence** : Usage interne Ayi NEDJIMI Consultants


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>