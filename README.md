# CyberMind — Assistant RAG de Threat Intelligence (MITRE ATT&CK)

Assistant pour analystes SOC qui répond aux questions sur les techniques **MITRE ATT&CK** (détection, sources de logs, mitigations) à partir d'une base vectorielle construite sur les données officielles, avec des réponses **ancrées dans le contexte** et sourcées par ID de technique.

> Projet personnel (Blue Team / SOC) : recherche sémantique sur ATT&CK + LLM via Groq, avec un travail explicite sur le contrôle des hallucinations.

---

## Fonctionnalités

- **Pipeline de données** : extraction des techniques ATT&CK actives (hors révoquées / dépréciées) depuis le bundle STIX officiel, avec leurs **mitigations** et leurs **stratégies de détection** (analytiques, sources de logs, éléments à ajuster).
- **Indexation sémantique** : 3 types de chunks par technique (`overview`, `detection`, `mitigation`), chacun préfixé par `ID - Nom [tactique]` et enrichi de métadonnées (technique, tactiques, plateformes, type).
- **RAG ancré** : le modèle répond uniquement à partir du contexte récupéré, cite les IDs de techniques et dit explicitement quand l'information n'y est pas.
- **Filtrage strict par ID** : une question contenant un ID (ex. `T1003.001`) ne reçoit que les chunks de cette technique.
- **Triage d'alerte** *(en cours de validation)* : `analyze.py` lit une alerte Wazuh au format JSON, en extrait les champs utiles et produit une fiche d'analyse (technique, lien avec l'alerte, points à vérifier, mitigations, limites).

## Chiffres clés (jeu de données testé)

| Élément | Valeur |
|---|---|
| Techniques et sous-techniques actives | 697 |
| Techniques avec mitigations | 586 |
| Analytiques de détection | 1 745 (dont 1 700 avec sources de logs) |
| Chunks indexés | 3 593 (1 158 description · 1 745 détection · 690 mitigation) |

## Architecture

```
enterprise-attack.json (STIX, MITRE)
        │
        ▼
extract_attack.py ──► data/techniques.json
        │              (techniques + mitigations + détections)
        ▼
build_index.py ──► chroma_db/   (ChromaDB, embeddings all-MiniLM-L6-v2, local)
        │
        ▼
rag.py :  question ──► retrieve() ──► prompt « grounded » ──► LLM (Groq) ──► réponse + sources
                          │
                          └─ ID détecté (Txxxx) ? → filtre strict sur la technique
                             sinon → recherche sémantique (top-k)

analyze.py :  alerte Wazuh (JSON) ──► extraction des champs ──► retrieve() ──► fiche d'analyse
```

## Stack

| Composant | Technologie |
|---|---|
| Orchestration | LangChain |
| Base vectorielle | ChromaDB |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2` (local, gratuit) |
| LLM | Groq — `openai/gpt-oss-120b` (configurable via `GROQ_MODEL`) |
| Données | MITRE ATT&CK Enterprise (bundle STIX) |
| Langage | Python 3.10+ |

## Installation

```powershell
git clone https://github.com/<ton-compte>/cybermind.git
cd cybermind
python -m venv venv
.\venv\Scripts\activate          # Linux/macOS : source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Crée un fichier `.env` à la racine (**ne jamais le commiter**) :

```
GROQ_API_KEY=ta_cle_groq
GROQ_MODEL=openai/gpt-oss-120b
```

Les modèles disponibles varient selon le compte et changent dans le temps. Pour lister ceux auxquels ta clé a accès :

```powershell
python list_models.py
```

## Utilisation

**1. Télécharger les données ATT&CK**

```powershell
mkdir data
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" -OutFile "data/enterprise-attack.json"
```

**2. Extraire les techniques, mitigations et détections**

```powershell
python extract_attack.py
```

**3. Construire l'index vectoriel** (le premier lancement télécharge le modèle d'embeddings, ~90 Mo)

```powershell
python build_index.py
```

**4. Poser des questions**

```powershell
python rag.py
```

Exemples :

```
Question > Quelles mitigations pour T1003.001 ?
Question > Comment détecter l'exécution de PowerShell encodé avec Sysmon ?
Question > Quelle est la capitale de la France ?     # doit être refusée (hors contexte)
```

**5. Analyser une alerte Wazuh**

```powershell
python analyze.py samples\alert_t1105.json
```

## Contrôle des hallucinations (retour d'expérience)

Les tests ont mis en évidence deux défaillances, corrigées ensuite :

| Problème constaté | Cause | Correctif |
|---|---|---|
| Mitigations d'autres techniques mélangées à celles de T1003.001, et le modèle affirmait qu'elles venaient toutes du contexte demandé | La récupération ajoutait des chunks de recherche sémantique générale aux chunks filtrés par ID | **Filtrage strict** : si un ID est détecté, seuls les chunks de cette technique sont fournis |
| Règles « Wazuh » inventées (format JSON, IDs de règles fictifs, commande inexistante) alors qu'ATT&CK ne contient aucune règle propre à un outil | Le prompt n'interdisait pas explicitement de combler les vides | Règles explicites dans le prompt : signaler l'absence de syntaxe d'outil dans ATT&CK, ne jamais inventer règle, ID ou commande |

Limites connues, à garder en tête :

- Le LLM peut **ajouter des détails de mémoire** autour des faits ancrés (descriptions d'Event IDs, paramètres). Les éléments critiques doivent être vérifiés dans la documentation officielle.
- La liste « Sources » affichée correspond aux chunks **récupérés**, pas nécessairement à ceux réellement utilisés dans la réponse.
- ATT&CK décrit des comportements et des sources de logs, pas des règles prêtes à l'emploi pour un SIEM donné.
- Une alerte seule ne prouve pas une compromission : la fiche de triage est une aide à l'analyse, pas un verdict.

## Sécurité

- Les champs d'une alerte sont traités comme des **données non fiables** dans le prompt de triage (mitigation de l'injection de prompt indirecte).
- La clé API reste dans `.env`, exclu du dépôt via `.gitignore`.

## Structure du dépôt

```
cybermind/
├── extract_attack.py     # STIX -> techniques.json (mitigations + détections)
├── build_index.py        # chunking + embeddings + ChromaDB
├── rag.py                # récupération + chaîne RAG (CLI)
├── analyze.py            # triage d'une alerte Wazuh (JSON)
├── list_models.py        # liste les modèles Groq disponibles
├── samples/              # exemples d'alertes
├── requirements.txt
└── .gitignore            # .env, venv/, chroma_db/, data/
```

## Pistes d'amélioration

- Interface web (Streamlit) pour le chat et le triage d'alertes
- Jeu de questions d'évaluation (précision de la récupération, taux de refus hors contexte)
- Correspondance « technique → événements Sysmon à surveiller dans Wazuh », issue de tests réels en laboratoire
- Prise en charge d'autres domaines ATT&CK (Cloud, ICS, Mobile)

## Licence et attributions

Projet à but pédagogique. Les données proviennent de **MITRE ATT&CK®**, marque déposée de The MITRE Corporation, utilisées selon leurs conditions d'utilisation : <https://attack.mitre.org/resources/terms-of-use/>.

## Auteure

**Hajer Ben Ghazi** — Élève ingénieure en Informatique, Faculté des Sciences de Tunis
GitHub : [hajerbgh](https://github.com/hajerbgh)
