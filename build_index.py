import json
import re
import shutil
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

SRC = "data/techniques.json"
DB_DIR = "chroma_db"

with open(SRC, encoding="utf-8") as f:
    techniques = json.load(f)


def clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)       # (Citation: ...)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # [texte](url) -> texte
    return re.sub(r"\s+", " ", text).strip()


splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
docs = []

for t in techniques:
    header = f"{t['id']} - {t['name']} [{', '.join(t['tactics'])}]"
    base = {
        "technique_id": t["id"],
        "technique_name": t["name"],
        "tactics": ",".join(t["tactics"]),
        "platforms": ",".join(t["platforms"]),
    }

    # 1) Description générale
    if t["description"]:
        for chunk in splitter.split_text(clean(t["description"])):
            docs.append(Document(
                page_content=f"{header}\nDESCRIPTION: {chunk}",
                metadata={**base, "kind": "overview"},
            ))

    # 2) Détection (une analytique = un chunk)
    for d in t["detections"]:
        for a in d["analytics"]:
            parts = [f"{header}\nDETECTION ({d['strategy']}):", clean(a["description"])]
            if a["log_sources"]:
                parts.append("Sources de logs: " + "; ".join(a["log_sources"]))
            if a["tuning"]:
                parts.append("A ajuster: " + " | ".join(a["tuning"]))
            docs.append(Document(
                page_content="\n".join(parts),
                metadata={**base, "kind": "detection",
                          "det_platforms": ",".join(a["platforms"])},
            ))

    # 3) Mitigations (toutes regroupées, puis découpées si trop longues)
    if t["mitigations"]:
        text = " ".join(f"{m['name']}: {clean(m['how'])}" for m in t["mitigations"])
        for chunk in splitter.split_text(text):
            docs.append(Document(
                page_content=f"{header}\nMITIGATION: {chunk}",
                metadata={**base, "kind": "mitigation"},
            ))

print(f"Chunks à indexer : {len(docs)}")
for k in ("overview", "detection", "mitigation"):
    print(f"  {k:<11}: {sum(1 for d in docs if d.metadata['kind'] == k)}")

# Reconstruction propre de la base
if Path(DB_DIR).exists():
    shutil.rmtree(DB_DIR)

print("\nChargement du modèle d'embeddings (1er lancement : téléchargement ~90 Mo)...")
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

db = Chroma(
    collection_name="attack",
    embedding_function=embeddings,
    persist_directory=DB_DIR,
)

BATCH = 500
for i in range(0, len(docs), BATCH):
    db.add_documents(docs[i:i + BATCH])
    print(f"  indexé {min(i + BATCH, len(docs))}/{len(docs)}")

# Test de récupération
print("\n--- Test ---")
for q in ["PowerShell encoded command execution",
          "which Sysmon events detect credential dumping from LSASS"]:
    print(f"\nQ: {q}")
    for r in db.similarity_search(q, k=3):
        m = r.metadata
        print(f"  {m['technique_id']:<10} {m['kind']:<10} {m['technique_name']}")