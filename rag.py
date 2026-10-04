import os
import re

from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEmbeddings

load_dotenv(override=True)

DB_DIR = "chroma_db"
MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
db = Chroma(collection_name="attack", embedding_function=embeddings,
            persist_directory=DB_DIR)
llm = ChatGroq(model=MODEL, temperature=0)

PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "Tu es CyberMind, un assistant de threat intelligence pour analystes SOC. "
     "Tu réponds UNIQUEMENT à partir du CONTEXTE fourni, issu de MITRE ATT&CK.\n"
     "Règles strictes :\n"
     "- Chaque extrait commence par 'ID - Nom [tactique]'. Si la question vise une "
     "technique précise, n'utilise que les extraits portant cet ID.\n"
     "- Cite les IDs de techniques (ex. T1059.001) pour chaque affirmation.\n"
     "- Pour la détection, donne les sources de logs (Sysmon EventCode, Windows "
     "Event ID) et les éléments à ajuster présents dans le contexte.\n"
     "- ATT&CK ne contient AUCUNE règle ni syntaxe propre à un outil (Wazuh, Splunk, "
     "Sentinel, Sigma...). Si la question cite un outil, dis-le explicitement, puis "
     "donne uniquement ce qu'ATT&CK fournit (événements à collecter, comportements "
     "à repérer). N'invente jamais de règle, d'ID de règle, de commande ou de syntaxe.\n"
     "- Si le contexte ne permet pas de répondre, dis-le clairement.\n"
     "- Réponds dans la langue de la question, de façon structurée et concise."),
    ("human", "CONTEXTE :\n{context}\n\nQUESTION : {question}"),
])

ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def retrieve(question: str, k: int = 6):
    ids = {m.upper() for m in ID_RE.findall(question)}
    docs = []
    if ids:
        # Question sur une technique précise : UNIQUEMENT ses chunks
        for tid in ids:
            docs += db.similarity_search(question, k=12, filter={"technique_id": tid})
    else:
        docs = db.similarity_search(question, k=k)

    seen, unique = set(), []
    for d in docs:
        if d.page_content not in seen:
            seen.add(d.page_content)
            unique.append(d)
    return unique


def ask(question: str):
    docs = retrieve(question)
    context = "\n\n---\n\n".join(d.page_content for d in docs)
    answer = (PROMPT | llm).invoke({"context": context, "question": question})
    sources = sorted({(d.metadata["technique_id"], d.metadata["technique_name"])
                      for d in docs})
    return answer.content, sources


if __name__ == "__main__":
    print(f"CyberMind prêt (modèle : {MODEL}). Ctrl+C pour quitter.\n")
    while True:
        q = input("Question > ").strip()
        if not q:
            continue
        text, sources = ask(q)
        print("\n" + text)
        print("\nSources :", ", ".join(f"{i} ({n})" for i, n in sources), "\n")