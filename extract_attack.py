import json
from collections import defaultdict

SRC = "data/enterprise-attack.json"
OUT = "data/techniques.json"

with open(SRC, encoding="utf-8") as f:
    objects = json.load(f)["objects"]

by_id = {o["id"]: o for o in objects}


def active(o):
    return o and not o.get("revoked") and not o.get("x_mitre_deprecated")


def log_sources(analytic):
    """Extrait les sources de logs de façon défensive (structure variable)."""
    out = []
    for ref in analytic.get("x_mitre_log_source_references", []) or []:
        if isinstance(ref, dict):
            comp = by_id.get(ref.get("x_mitre_data_component_ref", ""))
            name = ref.get("name") or (comp or {}).get("name", "")
            channel = ref.get("channel", "")
            out.append(f"{name} ({channel})" if channel else name)
        elif isinstance(ref, str):
            comp = by_id.get(ref)
            out.append(comp["name"] if comp else ref)
    return [x for x in out if x]


def tuning(analytic):
    out = []
    for m in analytic.get("x_mitre_mutable_elements", []) or []:
        if isinstance(m, dict):
            out.append(f"{m.get('field', '')}: {m.get('description', '')}".strip(": "))
        else:
            out.append(str(m))
    return out


mitigations = defaultdict(list)
detections = defaultdict(list)

for o in objects:
    if o.get("type") != "relationship":
        continue
    src = by_id.get(o["source_ref"])
    if not active(src):
        continue
    if o["relationship_type"] == "mitigates" and src["type"] == "course-of-action":
        mitigations[o["target_ref"]].append(
            {"name": src["name"], "how": o.get("description", "").strip()}
        )
    elif o["relationship_type"] == "detects" and src["type"] == "x-mitre-detection-strategy":
        analytics = []
        for aref in src.get("x_mitre_analytic_refs", []):
            a = by_id.get(aref)
            if not active(a):
                continue
            analytics.append({
                "description": (a.get("description") or "").strip(),
                "platforms": a.get("x_mitre_platforms", []),
                "log_sources": log_sources(a),
                "tuning": tuning(a),
            })
        detections[o["target_ref"]].append({"strategy": src["name"], "analytics": analytics})

techniques = []
for o in objects:
    if o.get("type") != "attack-pattern" or not active(o):
        continue
    ext_id = next(
        (r["external_id"] for r in o.get("external_references", [])
         if r.get("source_name") == "mitre-attack"),
        None,
    )
    if not ext_id:
        continue
    techniques.append({
        "id": ext_id,
        "name": o["name"],
        "description": o.get("description", "").strip(),
        "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
        "platforms": o.get("x_mitre_platforms", []),
        "detections": detections.get(o["id"], []),
        "mitigations": mitigations.get(o["id"], []),
    })

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(techniques, f, ensure_ascii=False, indent=2)

n_an = sum(len(d["analytics"]) for t in techniques for d in t["detections"])
n_ls = sum(1 for t in techniques for d in t["detections"]
           for a in d["analytics"] if a["log_sources"])
print(f"Techniques extraites     : {len(techniques)}")
print(f"Avec mitigations         : {sum(1 for t in techniques if t['mitigations'])}")
print(f"Avec detections          : {sum(1 for t in techniques if t['detections'])}")
print(f"Analytiques au total     : {n_an}")
print(f"Analytiques + log sources: {n_ls}")

t = next(t for t in techniques if t["id"] == "T1059.001")
print("\n--- T1059.001 ---")
for d in t["detections"]:
    print("Strategie :", d["strategy"])
    for a in d["analytics"]:
        print("  plateformes :", a["platforms"])
        print("  log sources :", a["log_sources"])
        print("  tuning      :", a["tuning"][:2])