import json

with open("data/enterprise-attack.json", encoding="utf-8") as f:
    objects = json.load(f)["objects"]

by_id = {o["id"]: o for o in objects}

tech = next(
    o for o in objects
    if o.get("type") == "attack-pattern"
    and any(r.get("external_id") == "T1059.001" for r in o.get("external_references", []))
)

for o in objects:
    if (o.get("type") == "relationship"
            and o["relationship_type"] == "detects"
            and o["target_ref"] == tech["id"]):
        strat = by_id[o["source_ref"]]
        print("=== STRATEGIE ===")
        print("type :", strat["type"])
        print("nom  :", strat["name"])
        print("champs :", list(strat.keys()))

        for ref in strat.get("x_mitre_analytic_refs", []):
            a = by_id.get(ref)
            if not a:
                continue
            print("\n--- ANALYTIQUE ---")
            print("type :", a["type"])
            print("champs :", list(a.keys()))
            print("plateformes :", a.get("x_mitre_platforms"))
            print("description :", (a.get("description") or "")[:400])
            print("log sources :", json.dumps(a.get("x_mitre_log_sources"), indent=1)[:600])