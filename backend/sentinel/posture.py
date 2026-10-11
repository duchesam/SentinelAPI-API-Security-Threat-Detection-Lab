"""Evaluate exported fixture configuration, never connect to or scan cloud assets."""
def evaluate(assets):
    findings=[]
    for a in assets:
        if a.get("public"):
            findings.append({"asset":a["id"],"rule":"POSTURE-001","severity":"high","reason":"Public exposure in supplied configuration"})
        if "*" in a.get("permissions",[]):
            findings.append({"asset":a["id"],"rule":"POSTURE-002","severity":"high","reason":"Wildcard permissions"})
        if a.get("encrypted") is False:
            findings.append({"asset":a["id"],"rule":"POSTURE-003","severity":"medium","reason":"Encryption disabled"})
    return findings

def attack_paths(assets):
    by_id={a["id"]:a for a in assets}; paths=[]
    def visit(node,path):
        if node in path or node not in by_id: return
        chain=path+[node]; a=by_id[node]
        if a.get("sensitive"):
            paths.append({"nodes":["internet"]+chain,"basis":"Explicit public and can_access fixture relationships; no exploit validation","priority":"high"})
        for target in a.get("can_access",[]): visit(target,chain)
    for a in assets:
        if a.get("public"): visit(a["id"],[])
    return paths
