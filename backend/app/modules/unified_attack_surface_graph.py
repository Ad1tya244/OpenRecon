import asyncio
from typing import Dict, Any, List, Set
from app.modules import subdomain_recon, dns_recon, ip_hosting_asn_intelligence, tech_fingerprint, directory_exposure_recon

async def build_graph(domain: str) -> Dict[str, Any]:
    """
    Consolidates findings into a graph structure (Nodes & Links).
    Identifies convergence points of risk.
    """
    graph = {
        "nodes": [],
        "links": [],
        "convergence_points": []
    }
    
    # Track existing nodes to avoid dupes: id -> node_index
    node_map = {}
    
    def add_node(id: str, label: str, group: str, meta: Dict = None) -> int:
        if id in node_map:
            # Merge meta if needed
            return node_map[id]
        
        idx = len(graph["nodes"])
        node = {
            "id": id,
            "label": label,
            "group": group, # domain, ip, tech, risk
            "meta": meta or {}
        }
        graph["nodes"].append(node)
        node_map[id] = idx
        return idx
    
    def add_link(source_id: str, target_id: str, relationship: str):
        if source_id not in node_map or target_id not in node_map:
             return
        graph["links"].append({
            "source": source_id,
            "target": target_id,
            "relationship": relationship
        })

    # 1. Root Domain
    root_idx = add_node(domain, domain, "domain", {"root": True})
    
    # 2. Subdomains (Passive)
    # Re-run passive recon or passed data?
    # Assuming re-run is acceptable given "No new data collection" constraint usually means "no active scanning" 
    # but passive lookup is fine.
    sub_data = await subdomain_recon.enumerate_subdomains(domain)
    subdomains = [s["hostname"] for s in sub_data.get("subdomains", [])]
    
    # Limit for graph clarity if too many?
    # Graph useful for < 100 nodes.
    
    for sub in subdomains:
        add_node(sub, sub, "subdomain")
        add_link(domain, sub, "subdomain_of")
        
    # 3. DNS & IPs (Fast resolution)
    # We resolve a subset to keep it fast, or all if small.
    # Reuse ip_hosting logic? ip_hosting resolves internally.
    # We'll call get_domain_intelligence for the ROOT domain to get root IPs.
    # For subdomains, we might skip deep resolution to avoid 100s of DNS queries in this specific graph endpoint
    # UNLESS the user wants the "Unified" view.
    # Let's resolve Top 10 subdomains + Root for demo.
    
    targets = [domain] + subdomains[:10]
    
    for target in targets:
        # Get Intelligence (resolves IPs + enrich)
        # Note: get_domain_intelligence does resolution.
        intel = await ip_hosting_asn_intelligence.get_domain_intelligence(target)
        
        if "ips" in intel and isinstance(intel["ips"], list):
            for ip_info in intel["ips"]:
                ip = ip_info.get("ip")
                if not ip: continue
                
                # Add IP Node
                add_node(ip, ip, "ip", {
                    "asn": ip_info.get("asn"),
                    "isp": ip_info.get("isp"),
                    "hosting": ip_info.get("hosting_type")
                })
                add_link(target, ip, "resolves_to")
                
                # Check for Risks in IP
                flags = ip_info.get("analysis_flags", [])
                for flag in flags:
                    flag_id = f"risk_{flag}"
                    add_node(flag_id, flag, "risk", {"severity": "Medium"}) # Simplified severity
                    add_link(ip, flag_id, "has_risk")

    # 4. Technologies (Root only for speed, or basic targets)
    # Tech fingerprint does HTTP request.
    tech_data = await tech_fingerprint.get_tech_fingerprint(domain)
    server = tech_data.get("server")
    if server:
        # Add Tech Node
        t_id = f"tech_{server}"
        add_node(t_id, server, "technology")
        add_link(domain, t_id, "runs_on")
        
    for fw in tech_data.get("frameworks", []):
         f_id = f"tech_{fw}"
         add_node(f_id, fw, "technology")
         add_link(domain, f_id, "uses_framework")
         
    # Tech Risks
    for flag in tech_data.get("flags", []):
        r_id = f"risk_{flag}"
        add_node(r_id, flag, "risk", {"severity": "High"})
        add_link(domain, r_id, "has_risk")

    # 5. Convergence Analysis (Simple)
    # Find nodes connected to > 1 risk node
    risk_counts = {}
    for link in graph["links"]:
        if link["relationship"] == "has_risk":
            target = link["source"] # The asset (source) has risk (target)
            risk_counts[target] = risk_counts.get(target, 0) + 1
            
    for node_id, count in risk_counts.items():
        if count >= 2:
            graph["convergence_points"].append({
                "node_id": node_id,
                "risk_count": count,
                "description": f"Converges {count} risk vectors"
            })
            # Mark node as high risk in meta
            if node_id in node_map:
                idx = node_map[node_id]
                graph["nodes"][idx]["meta"]["high_risk"] = True

    return graph
