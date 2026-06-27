
import sys
import json
import networkx as nx
import urllib.request

GEXF_FILE = "system_behavior_graph.gexf"
HTML_FILE  = "kguard_interactive_graph.html"

print("Loading saved K-Guard system graph...")
try:
    G = nx.read_gexf(GEXF_FILE)
except FileNotFoundError:
    print(f"ERROR: '{GEXF_FILE}' not found.", file=sys.stderr)
    sys.exit(1)

if G.number_of_nodes() == 0:
    print("ERROR: Graph is empty.", file=sys.stderr)
    sys.exit(1)

print(f"Graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

# Build node and edge lists for D3
nodes = []
for node, attrs in G.nodes(data=True):
    node_type = attrs.get("type", "unknown")
    safe_id = f"proc_{node[0]}_{node[1]}" if isinstance(node, tuple) else str(node)

    if node_type == "process":
        label = f"{attrs.get('comm','?')} ({attrs.get('pid','?')})"
        color = "#ff7675"
        tooltip = f"Process: {attrs.get('comm')}&#10;PID: {attrs.get('pid')}&#10;UID: {attrs.get('uid')}"
    elif node_type == "file_binary":
        label = str(node).split("/")[-1]
        color = "#74b9ff"
        tooltip = f"Binary: {node}"
    elif node_type == "file_data":
        label = str(node).split("/")[-1]
        color = "#55efc4"
        tooltip = f"Data File: {node}"
    elif node_type == "network_socket":
        label = str(node)
        color = "#a29bfe"
        tooltip = f"Socket: {attrs.get('ip')}:{attrs.get('port')}"
    else:
        label = str(node)[:20]
        color = "#636e72"
        tooltip = str(node)

    nodes.append({"id": safe_id, "label": label, "color": color, "tooltip": tooltip})

edges = []
for src, tgt, edata in G.edges(data=True):
    safe_src = f"proc_{src[0]}_{src[1]}" if isinstance(src, tuple) else str(src)
    safe_tgt = f"proc_{tgt[0]}_{tgt[1]}" if isinstance(tgt, tuple) else str(tgt)
    edges.append({
        "source": safe_src,
        "target": safe_tgt,
        "label": edata.get("relation", "")
    })

nodes_json = json.dumps(nodes)
edges_json = json.dumps(edges)
try:
    d3_js = urllib.request.urlopen("https://d3js.org/d3.v7.min.js", timeout=10).read().decode()
except Exception:
    print("WARNING: Could not fetch D3 from CDN.", file=sys.stderr)
    d3_js = "console.error('D3 failed to load');"
html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ margin:0; background:#0d1117; overflow:hidden; }}
  svg {{ width:100vw; height:100vh; }}
  .node circle {{ stroke:#0d1117; stroke-width:2px; cursor:grab; }}
  .node text {{ font:11px sans-serif; fill:#e6edf3; pointer-events:none; }}
  .link {{ stroke:#ffeaa7; stroke-opacity:0.5; stroke-width:1.5px; }}
  .link-label {{ font:9px sans-serif; fill:#8b949e; }}
  #tooltip {{
    position:absolute; background:#161b22; color:#e6edf3;
    border:1px solid #30363d; padding:6px 10px; border-radius:4px;
    font:12px sans-serif; pointer-events:none; white-space:pre;
    display:none; max-width:320px;
  }}
  #legend {{
    position:absolute; top:10px; left:10px; background:#161b22;
    border:1px solid #30363d; padding:8px 12px; border-radius:4px;
  }}
  .leg {{ display:flex; align-items:center; gap:8px;
          font:11px sans-serif; color:#e6edf3; margin:3px 0; }}
  .dot {{ width:12px; height:12px; border-radius:50%; flex-shrink:0; }}
</style>
</head>
<body>
<div id="tooltip"></div>
<div id="legend">
  <div class="leg"><div class="dot" style="background:#ff7675"></div>Process</div>
  <div class="leg"><div class="dot" style="background:#74b9ff;border-radius:2px"></div>Binary</div>
  <div class="leg"><div class="dot" style="background:#55efc4;border-radius:0"></div>Data File</div>
  <div class="leg"><div class="dot" style="background:#a29bfe;clip-path:polygon(50% 0%,100% 100%,0% 100%)"></div>Network</div>
</div>
<svg id="graph"></svg>

<script>{d3_js}</script>
<script>
const nodes = {nodes_json};
const edges = {edges_json};

const svg = d3.select("#svg#graph");
const width  = window.innerWidth;
const height = window.innerHeight;
const tip    = document.getElementById("tooltip");

const svgEl = d3.select("#graph")
  .attr("width", width).attr("height", height);

// Arrow marker
svgEl.append("defs").append("marker")
  .attr("id","arrow").attr("viewBox","0 -5 10 10")
  .attr("refX",20).attr("refY",0)
  .attr("markerWidth",6).attr("markerHeight",6)
  .attr("orient","auto")
  .append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#ffeaa7");

const g = svgEl.append("g");

// Zoom
svgEl.call(d3.zoom().scaleExtent([0.1,8]).on("zoom", e => g.attr("transform", e.transform)));

const sim = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(edges).id(d => d.id).distance(120))
  .force("charge", d3.forceManyBody().strength(-400))
  .force("center", d3.forceCenter(width/2, height/2))
  .force("collision", d3.forceCollide(30));

const link = g.append("g").selectAll("line")
  .data(edges).join("line")
  .attr("class","link")
  .attr("marker-end","url(#arrow)");

const linkLabel = g.append("g").selectAll("text")
  .data(edges).join("text")
  .attr("class","link-label")
  .text(d => d.label);

const node = g.append("g").selectAll("g")
  .data(nodes).join("g")
  .attr("class","node")
  .call(d3.drag()
    .on("start", (e,d) => {{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
    .on("drag",  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
    .on("end",   (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}));

node.append("circle").attr("r",14).attr("fill", d => d.color);
node.append("text").attr("dy","28px").attr("text-anchor","middle").text(d => d.label);

node.on("mouseover", (e,d) => {{
    tip.style.display = "block";
    tip.style.left = (e.pageX+12)+"px";
    tip.style.top  = (e.pageY-10)+"px";
    tip.textContent = d.tooltip;
  }})
  .on("mousemove", e => {{
    tip.style.left = (e.pageX+12)+"px";
    tip.style.top  = (e.pageY-10)+"px";
  }})
  .on("mouseout", () => tip.style.display="none");

sim.on("tick", () => {{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  linkLabel.attr("x",d=>(d.source.x+d.target.x)/2)
           .attr("y",d=>(d.source.y+d.target.y)/2);
  node.attr("transform", d=>`translate(${{d.x}},${{d.y}})`);
}});
</script>
</body>
</html>"""

with open(HTML_FILE, "w") as f:
    f.write(html)

print(f"Graph saved to '{HTML_FILE}'")