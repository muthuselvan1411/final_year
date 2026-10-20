import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { apiBase, getJson, Source } from "./api";
import { ReactFlow, Background, Controls, MiniMap, MarkerType, type Edge, type Node, type NodeMouseHandler, type EdgeMouseHandler } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./styles.css";

type Event = Record<string, any>;
type Incident = { index: number; event?: Event; supporting_events?: Event[]; supporting_event_ids?: string[]; decision?: Record<string, any>; evidence?: Record<string, any>; correlation?: Record<string, any>; prediction?: Record<string, any> };
type Summary = { source: Source & { malformed_records: number; errors: string[] }; total_events: number; incidents_recorded: number; event_types: Record<string, number>; decisions: Record<string, number>; detector_status: Record<string, number>; timestamp_bases: Record<string, number>; abstain_count: number };
type TestRecord = { event: Event; decision: Record<string, any>; correlation: Record<string, any>; supporting_events?: Event[]; evidence?: Record<string, any> };
type TestRun = { source: { label: string; kind: string }; scenario: string; records: TestRecord[]; total_events: number; decision_counts: Record<string, number>; detector_status: string; side_effects: string };
type View = "live" | "behavior" | "incidents" | "events";
type GraphPayload = {
  nodes: Array<{ id: string; type: string; label: string; data: Record<string, any> }>;
  edges: Array<{ id: string; source: string; target: string; type: string; source_event_id?: string; target_event_id?: string; evidence?: string; inferred?: boolean; details?: Record<string, any> }>;
  capture_contexts: string[];
  schema_ids: string[];
  windows: Array<Record<string, any>>;
  limitations: string[];
};

const tabs: Array<[View, string]> = [["live", "Live Monitoring"], ["behavior", "Behavioral Analysis"], ["incidents", "Incident Investigation"], ["events", "Event Explorer"]];

function App() {
  const [sources, setSources] = useState<Source[]>([]);
  const [source, setSource] = useState("");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [view, setView] = useState<View>("live");
  const [query, setQuery] = useState("");
  const [testRun, setTestRun] = useState<TestRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = () => {
    if (!source) return;
    setError("");
    Promise.all([
      getJson<Summary>(`/api/summary?source=${encodeURIComponent(source)}`),
      getJson<{ items: Incident[] }>(`/api/incidents?source=${encodeURIComponent(source)}&limit=200`),
      getJson<{ items: Event[] }>(`/api/events?source=${encodeURIComponent(source)}&limit=200`),
    ]).then(([nextSummary, nextIncidents, nextEvents]) => {
      setSummary(nextSummary); setIncidents(nextIncidents.items); setEvents(nextEvents.items); setSelected(null);
    }).catch((err: Error) => setError(err.message));
  };

  useEffect(() => {
    getJson<{ sources: Source[] }>("/api/sources").then((data) => {
      setSources(data.sources); if (data.sources[0]) setSource(data.sources[0].name);
    }).catch((err: Error) => setError(err.message));
  }, []);
  useEffect(refresh, [source]);

  const runTest = () => {
    setBusy(true); setError("");
    fetch(`${apiBase}/api/test-simulation`, { method: "POST" })
      .then(async (response) => { if (!response.ok) throw new Error((await response.json()).detail ?? response.statusText); return response.json() as Promise<TestRun>; })
      .then((result) => { setTestRun(result); setView("behavior"); })
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };

  const filteredIncidents = useMemo(() => incidents.filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase())), [incidents, query]);
  return <main className="shell">
    <header className="topbar">
      <div className="brand"><span className="mark">RS</span><div><strong>RansomShield</strong><small> evidence console</small></div></div>
      <div className="header-actions"><label>DATA SOURCE <select value={source} onChange={(event) => { setSource(event.target.value); setTestRun(null); }}>{sources.map((item) => <option key={item.name} value={item.name}>{item.label} · {item.kind}</option>)}</select></label><button className="ghost" onClick={refresh}>Refresh</button><button className="test-button" onClick={runTest} disabled={busy}>{busy ? "Testing…" : "Run safe test"}</button></div>
    </header>
    <div className="notice"><span className="status-dot" /> {summary ? `${summary.source.kind.toUpperCase()} · ${summary.source.label}` : "No source selected"} <span>Read-only · detector unavailable · no containment</span></div>
    <nav className="tabs">{tabs.map(([key, label]) => <button className={view === key ? "active" : ""} onClick={() => setView(key)} key={key}>{label}</button>)}</nav>
    {error && <div className="error">{error}</div>}
    {view === "live" && <LiveMonitoring summary={summary} incidents={incidents} events={events} onSelect={(item) => { setSelected(item); setView("incidents"); }} />}
    {view === "behavior" && <BehavioralAnalysis source={source} incidents={incidents} testRun={testRun} />}
    {view === "incidents" && <IncidentInvestigation incidents={filteredIncidents} selected={selected} query={query} setQuery={setQuery} onSelect={setSelected} />}
    {view === "events" && <EventExplorer events={events} query={query} setQuery={setQuery} />}
  </main>;
}

function LiveMonitoring({ summary, incidents, events, onSelect }: { summary: Summary | null; incidents: Incident[]; events: Event[]; onSelect: (item: Incident) => void }) {
  if (!summary) return <Empty title="Waiting for a configured source" text="Set RSHIELD_DASHBOARD_SOURCES and start the API." />;
  return <section><div className="page-heading"><div><p className="eyebrow">LIVE MONITORING</p><h1>{summary.source.label}</h1><p className="muted">Observed records from the selected {summary.source.kind} source. Historical data is not presented as live activity.</p></div><div className="availability"><span className="warning-dot" /> DETECTOR UNAVAILABLE<br /><b>ABSTAIN / null probability</b></div></div><div className="metrics"><Metric label="Events observed" value={summary.total_events} /><Metric label="Incidents recorded" value={summary.incidents_recorded} /><Metric label="ABSTAIN decisions" value={summary.abstain_count} /><Metric label="Malformed records" value={summary.source.malformed_records} /></div><div className="two-column"><Panel title="Event distribution"><Bars values={summary.event_types} /></Panel><Panel title="Decision distribution"><Bars values={summary.decisions} /></Panel></div><Panel title="Recent evidence"><div className="evidence-table"><div className="row header"><span>Event</span><span>Process</span><span>Decision</span><span>Source ID</span></div>{incidents.slice(-8).reverse().map((item) => <button className="row" key={item.index} onClick={() => onSelect(item)}><span>{item.event?.event_type ?? "OTHER"}</span><span>{item.event?.process ?? "—"} <small>#{item.event?.pid ?? "—"}</small></span><span className="state">{item.decision?.action ?? "—"}</span><span className="mono">{item.event?.source_event_id ?? "—"}</span></button>)}</div></Panel><p className="event-count">{events.length} normalized event records available to explore</p></section>;
}

function BehavioralAnalysis({ source, incidents, testRun }: { source: string; incidents: Incident[]; testRun: TestRun | null }) {
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  const [graphError, setGraphError] = useState("");
  const [graphLoading, setGraphLoading] = useState(true);
  useEffect(() => {
    if (!source) return;
    setGraph(null);
    setGraphError("");
    setGraphLoading(true);
    getJson<{ graph: GraphPayload }>(`/api/graph?source=${encodeURIComponent(source)}`)
      .then((payload) => setGraph(payload.graph))
      .catch((err: Error) => setGraphError(err.message))
      .finally(() => setGraphLoading(false));
  }, [source]);
  const testRecord = testRun?.records[testRun.records.length - 1];
  const record = testRecord ?? incidents[incidents.length - 1];
  const correlation = testRecord?.correlation ?? record?.correlation;
  if (graphError) return <Empty title="Graph unavailable" text={graphError} />;
  if (graphLoading) return <Empty title="Loading evidence graph" text="Reading persisted relationships from the selected source." />;
  if (graph && !testRun) return <GraphWorkspace source={source} graph={graph} incidents={incidents} />;
  if (!record || !correlation) return <Empty title="No correlation evidence available" text="Select a source with persisted correlation records or run the safe in-memory test." />;
  const relationships = correlation.relationships ?? [];
  const features = correlation.feature_values ?? {};
  const available = correlation.available ?? {};
  const timelineEvents = testRecord?.supporting_events ?? (record as Incident).supporting_events ?? [];
  return <section><div className="page-heading"><div><p className="eyebrow">BEHAVIORAL ANALYSIS</p><h1>Evidence-backed correlation</h1><p className="muted">Only persisted relationship records are shown. No edge is inferred by the browser.</p></div><div className="schema">{correlation.schema_id ?? "No correlation schema"}<br /><small>{correlation.capture_context ?? record.event?.source_context ?? "context unavailable"}</small></div></div><div className="analysis-meta"><span>Window {correlation.window_start ?? "—"} → {correlation.window_end ?? "—"}</span><span>Basis: {correlation.timestamp_source ?? "unavailable"} ({correlation.timestamp_unit ?? "—"})</span><span>Supporting events: {(correlation.supporting_event_ids ?? []).length}</span></div><div className="analysis-grid"><Panel title="Process / entity relationships"><div className="relationship-graph">{relationships.length === 0 ? <Empty title="No relationships recorded" text="This window has no supported parent-child, file, network or ordering edges." /> : relationships.map((relation: any, index: number) => <div className="edge" key={`${relation.relationship_type}-${index}`}><span className={relation.inferred ? "inferred" : "observed"}>{relation.inferred ? "INFERRED" : "OBSERVED"}</span><b>{relation.relationship_type}</b><small>{relation.source_event_id ?? "—"} → {relation.target_event_id ?? "—"}</small><em>{relation.evidence}</em></div>)}</div></Panel><Panel title="Correlation feature vector"><div className="feature-list">{Object.entries(features).map(([name, value]) => <div className="feature" key={name}><span>{name}</span><b>{String(value)}</b><i className={available[name] ? "available" : "missing"}>{available[name] ? "available" : "unavailable"}</i></div>)}</div></Panel></div><Panel title="Ordered event timeline"><div className="timeline">{timelineEvents.map((event, index) => <div className="timeline-item" key={`${event.source_event_id}-${index}`}><span className="mono">{event.timestamp_ns ?? event.timestamp ?? "—"}</span><b>{event.event_type ?? "OTHER"}</b><code>{event.source_event_id ?? "—"}</code></div>)}</div></Panel><Panel title="Supporting event IDs"><div className="chips">{(correlation.supporting_event_ids ?? []).map((id: string) => <code key={id}>{id}</code>)}</div><p className="limitations">{[...(correlation.limitations ?? []), ...(record.evidence?.limitations ?? [])].map((item: string) => <span key={item}>{item}</span>)}</p></Panel></section>;
}

function GraphWorkspace({ source, graph, incidents }: { source: string; graph: GraphPayload; incidents: Incident[] }) {
  const [selectedId, setSelectedId] = useState("");
  const [eventDetail, setEventDetail] = useState<Event | null>(null);
  useEffect(() => setSelectedId(""), [graph]);
  const processNodes = graph.nodes.filter((node) => node.type === "process");
  const otherNodes = graph.nodes.filter((node) => node.type !== "process");
  const nodes: Node[] = [...processNodes, ...otherNodes].map((node, index) => ({
    id: node.id,
    position: node.type === "process"
      ? { x: 80, y: index * 180 + 90 }
      : { x: node.type === "file" ? 420 : 760, y: (index - processNodes.length) * 130 + 80 },
    data: { label: <div><strong>{node.label}</strong><small>{node.type}{node.data.pid ? ` · PID ${node.data.pid}` : ""}</small></div> },
    className: `graph-node ${node.type}`,
  }));
  const edges: Edge[] = graph.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.type,
    markerEnd: { type: MarkerType.ArrowClosed, color: edge.inferred ? "#f0bd59" : "#72dfca" },
    className: edge.inferred ? "graph-edge inferred-edge" : "graph-edge",
    data: edge,
  }));
  const selectedNode = graph.nodes.find((node) => node.id === selectedId);
  const selectedEdge = graph.edges.find((edge) => edge.id === selectedId);
  const latest = incidents[incidents.length - 1];
  const correlation = latest?.correlation ?? {};
  const onNodeClick: NodeMouseHandler = (_, node) => setSelectedId(node.id);
  const onEdgeClick: EdgeMouseHandler = (_, edge) => {
    setSelectedId(edge.id);
    setEventDetail(null);
    if (edge.data?.source_event_id) {
      getJson<{ event: Event }>(`/api/events/${encodeURIComponent(String(edge.data.source_event_id))}?source=${encodeURIComponent(source)}`)
        .then((payload) => setEventDetail(payload.event))
        .catch(() => setEventDetail(null));
    }
  };
  return <section>
    <div className="page-heading"><div><p className="eyebrow">BEHAVIORAL ANALYSIS</p><h1>Evidence-backed correlation</h1><p className="muted">Interactive graph from persisted entity endpoints. Selecting an edge or node never creates new evidence.</p></div><div className="schema">{graph.schema_ids.join(", ") || "No correlation schema"}<br /><small>{graph.capture_contexts.join(", ") || "context unavailable"}</small></div></div>
    <div className="analysis-meta"><span>Nodes: {graph.nodes.length}</span><span>Relationships: {graph.edges.length}</span><span>Source contexts: {graph.capture_contexts.length}</span><span>Windows: {graph.windows.length}</span></div>
    <div className="graph-layout">
      <div className="graph-canvas"><div className="graph-legend"><span className="legend-process">Process</span><span className="legend-file">File</span><span className="legend-network">Network</span><span>Solid = observed · dashed = inferred</span></div>{nodes.length ? <ReactFlow nodes={nodes} edges={edges} fitView onNodeClick={onNodeClick} onEdgeClick={onEdgeClick}><Background color="#26323e" gap={24} /><Controls /><MiniMap /></ReactFlow> : <Empty title="No relationship evidence" text="Correlation completed, but this source contains no supported entity-to-entity relationships." />}</div>
      <aside className="graph-inspector"><p className="eyebrow">SELECTION</p>{selectedNode ? <><h2>{selectedNode.label}</h2><Detail label="Entity">{selectedNode.type}<br /><code>{selectedNode.id}</code></Detail><Detail label="Properties"><pre>{JSON.stringify(selectedNode.data, null, 2)}</pre></Detail></> : selectedEdge ? <><h2>{selectedEdge.type}</h2><Detail label="Endpoints"><code>{selectedEdge.source} → {selectedEdge.target}</code></Detail><Detail label="Evidence"><button className="evidence-link" onClick={() => selectedEdge.source_event_id && getJson<{ event: Event }>(`/api/events/${encodeURIComponent(selectedEdge.source_event_id)}?source=${encodeURIComponent(source)}`).then((payload) => setEventDetail(payload.event))}>{selectedEdge.source_event_id ?? "source event unavailable"}</button><br />{selectedEdge.target_event_id ?? "target event unavailable"}<br />{selectedEdge.evidence ?? "—"}</Detail><Detail label="Details"><pre>{JSON.stringify(selectedEdge.details ?? {}, null, 2)}</pre></Detail>{eventDetail && <Detail label="Raw event"><pre>{JSON.stringify(eventDetail, null, 2)}</pre></Detail>}</> : <Empty title="Select a node or edge" text="Inspect entity properties and exact relationship provenance here." />}</aside>
    </div>
    <div className="analysis-grid"><Panel title="Behavioral evidence"><div className="timeline">{(latest?.supporting_events ?? []).map((event, index) => <div className="timeline-item" key={`${event.source_event_id}-${index}`}><span className="mono">{event.timestamp_ns ?? event.timestamp ?? "—"}</span><b>{event.event_type ?? "OTHER"}</b><code>{event.source_event_id ?? "—"}</code></div>)}</div><p className="limitations">{graph.limitations.map((item) => <span key={item}>{item}</span>)}</p></Panel><Panel title="MITRE ATT&CK context"><div className="empty compact-empty"><strong>No ATT&CK mapping established for the selected evidence.</strong><span>Correlation is descriptive and does not classify observed behavior as ransomware.</span></div></Panel></div>
  </section>;
}

function IncidentInvestigation({ incidents, selected, query, setQuery, onSelect }: { incidents: Incident[]; selected: Incident | null; query: string; setQuery: (value: string) => void; onSelect: (item: Incident) => void }) {
  return <section><div className="page-heading compact"><div><p className="eyebrow">INCIDENT INVESTIGATION</p><h1>Trace a decision to evidence</h1></div><input placeholder="Search IDs, paths, process, decision…" value={query} onChange={(event) => setQuery(event.target.value)} /></div><div className="investigation-grid"><Panel title={`${incidents.length} records`}><div className="evidence-table">{incidents.map((item) => <button className={`row ${selected?.index === item.index ? "selected" : ""}`} key={item.index} onClick={() => onSelect(item)}><span>{item.event?.event_type ?? "OTHER"}</span><span>{item.event?.process ?? "—"}</span><span className="state">{item.decision?.action ?? "—"}</span><span className="mono">{item.event?.source_event_id ?? "—"}</span></button>)}</div></Panel>{selected ? <IncidentDetail item={selected} /> : <Empty title="Select an incident" text="Supporting IDs, raw payloads and correlation provenance appear here." />}</div></section>;
}

function IncidentDetail({ item }: { item: Incident }) {
  const evidence = item.evidence ?? {};
  const correlation = item.correlation;
  return <aside className="detail"><p className="eyebrow">EVIDENCE DETAIL</p><h2>{item.event?.event_type ?? "Incident"}</h2><Detail label="Triggering event"><code>{item.event?.source_event_id ?? "—"}</code><pre>{JSON.stringify(item.event ?? {}, null, 2)}</pre></Detail><Detail label="Decision">{String(item.decision?.action ?? "—")} · {String(evidence.decision_basis ?? "—")}</Detail><Detail label="Detector">{String(evidence.detector_status ?? "unknown")} · probability {item.prediction?.malicious_probability == null ? "null" : String(item.prediction.malicious_probability)}</Detail><Detail label="Schemas">{String(evidence.feature_schema_id ?? "—")}<br />{correlation ? String(correlation.schema_id ?? "—") : "No correlation evidence available"}</Detail><Detail label="Supporting events">{(correlation?.supporting_event_ids ?? item.supporting_event_ids ?? []).map((id: string) => <code key={id}>{id}</code>)}</Detail><Detail label="Limitations">{[...(evidence.limitations ?? []), ...(correlation?.limitations ?? [])].length ? [...(evidence.limitations ?? []), ...(correlation?.limitations ?? [])].map((text: string) => <span className="limitation" key={text}>{text}</span>) : "None recorded"}</Detail></aside>;
}

function EventExplorer({ events, query, setQuery }: { events: Event[]; query: string; setQuery: (value: string) => void }) {
  const filtered = events.filter((event) => JSON.stringify(event).toLowerCase().includes(query.toLowerCase()));
  return <section><div className="page-heading compact"><div><p className="eyebrow">EVENT EXPLORER</p><h1>Normalized telemetry</h1></div><input placeholder="Search event type, PID, path, source ID…" value={query} onChange={(event) => setQuery(event.target.value)} /></div><Panel title={`${filtered.length} records in current page`}><div className="evidence-table"><div className="row header"><span>Timestamp</span><span>Type</span><span>PID / PPID</span><span>Path / destination</span><span>Source ID</span></div>{filtered.map((event, index) => <div className="row" key={`${event.source_event_id}-${index}`}><span className="mono">{event.timestamp_ns ?? event.timestamp ?? "—"}</span><span>{event.event_type ?? "OTHER"}</span><span>{event.pid ?? "—"} / {event.ppid ?? "—"}</span><span>{event.path ?? event.dst_ip ?? "—"}</span><span className="mono">{event.source_event_id ?? "—"}</span></div>)}</div></Panel></section>;
}

function Detail({ label, children }: { label: string; children: ReactNode }) { return <div className="detail-block"><dt>{label}</dt><dd>{children}</dd></div>; }
function Metric({ label, value }: { label: string; value: number }) { return <div className="metric"><span>{label}</span><strong>{value.toLocaleString()}</strong></div>; }
function Panel({ title, children }: { title: string; children: ReactNode }) { return <div className="panel"><h3>{title}</h3>{children}</div>; }
function Bars({ values }: { values: Record<string, number> }) { const max = Math.max(...Object.values(values), 1); return <div className="bars">{Object.entries(values).map(([key, value]) => <div className="bar-row" key={key}><span>{key}</span><div><i style={{ width: `${(value / max) * 100}%` }} /></div><b>{value}</b></div>)}</div>; }
function Empty({ title, text }: { title: string; text: string }) { return <div className="empty"><strong>{title}</strong><span>{text}</span></div>; }

createRoot(document.getElementById("root")!).render(<App />);
