
import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  CircleAlert,
  CloudUpload,
  FileSearch,
  Globe,
  LayoutDashboard,
  LoaderCircle,
  Network,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  Wifi,
  X,
} from "lucide-react";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

const API_URL = "http://localhost:5000/api";
const COLORS = ["#c7f36b", "#8c9a70", "#e6a15a", "#85877b", "#62645b"];

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function StatCard({ icon: Icon, label, value, detail, accent }) {
  return (
    <article className="stat-card">
      <div className={`stat-icon ${accent}`}>
        <Icon size={18} />
      </div>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      <div className="stat-detail">{detail}</div>
    </article>
  );
}

function EmptyState({ icon: Icon, title, message }) {
  return (
    <div className="empty-state">
      <Icon size={27} />
      <strong>{title}</strong>
      <span>{message}</span>
    </div>
  );
}

export default function App() {
  const fileInput = useRef(null);

  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [report, setReport] = useState(null);
  const [filename, setFilename] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [apiOnline, setApiOnline] = useState(false);
  const [activeNav, setActiveNav] = useState("Overview");
  const [hostSearch, setHostSearch] = useState("");

  async function checkApi() {
    try {
      const response = await fetch(`${API_URL}/health`);
      setApiOnline(response.ok);
    } catch {
      setApiOnline(false);
    }
  }

  useEffect(() => {
    checkApi();
  }, []);

  async function analyzeFile(selectedFile = file) {
    if (!selectedFile) {
      setError("Choose a PCAP file before starting analysis.");
      return;
    }

    const extension = selectedFile.name.split(".").pop().toLowerCase();

    if (!["pcap", "cap"].includes(extension)) {
      setError("Please select a .pcap or .cap file.");
      return;
    }

    if (selectedFile.size > 50 * 1024 * 1024) {
      setError("The selected file exceeds the 50 MB upload limit.");
      return;
    }

    setLoading(true);
    setError("");
    setReport(null);
    setFilename(selectedFile.name);

    try {
      const formData = new FormData();
      formData.append("pcap", selectedFile);

      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(
          data.details || data.error || "Analysis failed."
        );
      }

      setReport(data.report);
      setFilename(data.filename || selectedFile.name);
      setApiOnline(true);
    } catch (err) {
      setError(
        `${err.message || "Could not analyze this capture."} Check that the backend is running on port 5000.`
      );
      checkApi();
    } finally {
      setLoading(false);
    }
  }

  function chooseFile(selectedFile) {
    if (!selectedFile) return;
    setFile(selectedFile);
    setError("");

    if (fileInput.current) {
      fileInput.current.value = "";
    }
  }

  function downloadReport() {
    if (!report) return;

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    const baseName = filename.replace(/\.[^.]+$/, "");

    anchor.href = url;
    anchor.download = `${baseName || "packetlens"}-report.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function navigateTo(label, sectionId) {
    setActiveNav(label);
    document.getElementById(sectionId)?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }

  const applications = Object.entries(report?.applications || {})
    .map(([name, count]) => ({ name, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count);

  const totalApplications = applications.reduce(
    (sum, item) => sum + item.count,
    0
  );

  const protocolData = report
    ? [
        { name: "TCP", value: report.tcp_packets || 0 },
        { name: "UDP", value: report.udp_packets || 0 },
        {
          name: "Other / unclassified",
          value: Math.max(
            0,
            (report.total_packets || 0) -
              (report.tcp_packets || 0) -
              (report.udp_packets || 0)
          ),
        },
      ].filter((item) => item.value > 0)
    : [];

  const hosts = report?.detected_hosts || [];
  const dnsQueries = report?.detected_dns_queries || [];

  const filteredHosts = hosts.filter((host) => {
    const searchableText = [
      host.hostname,
      host.host,
      host.ip,
      host.application,
      host.app,
      host.status,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    return searchableText.includes(hostSearch.toLowerCase());
  });

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={22} />
          </div>
          <div>
            <div className="brand-name">
              Packet<span>Lens</span>
            </div>
            <div className="brand-subtitle">NETWORK INTELLIGENCE</div>
          </div>
        </div>

        <div className="side-label">WORKSPACE</div>

        <nav className="side-nav">
          <button
            className={`nav-item ${activeNav === "Overview" ? "selected" : ""}`}
            onClick={() => navigateTo("Overview", "overview")}
          >
            <LayoutDashboard size={17} />
            Overview
          </button>

          <button
            className={`nav-item ${activeNav === "Traffic Analysis" ? "selected" : ""}`}
            onClick={() => navigateTo("Traffic Analysis", "traffic-analysis")}
          >
            <Activity size={17} />
            Traffic Analysis
          </button>

          <button
            className={`nav-item ${activeNav === "Detected Hosts" ? "selected" : ""}`}
            onClick={() => navigateTo("Detected Hosts", "detected-hosts")}
          >
            <Globe size={17} />
            Detected Hosts
          </button>

          <button
            className={`nav-item ${activeNav === "DNS Queries" ? "selected" : ""}`}
            onClick={() => navigateTo("DNS Queries", "dns-queries")}
          >
            <Network size={17} />
            DNS Queries
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="engine-card">
            <div className="engine-heading">
              <span className={`status-dot ${apiOnline ? "" : "offline"}`} />
              ANALYZER ENGINE
            </div>

            <div className="engine-status">
              {apiOnline ? "API connected" : "API not connected"}
            </div>

            <div className="engine-caption">
              {apiOnline
                ? "Ready to inspect traffic"
                : "Start the backend on port 5000"}
            </div>

            <button className="reconnect-button" onClick={checkApi}>
              <RefreshCw size={13} />
              Check connection
            </button>
          </div>

          <div className="sidebar-footer">
            <div className="footer-avatar">PL</div>
            <div>
              <strong>PacketLens</strong>
              <span>C++17 DPI Engine</span>
            </div>
            <ShieldCheck size={17} className="footer-shield" />
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span className="crumb-separator">/</span>
            <strong>{activeNav}</strong>
          </div>

          <div className="topbar-right">
            <span className="environment-badge">
              <span className="status-dot" />
              LOCAL ENVIRONMENT
            </span>
            <div className="topbar-divider" />
            <div className="topbar-icon">
              <Wifi size={17} />
            </div>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading" id="overview">
            <div>
              <div className="eyebrow">
                <span />
                DEEP PACKET INSPECTION
              </div>
              <h1>
                Network <span>Overview</span>
              </h1>
              <p>
                Inspect traffic, identify applications, and explore detected
                hosts.
              </p>
            </div>

            <button
              className="secondary-button"
              onClick={downloadReport}
              disabled={!report}
            >
              <ArrowUpRight size={15} />
              Export report
            </button>
          </section>

          <section
            className={`upload-panel ${dragging ? "drag-active" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              chooseFile(event.dataTransfer.files[0]);
            }}
          >
            <input
              ref={fileInput}
              type="file"
              accept=".pcap,.cap"
              hidden
              onChange={(event) => chooseFile(event.target.files[0])}
            />

            <div className="upload-icon">
              <CloudUpload size={24} />
            </div>

            <div className="upload-copy">
              <strong>
                {file ? file.name : "Analyze a packet capture"}
              </strong>
              <span>
                {file
                  ? `${formatBytes(file.size)} · Ready to analyze`
                  : "Drag and drop a PCAP file here, or browse your files."}
              </span>
              <small>PCAP / CAP files · Maximum 50 MB</small>
            </div>

            <div className="upload-actions">
              <button
                className="browse-button"
                onClick={() => fileInput.current?.click()}
                disabled={loading}
              >
                Browse files
              </button>

              <button
                className="analyze-button"
                onClick={() => analyzeFile()}
                disabled={loading || !file}
              >
                {loading ? (
                  <>
                    <LoaderCircle size={15} className="spin" />
                    Analyzing
                  </>
                ) : (
                  <>
                    <FileSearch size={15} />
                    Analyze PCAP
                  </>
                )}
              </button>
            </div>
          </section>

          {error && (
            <div className="error-banner" role="alert">
              <CircleAlert size={17} />
              <span>{error}</span>
              <button
                onClick={() => setError("")}
                aria-label="Dismiss error"
              >
                <X size={16} />
              </button>
            </div>
          )}

          {report && (
            <div className="success-banner">
              <CheckCircle2 size={16} />
              Analysis complete: <strong>{filename}</strong>
            </div>
          )}

          <section className="section-header">
            <div>
              <h2>Traffic summary</h2>
              <p>
                {report
                  ? "Results from your uploaded capture"
                  : "Upload a PCAP to populate these metrics"}
              </p>
            </div>

            <span className="data-badge">
              <span className={`status-dot ${report ? "" : "offline"}`} />
              {report ? "ANALYSIS COMPLETE" : "AWAITING CAPTURE"}
            </span>
          </section>

          <section className="stats-grid">
            <StatCard
              icon={Activity}
              label="Total packets"
              value={report ? (report.total_packets || 0).toLocaleString() : "—"}
              detail="Packets in capture"
              accent="green"
            />

            <StatCard
              icon={Network}
              label="Total data"
              value={report ? formatBytes(report.total_bytes || 0) : "—"}
              detail={
                report
                  ? `${(report.total_bytes || 0).toLocaleString()} bytes`
                  : "Captured bytes"
              }
              accent="neutral"
            />

            <StatCard
              icon={Globe}
              label="Connections"
              value={report ? (report.connections || 0).toLocaleString() : "—"}
              detail="Tracked connections"
              accent="orange"
            />

            <StatCard
              icon={ShieldCheck}
              label="Forwarded"
              value={report ? (report.forwarded || 0).toLocaleString() : "—"}
              detail={
                report
                  ? `${(report.dropped || 0).toLocaleString()} dropped`
                  : "Packet decisions"
              }
              accent="green"
            />
          </section>

          <section className="charts-grid" id="traffic-analysis">
            <article className="panel traffic-panel">
              <div className="panel-heading">
                <div>
                  <h3>Protocol distribution</h3>
                  <p>Packet count by transport protocol</p>
                </div>
                <div className="panel-symbol">
                  <Activity size={16} />
                </div>
              </div>

              {report && protocolData.length > 0 ? (
                <>
                  <div className="protocol-chart">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={protocolData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={62}
                          outerRadius={88}
                          paddingAngle={3}
                          stroke="none"
                        >
                          {protocolData.map((entry, index) => (
                            <Cell
                              key={entry.name}
                              fill={COLORS[index % COLORS.length]}
                            />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: "#20211d",
                            border: "1px solid #414238",
                            borderRadius: 6,
                            color: "#eeeee5",
                            fontSize: 12,
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>

                    <div className="chart-center">
                      <strong>
                        {(report.total_packets || 0).toLocaleString()}
                      </strong>
                      <span>PACKETS</span>
                    </div>
                  </div>

                  <div className="legend-list">
                    {protocolData.map((item, index) => (
                      <div className="legend-row" key={item.name}>
                        <span className="legend-name">
                          <span
                            className="legend-dot"
                            style={{
                              background: COLORS[index % COLORS.length],
                            }}
                          />
                          {item.name}
                        </span>

                        <strong>{item.value.toLocaleString()}</strong>

                        <span className="legend-percent">
                          {report.total_packets
                            ? `${(
                                (item.value / report.total_packets) *
                                100
                              ).toFixed(1)}%`
                            : "0%"}
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <EmptyState
                  icon={Activity}
                  title="No traffic data yet"
                  message="Upload a PCAP to view protocol distribution."
                />
              )}
            </article>

            <article className="panel applications-panel">
              <div className="panel-heading">
                <div>
                  <h3>Application classification</h3>
                  <p>Application counts reported by the DPI engine</p>
                </div>
                <div className="panel-symbol">
                  <ShieldCheck size={16} />
                </div>
              </div>

              {applications.length > 0 ? (
                <div className="application-list">
                  {applications.slice(0, 8).map((item, index) => (
                    <div className="application-row" key={item.name}>
                      <div className="application-info">
                        <span
                          className="app-color"
                          style={{
                            background: COLORS[index % COLORS.length],
                          }}
                        />
                        <span title={item.name}>{item.name}</span>
                      </div>

                      <div className="application-bar-track">
                        <div
                          className="application-bar"
                          style={{
                            width: `${
                              (item.count /
                                Math.max(
                                  ...applications.map((app) => app.count),
                                  1
                                )) *
                              100
                            }%`,
                            background: COLORS[index % COLORS.length],
                          }}
                        />
                      </div>

                      <strong>{item.count}</strong>
                    </div>
                  ))}

                  <div className="application-footnote">
                    {totalApplications.toLocaleString()} classified
                    application records
                  </div>
                </div>
              ) : (
                <EmptyState
                  icon={ShieldCheck}
                  title="No applications classified"
                  message="Application classifications will appear after analysis."
                />
              )}
            </article>
          </section>

          <section className="panel hosts-panel" id="detected-hosts">
            <div className="panel-heading">
              <div>
                <h3>Detected hosts</h3>
                <p>Hostnames and applications identified in the capture</p>
              </div>
              <span className="count-badge">{hosts.length} hosts</span>
            </div>

            <div className="host-search">
              <Search size={16} />
              <input
                type="search"
                placeholder="Search hostname, IP, or application..."
                value={hostSearch}
                onChange={(event) => setHostSearch(event.target.value)}
                aria-label="Search detected hosts"
              />
              {hostSearch && (
                <button
                  onClick={() => setHostSearch("")}
                  aria-label="Clear host search"
                >
                  <X size={15} />
                </button>
              )}
            </div>

            {filteredHosts.length > 0 ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>HOSTNAME / HOST</th>
                      <th>APPLICATION</th>
                      <th>STATUS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredHosts.map((host, index) => (
                      <tr
                        key={`${host.hostname || host.host || host.ip || "host"}-${index}`}
                      >
                        <td>
                          <Globe size={14} className="table-icon" />
                          {host.hostname || host.host || host.ip || "Unknown"}
                        </td>
                        <td>
                          <span className="app-pill">
                            {host.application || host.app || "Unknown"}
                          </span>
                        </td>
                        <td>
                          <span className="detected-status">
                            <span />
                            {host.status || "Detected"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                icon={Globe}
                title={hosts.length ? "No matching hosts" : "No hosts detected"}
                message={
                  hosts.length
                    ? "Try another hostname, IP address, or application."
                    : "Detected hostnames will appear here after analysis."
                }
              />
            )}
          </section>

          <section className="panel dns-panel" id="dns-queries">
            <div className="panel-heading">
              <div>
                <h3>DNS queries</h3>
                <p>Domain names found in DNS packets</p>
              </div>
              <span className="count-badge">
                {dnsQueries.length} queries
              </span>
            </div>

            {dnsQueries.length > 0 ? (
              <div className="dns-list">
                {dnsQueries.map((item, index) => (
                  <div
                    className="dns-row"
                    key={`${item.query || "query"}-${index}`}
                  >
                    <div className="dns-icon">
                      <Network size={15} />
                    </div>
                    <div className="dns-domain">
                      <strong>{item.query || "Unknown domain"}</strong>
                      <span>DNS query</span>
                    </div>
                    <span className="app-pill">
                      {item.app || item.application || "DNS"}
                    </span>
                    <CheckCircle2 size={15} className="dns-check" />
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Network}
                title="No DNS queries found"
                message="DNS queries will appear here after analysis."
              />
            )}
          </section>

          <footer className="page-footer">
            <span>
              <span className="status-dot" />
              PacketLens · C++17 inspection engine
            </span>
            <span>
              Results reflect the uploaded capture, not live network monitoring.
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}
