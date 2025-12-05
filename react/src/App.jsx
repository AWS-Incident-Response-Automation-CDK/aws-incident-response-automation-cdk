import { useState, useEffect } from 'react'
import { useAuth } from "react-oidc-context";
import './App.css'

// --- CONFIGURATION ---
const API_BASE_URL = 'https://staticdashboard.website/';
const ITEMS_PER_PAGE = 10;

// --- ICONS ---
const Icons = {
  Shield: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  Activity: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  ),
  Network: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="20" r="1" /><circle cx="12" cy="4" r="1" /><circle cx="6" cy="12" r="1" /><circle cx="18" cy="12" r="1" />
      <path d="M12 5v14M6 12h12" />
    </svg>
  ),
  RefreshCw: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  ),
  X: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  ),
  Eye: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
    </svg>
  ),
  ChevronLeft: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="15 18 9 12 15 6"></polyline>
    </svg>
  ),
  ChevronRight: ({ size = 24, color = "currentColor" }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6"></polyline>
    </svg>
  )
};

function App() {
  const auth = useAuth();
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const signOutRedirect = async () => {
    setIsLoggingOut(true);
    const clientId = "77p7mci6tco3fuhfh3p9mbb79n";
    const logoutUri = window.location.origin;
    const cognitoDomain = "https://ap-southeast-14boyagnkq.auth.ap-southeast-1.amazoncognito.com";
    await auth.removeUser();
    window.location.href = `${cognitoDomain}/logout?client_id=${clientId}&logout_uri=${encodeURIComponent(logoutUri)}`;
  };

  const [activeTab, setActiveTab] = useState('guardduty');
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);

  // Stats for charts
  const [stats, setStats] = useState({
    guardduty: { high: 0, medium: 0, low: 0 },
    cloudtrail: [],
    vpc: [],
    eni: []
  });

  // Define which columns appear in the main table list for cleaner UI
  const TABLE_COLUMNS = {
    guardduty: ['finding_type', 'severity', 'region', 'account_id', 'created_at', 'event_last_seen'],
    cloudtrail: ['eventtime', 'eventname', 'usertype', 'username', 'awsregion', 'sourceipaddress'],
    vpc: ['account_id', 'vpc_id', 'region', 'query_name', 'srcids_instance', 'timestamp'],
    eni: ['account_id', 'interface_id', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol', 'action']
  };

  // Modal state
  const [selectedItem, setSelectedItem] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const endpoints = {
    guardduty: '/logs/guardduty',
    cloudtrail: '/logs/cloudtrail',
    vpc: '/logs/vpc',
    eni: '/logs/eni_logs'
  };

  useEffect(() => { if (auth.isAuthenticated) fetchOverallStats(); }, [auth.isAuthenticated]);
  useEffect(() => { if (auth.isAuthenticated) fetchListData(activeTab); }, [activeTab, auth.isAuthenticated]);

  const fetchListData = async (tab) => {
    setLoading(true);
    setError(null);
    setCurrentPage(1);
    try {
      const url = `${API_BASE_URL}${endpoints[tab]}`;
      const items = await fetchAndParse(url);
      setData(items);
    } catch (err) {
      console.error("Fetch error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchOverallStats = async () => {
    try {
      const [gdData, ctData, vpcData, eniData] = await Promise.all([
        fetchAndParse(`${API_BASE_URL}${endpoints.guardduty}`),
        fetchAndParse(`${API_BASE_URL}${endpoints.cloudtrail}`),
        fetchAndParse(`${API_BASE_URL}${endpoints.vpc}`),
        fetchAndParse(`${API_BASE_URL}${endpoints.eni}`)
      ]);

      setStats({
        guardduty: processSeverity(gdData),
        cloudtrail: processDistribution(ctData, 'eventname'),
        vpc: processDistribution(vpcData, 'action'),
        eni: processDistribution(eniData, 'action')
      });
    } catch (e) {
      console.warn("Could not load stats", e);
    }
  };

  const fetchAndParse = async (url) => {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP Error! Status: ${response.status}`);
    const result = await response.json();
    return result.ResultSet ? parseAthenaResult(result.ResultSet) : (Array.isArray(result) ? result : []);
  };

  // --- NEW HELPER: Bucket Severity ---
  const processSeverity = (items) => {
    let high = 0, medium = 0, low = 0;
    items.forEach(item => {
      const sev = parseFloat(item.severity || 0);
      if (sev > 7) high++;
      else if (sev >= 4) medium++;
      else low++;
    });
    return { high, medium, low };
  };

  const processDistribution = (items, key) => {
    const counts = {};
    items.forEach(item => {
      const val = (item[key] || 'Unknown').toString().toUpperCase();
      counts[val] = (counts[val] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  };

  // Updated: Just set the data directly. No API call needed.
  const handleRowClick = (row) => {
    setSelectedItem(row);
    setIsModalOpen(true);
  };

  const parseAthenaResult = (resultSet) => {
    const rows = resultSet.Rows;
    if (!rows || rows.length < 2) return [];
    const headers = rows[0].Data.map(col => col.VarCharValue);
    return rows.slice(1).map(row => {
      let obj = {};
      row.Data.forEach((col, index) => {
        obj[headers[index]] = col.VarCharValue || "";
      });
      return obj;
    });
  };

  const indexOfLastItem = currentPage * ITEMS_PER_PAGE;
  const indexOfFirstItem = indexOfLastItem - ITEMS_PER_PAGE;
  const currentItems = data.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(data.length / ITEMS_PER_PAGE);

  const nextPage = () => { if (currentPage < totalPages) setCurrentPage(prev => prev + 1); };
  const prevPage = () => { if (currentPage > 1) setCurrentPage(prev => prev - 1); };

  // --- NEW: SUMMARY METRICS CALCULATION ---
  const getSummaryMetrics = () => {
    // 1. Get "Today's Date" string (YYYY-MM-DD) in local time
    const now = new Date();
    const todayStr = now.getFullYear() + '-' +
      String(now.getMonth() + 1).padStart(2, '0') + '-' +
      String(now.getDate()).padStart(2, '0');

    if (activeTab === 'guardduty') {
      const todaysFindings = data.filter(i => (i.date || '').startsWith(todayStr)).length;
      const highSev = data.filter(i => parseFloat(i.severity) > 7).length;
      return [
        { label: "Total Findings", value: todaysFindings, sub: todayStr },
        { label: "Critical / High", value: highSev, sub: "Requires Action" },
        { label: "Regions Affected", value: new Set(data.map(i => i.region)).size || 1, sub: "Active Regions" }
      ];
    }
    if (activeTab === 'cloudtrail') {
      const todaysEvents = data.filter(i => (i.eventtime || '').startsWith(todayStr)).length;
      return [
        { label: "Total Events", value: todaysEvents, sub: "Captured Logs" },
        { label: "Unique Users", value: new Set(data.map(i => i.username)).size, sub: "Active Identities" },
        { label: "Errors", value: data.filter(i => i.errorcode).length, sub: "Failed API Calls" }
      ];
    }
    // VPC
    return [
      { label: "Flow Logs", value: data.length, sub: "Traffic Records" },
      { label: "Rejections", value: data.filter(i => i.action === 'REJECT').length, sub: "Blocked Traffic" },
      { label: "Interfaces", value: new Set(data.map(i => i.interface_id)).size, sub: "Active ENIs" }
    ];
  };

  const renderSummaryChart = () => {
    // 1. New Design for GuardDuty
    if (activeTab === 'guardduty') {
      const { high, medium, low } = stats.guardduty;
      return (
        <div className="stat-card" style={{ height: '100%', borderLeftWidth: '4px', boxSizing: 'border-box', borderLeftColor: 'var(--danger)' }}>
          <div className="card-header">
            <h3>Threat Severity Distribution</h3>
          </div>

          {/* Colored Blocks */}
          <div className="severity-container">
            <div className="severity-box high">
              <span className="sev-count">{high}</span>
              <span className="sev-label">HIGH</span>
            </div>
            <div className="severity-box medium">
              <span className="sev-count">{medium}</span>
              <span className="sev-label">MEDIUM</span>
            </div>
            <div className="severity-box low">
              <span className="sev-count">{low}</span>
              <span className="sev-label">LOW</span>
            </div>
          </div>

          {/* Legend / Note */}
          <div className="severity-legend">
            <div className="legend-title">Note: Severity level</div>
            <div className="legend-items">
              <div className="legend-item">
                <span className="dot dot-high"></span> High: Above 7
              </div>
              <div className="legend-item">
                <span className="dot dot-med"></span> Medium: 4 → 7
              </div>
              <div className="legend-item">
                <span className="dot dot-low"></span> Low: 1 → 4
              </div>
            </div>
          </div>
        </div>
      );
    }

    // 2. Existing Bar Chart for CloudTrail / VPC
    // Determine data source based on tab
    let chartData, title, colorClass, Icon;

    if (activeTab === 'cloudtrail') {
      chartData = stats.cloudtrail;
      title = "Top User Activities";
      colorClass = "ct";
      Icon = Icons.Activity;
    } else if (activeTab === 'vpc') {
      chartData = stats.vpc;
      title = "VPC Traffic Actions";
      colorClass = "vpc";
      Icon = Icons.Network;
    } else { // ENI Tab
      chartData = stats.eni || []; // Fallback to empty array if undefined
      title = "ENI Traffic Actions";
      colorClass = "vpc"; // Reuse VPC blue style
      Icon = Icons.Network;
    }

    return (
      <div className={`stat-card ${colorClass}`} style={{ height: '100%', borderLeftWidth: '4px', boxSizing: 'border-box' }}>
        <div className="card-header">
          <h3>{title}</h3>
          <Icon size={20} />
        </div>
        <div style={{ marginTop: '1rem' }}>
          {chartData.length === 0 ? <p className="text-secondary">No data available</p> : chartData.map((bar) => (
            <div key={bar.label} className="chart-row">
              <div className="chart-label" title={bar.label}>
                {bar.label.length > 15 ? bar.label.substring(0, 12) + '..' : bar.label}
              </div>
              <div className="chart-track">
                <div className="chart-fill" style={{ width: `${Math.min((bar.count / (activeTab === 'vpc' ? 20 : 10)) * 100, 100)}%` }}></div>
              </div>
              <div className="chart-value">{bar.count}</div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const metrics = getSummaryMetrics();

  useEffect(() => {
    if (!auth.isLoading && !auth.isAuthenticated && !auth.error && !isLoggingOut) {
      auth.signinRedirect();
    }
  }, [auth.isLoading, auth.isAuthenticated, auth.error, auth, isLoggingOut]);

  if (auth.isLoading) {
    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>Loading...</div>;
  }

  if (auth.error) {
    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>Error: {auth.error.message}</div>;
  }

  if (!auth.isAuthenticated) {
    return (
      <div className="login-container" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <p>Redirecting to login...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div className="logo-section">
          <h1><Icons.Shield size={28} color="#fff" /> Security Hub</h1>
        </div>
        <div className="user-controls" style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ color: 'white', marginRight: '10px' }}>Welcome, {auth.user?.profile.email}</span>

          <button onClick={() => signOutRedirect()} style={{ padding: '5px 10px', cursor: 'pointer' }}>Global Sign Out</button>
        </div>
      </header>

      <div className="controls">
        <div className="tabs">
          <button className={`tab-btn ${activeTab === 'guardduty' ? 'active' : ''}`} onClick={() => setActiveTab('guardduty')}>
            <Icons.Shield size={18} /> GuardDuty
          </button>
          <button className={`tab-btn ${activeTab === 'cloudtrail' ? 'active' : ''}`} onClick={() => setActiveTab('cloudtrail')}>
            <Icons.Activity size={18} /> CloudTrail
          </button>
          <button className={`tab-btn ${activeTab === 'vpc' ? 'active' : ''}`} onClick={() => setActiveTab('vpc')}>
            <Icons.Network size={18} /> VPC Network
          </button>
          <button className={`tab-btn ${activeTab === 'eni' ? 'active' : ''}`} onClick={() => setActiveTab('eni')}>
            <Icons.Network size={18} /> ENI Flow Logs
          </button>
        </div>
        <button className="refresh-btn" onClick={() => fetchListData(activeTab)}>
          <Icons.RefreshCw size={18} /> Refresh
        </button>
      </div>

      <main className="content-area">

        {/* --- 1. TOP SECTION: METRICS + CHART --- */}
        <div className="summary-section">
          <div className="summary-grid">

            {/* NEW: Summary Metric Cards (Replaces Diagram) */}
            <div className="metrics-cards-container">
              {metrics.map((m, i) => (
                <div key={i} className="metric-card">
                  <h4>{m.label}</h4>
                  <div className="value">{m.value}</div>
                  <div className="sub-text">{m.sub}</div>
                </div>
              ))}
            </div>

            {/* Right: Chart */}
            <div className="metrics-card-wrapper">
              {renderSummaryChart()}
            </div>
          </div>
        </div>

        {/* --- 2. BOTTOM SECTION: LIST DATA --- */}
        <div className="list-section">
          <div className="section-title" style={{ marginTop: '0' }}>
            {activeTab === 'guardduty' ? 'Findings List' :
              activeTab === 'cloudtrail' ? 'Audit Logs' :
                activeTab === 'vpc' ? 'VPC Flow Logs' : 'ENI Flow Logs'}
          </div>

          {error && <div className="error-message"><p>{error}</p></div>}
          {loading && <div className="loading-spinner"><div className="spinner"></div></div>}

          {!loading && !error && data.length > 0 && (
            <>
              {/* KEY CHANGE: 
                   Pagination is now a SIBLING to table-wrapper, not a CHILD.
                */}
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      {/* Dynamic Headers based on Configuration */}
                      {data.length > 0 && TABLE_COLUMNS[activeTab] ?
                        TABLE_COLUMNS[activeTab].map((key) => (
                          <th key={key}>{key.replace(/_/g, ' ')}</th>
                        )) :
                        // Fallback if config missing: Show first 5 keys
                        Object.keys(data[0] || {}).slice(0, 5).map(key => <th key={key}>{key}</th>)
                      }
                    </tr>
                  </thead>
                  <tbody>
                    {currentItems.map((row, i) => (
                      <tr
                        key={i}
                        onClick={() => handleRowClick(row)}
                        className="clickable-row"
                      >
                        {/* Only render the columns defined in TABLE_COLUMNS */}
                        {TABLE_COLUMNS[activeTab] ?
                          TABLE_COLUMNS[activeTab].map((colKey, j) => (
                            <td key={j}>{row[colKey] || '-'}</td>
                          )) :
                          // Fallback
                          Object.values(row).slice(0, 5).map((val, j) => <td key={j}>{val}</td>)
                        }
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination OUTSIDE wrapper to prevent moving */}
              <div className="pagination">
                <button className="page-btn" onClick={prevPage} disabled={currentPage === 1}>
                  Previous
                </button>
                <span className="page-info">
                  Page <b>{currentPage}</b> of <b>{totalPages}</b>
                </span>
                <button className="page-btn" onClick={nextPage} disabled={currentPage === totalPages}>
                  Next
                </button>
              </div>
            </>
          )}

          {!loading && !error && data.length === 0 && (
            <div className="empty-state">No records found.</div>
          )}
        </div>
      </main>

      {/* --- DETAIL MODAL --- */}
      {isModalOpen && (
        <div className="modal-overlay" onClick={() => setIsModalOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Incident Details</h2>
              <button className="close-btn" onClick={() => setIsModalOpen(false)}>X</button>
            </div>
            <div className="modal-body">
              {detailLoading ? <p>Loading...</p> : selectedItem ? (
                <div>
                  {Object.entries(selectedItem).map(([key, value]) => (
                    <div key={key} className="detail-row">
                      <div className="detail-label">{key.replace(/_/g, ' ')}</div>
                      <div className="detail-value">{value}</div>
                    </div>
                  ))}
                </div>
              ) : <p>No details found.</p>}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App