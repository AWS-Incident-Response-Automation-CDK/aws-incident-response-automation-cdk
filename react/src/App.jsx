import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useAuth } from "react-oidc-context";
import './App.css'

// --- CONFIGURATION CONSTANTS ---
const ITEMS_PER_PAGE = 10;

const SEVERITY_THRESHOLDS = {
  HIGH: 7,
  MEDIUM: 4,
  LOW: 1
};

const ENDPOINTS = {
  guardduty: '/logs/guardduty',
  cloudtrail: '/logs/cloudtrail',
  vpc: '/logs/vpc',
  eni: '/logs/eni_logs'
};

const TABLE_COLUMNS = {
  guardduty: ['finding_type', 'severity', 'region', 'account_id', 'created_at', 'event_last_seen'],
  cloudtrail: ['eventtime', 'eventname', 'usertype', 'username', 'awsregion', 'sourceipaddress', 'isconsolelogin', 'isrootuser', 'isassumedrole', 'ishighriskevent', 'isprivilegedaction', 'isdataaccess'],
  vpc: ['account_id', 'vpc_id', 'region', 'query_name', 'srcids_instance', 'timestamp'],
  eni: ['account_id', 'interface_id', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol', 'action', 'timestamp_str']
};

const DATE_COLUMNS = ['eventtime', 'timestamp', 'created_at', 'event_last_seen', 'timestamp_str'];

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

// --- UTILITY FUNCTIONS ---
const parseAthenaResult = (resultSet) => {
  const rows = resultSet.Rows;
  if (!rows || rows.length < 2) return [];
  const headers = rows[0].Data.map(col => col.VarCharValue);
  
  return rows.slice(1).map(row => {
    const obj = {};
    row.Data.forEach((col, index) => {
      const header = headers[index];
      let value = col.VarCharValue || "";
      
      // OPTIMIZATION: Pre-parse date columns to timestamps for faster sorting
      if (DATE_COLUMNS.includes(header) && value) {
        const timestamp = new Date(value).getTime();
        if (!isNaN(timestamp)) {
          obj[`__${header}_timestamp`] = timestamp; // Store parsed timestamp
        }
      }
      
      obj[header] = value;
    });
    return obj;
  });
};

const processSeverity = (items) => {
  let high = 0, medium = 0, low = 0;
  items.forEach(item => {
    const sev = parseFloat(item.severity || 0);
    if (sev > SEVERITY_THRESHOLDS.HIGH) high++;
    else if (sev >= SEVERITY_THRESHOLDS.MEDIUM) medium++;
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

const getTodayString = () => {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
};

function App({ config }) {
  const base = config ? config.apiBaseUrl : '';
  const auth = useAuth();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const dataCacheRef = useRef({});

  // Data State
  const [activeTab, setActiveTab] = useState('guardduty');
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filter and Sort State
  const [selectedFilter, setSelectedFilter] = useState({});
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);

  // Stats for charts
  const [stats, setStats] = useState({
    guardduty: { high: 0, medium: 0, low: 0 },
    cloudtrail: [],
    vpc: [],
    eni: []
  });

  // Modal state
  const [selectedItem, setSelectedItem] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // --- MEMOIZED FETCH FUNCTION ---
  const fetchAndParse = useCallback(async (url) => {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP Error! Status: ${response.status}`);
    const result = await response.json();
    return result.ResultSet ? parseAthenaResult(result.ResultSet) : (Array.isArray(result) ? result : []);
  }, []);

  // --- FETCH LIST DATA ---
  const fetchListData = useCallback(async (tab) => {

    if (dataCacheRef.current[tab]) {
      setData(dataCacheRef.current[tab]);
      setCurrentPage(1);
      return;
    }

    setLoading(true);
    setError(null);
    setCurrentPage(1);

    try {
      const url = `${base}${ENDPOINTS[tab]}`;
      const items = await fetchAndParse(url);
      dataCacheRef.current[tab] = items;
      setData(items);
    } catch (err) {
      console.error("Fetch error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [base, fetchAndParse]);

  // --- FETCH OVERALL STATS ---
  const fetchOverallStats = useCallback(async () => {
    try {
      const [gdData, ctData, vpcData, eniData] = await Promise.all([
        fetchAndParse(`${base}${ENDPOINTS.guardduty}`),
        fetchAndParse(`${base}${ENDPOINTS.cloudtrail}`),
        fetchAndParse(`${base}${ENDPOINTS.vpc}`),
        fetchAndParse(`${base}${ENDPOINTS.eni}`)
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
  }, [base, fetchAndParse]);

  // --- SIGN OUT ---
  const signOutRedirect = useCallback(async () => {
    setIsLoggingOut(true);
    if (!config) return;
    dataCacheRef.current = {};
    const clientId = config.cognito.clientId;
    const logoutUri = window.location.origin;
    const cognitoDomain = `https://${config.cognito.domain}`;
    await auth.removeUser();
    window.location.href = `${cognitoDomain}/logout?client_id=${clientId}&logout_uri=${encodeURIComponent(logoutUri)}`;
  }, [auth, config]);

  // --- TAB CHANGE HANDLER ---
  const handleTabChange = useCallback((tab) => {
    setData([]);
    setCurrentPage(1);
    setSelectedFilter({});
    setSortConfig({ key: null, direction: 'asc' });
    setActiveTab(tab);
  }, []);

  // --- EFFECTS ---
  useEffect(() => {
    if (auth.isAuthenticated) {
      fetchOverallStats();
    }
  }, [auth.isAuthenticated, fetchOverallStats]);

  useEffect(() => {
    if (auth.isAuthenticated) {
      fetchListData(activeTab);
    }
  }, [activeTab, auth.isAuthenticated, fetchListData]);

  useEffect(() => {
    if (!auth.isLoading && !auth.isAuthenticated && !auth.error && !isLoggingOut) {
      auth.signinRedirect();
    }
  }, [auth, isLoggingOut]);

  // Reset to page 1 on filter change
  useEffect(() => {
    setCurrentPage(1);
  }, [selectedFilter]);

  // --- OPTIMIZED: Calculate filter options alongside data processing ---
  const dataWithFilterOptions = useMemo(() => {
    if (!data.length) return { data, filterOptions: {} };
    
    const activeCols = TABLE_COLUMNS[activeTab];
    const uniqueValuesPerCol = {};

    // Initialize sets for each column
    activeCols.forEach(col => {
      uniqueValuesPerCol[col] = new Set();
    });

    // Single pass through data to collect unique values
    data.forEach(item => {
      activeCols.forEach(col => {
        const isDate = DATE_COLUMNS.includes(col);
        let val = item[col] || '';
        
        if (isDate && val.includes('T')) {
          val = val.split('T')[0]; // Extract date part only
        }
        
        if (val) {
          uniqueValuesPerCol[col].add(val);
        }
      });
    });

    // Convert Sets to sorted arrays
    const filterOptions = {};
    Object.entries(uniqueValuesPerCol).forEach(([col, valueSet]) => {
      filterOptions[col] = Array.from(valueSet).sort();
    });

    return { data, filterOptions };
  }, [data, activeTab]);

  // --- OPTIMIZED: Filter & Sort with pre-parsed timestamps ---
  const filteredAndSortedData = useMemo(() => {
    const { data: dataItems } = dataWithFilterOptions;
    
    // First, filter the data
    const filtered = dataItems.filter(item => {
      return Object.entries(selectedFilter).every(([key, value]) => {
        if (!value) return true;
        let rowValue = String(item[key] || '');

        if (DATE_COLUMNS.includes(key) && rowValue.includes('T')) {
          rowValue = rowValue.split('T')[0];
        }
        return rowValue === value;
      });
    });

    // Then, sort the filtered data
    if (!sortConfig.key) return filtered;

    return [...filtered].sort((a, b) => {
      const key = sortConfig.key;
      
      // OPTIMIZATION: Use pre-parsed timestamps for date columns
      if (DATE_COLUMNS.includes(key)) {
        const timestampKey = `__${key}_timestamp`;
        const dateA = a[timestampKey];
        const dateB = b[timestampKey];
        
        // Handle items without parsed timestamps (fallback)
        if (dateA === undefined && dateB === undefined) return 0;
        if (dateA === undefined) return 1;
        if (dateB === undefined) return -1;
        
        return sortConfig.direction === 'asc' ? dateA - dateB : dateB - dateA;
      }

      let valA = a[key] || '';
      let valB = b[key] || '';

      const numA = parseFloat(valA);
      const numB = parseFloat(valB);
      const isPureNumber = !isNaN(numA) && !isNaN(numB) && 
                          String(valA).trim() === String(numA) && 
                          String(valB).trim() === String(numB);

      if (isPureNumber) {
        return sortConfig.direction === 'asc' ? numA - numB : numB - numA;
      }

      valA = String(valA).toUpperCase();
      valB = String(valB).toUpperCase();

      if (valA < valB) return sortConfig.direction === 'asc' ? -1 : 1;
      if (valA > valB) return sortConfig.direction === 'asc' ? 1 : -1;
      return 0;
    });
  }, [dataWithFilterOptions, selectedFilter, sortConfig]);

  // --- MEMOIZED PAGINATION DATA ---
  const paginationData = useMemo(() => {
    const indexOfLastItem = currentPage * ITEMS_PER_PAGE;
    const indexOfFirstItem = indexOfLastItem - ITEMS_PER_PAGE;
    const currentItems = filteredAndSortedData.slice(indexOfFirstItem, indexOfLastItem);
    const totalPages = Math.ceil(filteredAndSortedData.length / ITEMS_PER_PAGE);
    return { currentItems, totalPages };
  }, [filteredAndSortedData, currentPage]);

  // --- MEMOIZED SUMMARY METRICS ---
  const summaryMetrics = useMemo(() => {
    const todayStr = getTodayString();

    if (activeTab === 'guardduty') {
      const todaysFindings = data.filter(i => (i.date || '').startsWith(todayStr)).length;
      const highSev = data.filter(i => parseFloat(i.severity) > SEVERITY_THRESHOLDS.HIGH).length;
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
    return [
      { label: "Flow Logs", value: data.length, sub: "Traffic Records" },
      { label: "Rejections", value: data.filter(i => i.action === 'REJECT').length, sub: "Blocked Traffic" },
      { label: "Interfaces", value: new Set(data.map(i => i.interface_id)).size, sub: "Active ENIs" }
    ];
  }, [data, activeTab]);

  // --- MEMOIZED CHART DATA ---
  const chartData = useMemo(() => {
    if (activeTab === 'guardduty') {
      return { type: 'severity', data: stats.guardduty };
    }
    
    let chartStats, title, colorClass, Icon;
    if (activeTab === 'cloudtrail') {
      chartStats = stats.cloudtrail;
      title = "Top User Activities";
      colorClass = "ct";
      Icon = Icons.Activity;
    } else if (activeTab === 'vpc') {
      chartStats = stats.vpc;
      title = "VPC Traffic Actions";
      colorClass = "vpc";
      Icon = Icons.Network;
    } else {
      chartStats = stats.eni || [];
      title = "ENI Traffic Actions";
      colorClass = "vpc";
      Icon = Icons.Network;
    }
    
    return { type: 'distribution', data: chartStats, title, colorClass, Icon };
  }, [activeTab, stats]);

  // --- EVENT HANDLERS ---
  const handleRowClick = useCallback((row) => {
    setSelectedItem(row);
    setIsModalOpen(true);
  }, []);

  const closeModal = useCallback(() => {
    setIsModalOpen(false);
  }, []);

  const nextPage = useCallback(() => {
    if (currentPage < paginationData.totalPages) {
      setCurrentPage(prev => prev + 1);
    }
  }, [currentPage, paginationData.totalPages]);

  const prevPage = useCallback(() => {
    if (currentPage > 1) {
      setCurrentPage(prev => prev - 1);
    }
  }, [currentPage]);

  const handleRefresh = useCallback(() => {
    dataCacheRef.current[activeTab] = null;
    fetchListData(activeTab);
  }, [activeTab, fetchListData]);

  const handleFilterChange = useCallback((colName, value) => {
    setSelectedFilter(prev => ({
      ...prev,
      [colName]: value
    }));
  }, []);

  const clearFilters = useCallback(() => {
    setSelectedFilter({});
  }, []);

  const sortHandler = useCallback((key) => {
    setSortConfig(prev => {
      let direction = 'asc';
      if (prev.key === key && prev.direction === 'asc') {
        direction = 'desc';
      }
      return { key, direction };
    });
  }, []);

  const getDetailTitle = useCallback(() => {
    if (activeTab === 'guardduty') return 'Finding Details';
    if (activeTab === 'cloudtrail') return 'Event Details';
    if (activeTab === 'vpc') return 'VPC Flow Log Details';
    return 'ENI Flow Log Details';
  }, [activeTab]);

  const getSectionTitle = useCallback(() => {
    switch (activeTab) {
      case 'guardduty': return 'Findings List';
      case 'cloudtrail': return 'Audit Logs';
      case 'vpc': return 'VPC Flow Logs';
      case 'eni': return 'ENI Flow Logs';
      default: return 'Logs';
    }
  }, [activeTab]);

  // --- RENDER HELPERS ---
  const renderSummaryChart = () => {
    if (chartData.type === 'severity') {
      const { high, medium, low } = chartData.data;
      return (
        <div className="stat-card" style={{ height: '100%', borderLeftWidth: '4px', boxSizing: 'border-box', borderLeftColor: 'var(--danger)' }}>
          <div className="card-header">
            <h3>Threat Severity Distribution</h3>
          </div>
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
          <div className="severity-legend">
            <div className="legend-title">Note: Severity level</div>
            <div className="legend-items">
              <div className="legend-item">
                <span className="dot dot-high"></span> High: Above {SEVERITY_THRESHOLDS.HIGH}
              </div>
              <div className="legend-item">
                <span className="dot dot-med"></span> Medium: {SEVERITY_THRESHOLDS.MEDIUM} → {SEVERITY_THRESHOLDS.HIGH}
              </div>
              <div className="legend-item">
                <span className="dot dot-low"></span> Low: {SEVERITY_THRESHOLDS.LOW} → {SEVERITY_THRESHOLDS.MEDIUM}
              </div>
            </div>
          </div>
        </div>
      );
    }

    const { data: distributionData, title, colorClass, Icon } = chartData;
    return (
      <div className={`stat-card ${colorClass}`} style={{ height: '100%', borderLeftWidth: '4px', boxSizing: 'border-box' }}>
        <div className="card-header">
          <h3>{title}</h3>
          <Icon size={20} />
        </div>
        <div style={{ marginTop: '1rem' }}>
          {distributionData.length === 0 ? (
            <p className="text-secondary">No data available</p>
          ) : (
            distributionData.map((bar) => (
              <div key={bar.label} className="chart-row">
                <div className="chart-label" title={bar.label}>
                  {bar.label.length > 15 ? bar.label.substring(0, 12) + '..' : bar.label}
                </div>
                <div className="chart-track">
                  <div className="chart-fill" style={{ width: `${Math.min((bar.count / (activeTab === 'vpc' ? 20 : 10)) * 100, 100)}%` }}></div>
                </div>
                <div className="chart-value">{bar.count}</div>
              </div>
            ))
          )}
        </div>
      </div>
    );
  };

  const renderFilters = () => {
    const { filterOptions } = dataWithFilterOptions;
    if (!data.length) return null;
    
    return (
      <div className="filters-container">
        {Object.entries(filterOptions).map(([colName, values]) => (
          <div key={colName} className="filter-group">
            <label>{colName.replace(/_/g, ' ')}</label>
            <select name={colName} value={selectedFilter[colName] || ''} onChange={(e) => handleFilterChange(colName, e.target.value)}>
              <option value="">All</option>
              {values.map((optionValue, optionIdx) => (
                <option key={optionIdx} value={optionValue}>{optionValue}</option>
              ))}
            </select>
          </div>
        ))}
      </div>
    );
  };

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
          <h1><Icons.Shield size={28} color="#fff" /> Dashboard Hub</h1>
        </div>
        <div className="user-controls" style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ color: 'white', marginRight: '10px' }}>Welcome, {auth.user?.profile.email}</span>
          <button onClick={signOutRedirect} style={{ padding: '5px 10px', cursor: 'pointer' }}>Global Sign Out</button>
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
        <button className="refresh-btn" onClick={handleRefresh}>
          <Icons.RefreshCw size={18} /> Refresh
        </button>
      </div>

      <main className="content-area">
        <div className="summary-section">
          <div className="summary-grid">
            <div className="metrics-cards-container">
              {summaryMetrics.map((m, i) => (
                <div key={i} className="metric-card">
                  <h4>{m.label}</h4>
                  <div className="value">
                    {m.value}
                    {m.value > 998 ? '+' : ''}
                  </div>
                  <div className="sub-text">{m.sub}</div>
                </div>
              ))}
            </div>
            <div className="metrics-card-wrapper">
              {renderSummaryChart()}
            </div>
          </div>
        </div>

        <div className="list-section">
          <div className="section-title" style={{ marginTop: '0' }}>
            {getSectionTitle()}
          </div>

          <div className='filter-section'>
            {renderFilters()}
            <button className='clearbtn' onClick={clearFilters}>CLEAR</button>
          </div>

          {error && <div className="error-message"><p>{error}</p></div>}
          {loading && <div className="loading-spinner"><div className="spinner"></div></div>}

          {!loading && !error && data.length > 0 && (
            <>
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      {TABLE_COLUMNS[activeTab]?.map((key) => (
                        <th key={key} onClick={() => sortHandler(key)} style={{ cursor: 'pointer', userSelect: 'none' }}>
                          <span className="th-content">
                            {key.replace(/_/g, ' ')}

                            {sortConfig.key === key ? (
                              <span style={{ marginLeft: '5px' }}>{sortConfig.direction === 'asc' ? ' ▲' : ' ▼'}</span>
                            ) : (
                              <span style={{ marginLeft: '5px', opacity: 0.3 }}> ▼</span>
                            )}
                          </span>
                        </th>
                      )) || Object.keys(data[0] || {}).slice(0, 5).map(key => <th key={key}>{key}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {paginationData.currentItems.map((row, i) => (
                      <tr key={i} onClick={() => handleRowClick(row)} className="clickable-row">
                        {TABLE_COLUMNS[activeTab]?.map((colKey, j) => (
                          <td key={j}>{row[colKey] || '-'}</td>
                        )) || Object.values(row).slice(0, 5).map((val, j) => <td key={j}>{val}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="pagination">
                <button className="page-btn" onClick={prevPage} disabled={currentPage === 1}>
                  Previous
                </button>
                <span className="page-info">
                  Page <b>{currentPage}</b> of <b>{paginationData.totalPages}</b>
                </span>
                <button className="page-btn" onClick={nextPage} disabled={currentPage === paginationData.totalPages}>
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

      {isModalOpen && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{getDetailTitle()}</h2>
              <button className="close-btn" onClick={closeModal}>X</button>
            </div>
            <div className="modal-body">
              {selectedItem ? (
                <div>
                  {Object.entries(selectedItem)
                  .filter(([key]) => !key.startsWith('__'))
                  .map(([key, value]) => (
                    <div key={key} className="detail-row">
                      <div className="detail-label">{key.replace(/_/g, ' ')}</div>
                      <div className="detail-value">
                        {typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value)}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p>No details found.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;