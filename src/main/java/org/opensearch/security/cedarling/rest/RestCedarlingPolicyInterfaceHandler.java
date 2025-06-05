package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.common.bytes.BytesArray;
import org.opensearch.common.xcontent.XContentType;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Arrays;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * REST handler for serving the responsive mobile-friendly policy management interface
 * Serves HTML, CSS, and JavaScript directly from the OpenSearch plugin
 */
public class RestCedarlingPolicyInterfaceHandler extends BaseRestHandler {
    
    @Override
    public String getName() {
        return "cedarling_policy_interface_handler";
    }

    @Override
    public List<Route> routes() {
        return Arrays.asList(
            new Route(GET, "/_plugins/_cedarling/interface"),
            new Route(GET, "/_plugins/_cedarling/interface/"),
            new Route(GET, "/_plugins/_cedarling/interface/{resource}")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String path = request.path();
        
        return channel -> {
            try {
                if (path.equals("/_plugins/_cedarling/interface") || path.equals("/_plugins/_cedarling/interface/")) {
                    // Serve main interface HTML
                    serveMainInterface(channel);
                } else if (path.contains("/interface/css/")) {
                    // Serve CSS files
                    String cssFile = extractResourceName(path, "css");
                    serveCssFile(channel, cssFile);
                } else if (path.contains("/interface/js/")) {
                    // Serve JavaScript files
                    String jsFile = extractResourceName(path, "js");
                    serveJsFile(channel, jsFile);
                } else {
                    // Serve 404 for unknown resources
                    channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, "Resource not found"));
                }
            } catch (Exception e) {
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                    "Error serving interface: " + e.getMessage()));
            }
        };
    }
    
    private void serveMainInterface(RestChannel channel) throws IOException {
        String html = generateMainInterfaceHtml();
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "text/html; charset=utf-8",
            new BytesArray(html.getBytes(StandardCharsets.UTF_8))
        );
        
        // Add cache headers
        response.addHeader("Cache-Control", "no-cache");
        channel.sendResponse(response);
    }
    
    private void serveCssFile(RestChannel channel, String filename) throws IOException {
        String css = getCedarlingAdminCss();
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "text/css; charset=utf-8",
            new BytesArray(css.getBytes(StandardCharsets.UTF_8))
        );
        
        // Add cache headers for CSS
        response.addHeader("Cache-Control", "public, max-age=3600");
        channel.sendResponse(response);
    }
    
    private void serveJsFile(RestChannel channel, String filename) throws IOException {
        String js = getCedarlingAdminJs();
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/javascript; charset=utf-8",
            new BytesArray(js.getBytes(StandardCharsets.UTF_8))
        );
        
        // Add cache headers for JavaScript
        response.addHeader("Cache-Control", "public, max-age=3600");
        channel.sendResponse(response);
    }
    
    private String extractResourceName(String path, String type) {
        // Extract filename from path like /_plugins/_cedarling/interface/css/cedarling-admin.css
        String[] parts = path.split("/");
        return parts[parts.length - 1];
    }
    
    private String generateMainInterfaceHtml() {
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Cedarling Policy Management - OpenSearch Security Plugin</title>
            <link rel="stylesheet" href="/_plugins/_cedarling/interface/css/cedarling-admin.css">
        </head>
        <body>
            <!-- Header -->
            <header class="header">
                <div class="container">
                    <div class="header-content">
                        <div class="logo">
                            <div class="logo-icon">C</div>
                            <div class="logo-text">Cedarling Policy Manager</div>
                        </div>
                        <div class="status-indicator">
                            <div class="status-dot"></div>
                            <span class="status-text">HEALTHY</span>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Main Content -->
            <main class="container">
                <!-- Navigation Tabs -->
                <nav class="nav-tabs">
                    <button class="tab-button active" data-tab="dashboard">Dashboard</button>
                    <button class="tab-button" data-tab="policies">Policies</button>
                    <button class="tab-button" data-tab="monitoring">Monitoring</button>
                    <button class="tab-button" data-tab="logs">Audit Logs</button>
                </nav>

                <!-- Dashboard Tab -->
                <div id="dashboard-tab" class="tab-content">
                    <!-- Key Metrics -->
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value" data-metric="policy-version">v1.2.3</div>
                            <div class="metric-label">Policy Version</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value" data-metric="policies-count">45</div>
                            <div class="metric-label">Active Policies</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value" data-metric="health-status">HEALTHY</div>
                            <div class="metric-label">System Health</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value" data-metric="sync-strategy">SMART_SYNC</div>
                            <div class="metric-label">Sync Strategy</div>
                        </div>
                    </div>

                    <!-- System Overview -->
                    <div class="card">
                        <div class="card-header">
                            <div>
                                <h2 class="card-title">System Overview</h2>
                                <div class="card-subtitle">Current plugin status and configuration</div>
                            </div>
                            <button class="btn btn-primary btn-force-sync">Force Sync</button>
                        </div>
                        
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Component</th>
                                        <th>Status</th>
                                        <th>Details</th>
                                        <th>Last Updated</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td data-label="Component">Embedded Engine</td>
                                        <td data-label="Status"><span class="badge badge-success">Active</span></td>
                                        <td data-label="Details">jans-cedarling Java bindings</td>
                                        <td data-label="Last Updated" data-metric="last-sync">2 minutes ago</td>
                                    </tr>
                                    <tr>
                                        <td data-label="Component">Policy Store</td>
                                        <td data-label="Status"><span class="badge badge-success">Synchronized</span></td>
                                        <td data-label="Details">SMART_SYNC active</td>
                                        <td data-label="Last Updated">1 minute ago</td>
                                    </tr>
                                    <tr>
                                        <td data-label="Component">Conflict Resolution</td>
                                        <td data-label="Status"><span class="badge badge-success">Ready</span></td>
                                        <td data-label="Details">TIMESTAMP_BASED strategy</td>
                                        <td data-label="Last Updated">5 minutes ago</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Policies Tab -->
                <div id="policies-tab" class="tab-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">
                            <div>
                                <h2 class="card-title">Policy Management</h2>
                                <div class="card-subtitle">Manage Cedar authorization policies</div>
                            </div>
                            <button class="btn btn-primary btn-add-policy">Add Policy</button>
                        </div>
                        
                        <div class="table-responsive">
                            <table id="policies-table" class="table">
                                <thead>
                                    <tr>
                                        <th>Policy Name</th>
                                        <th>ID</th>
                                        <th>Effect</th>
                                        <th>Status</th>
                                        <th>Last Modified</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Dynamic content loaded by JavaScript -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Monitoring Tab -->
                <div id="monitoring-tab" class="tab-content" style="display: none;">
                    <!-- Cluster Status -->
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value" data-cluster="cluster-nodes">3</div>
                            <div class="metric-label">Total Nodes</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value" data-cluster="cluster-sync-nodes">3</div>
                            <div class="metric-label">Synchronized</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value" data-cluster="cluster-health">100%</div>
                            <div class="metric-label">Cluster Health</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value" data-cluster="cluster-leader">node-1</div>
                            <div class="metric-label">Leader Node</div>
                        </div>
                    </div>

                    <!-- Performance Metrics -->
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Performance Metrics</h2>
                            <div class="card-subtitle">Real-time system performance data</div>
                        </div>
                        
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Metric</th>
                                        <th>Current Value</th>
                                        <th>Target</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td data-label="Metric">Authorization Latency</td>
                                        <td data-label="Current Value">&lt;1ms</td>
                                        <td data-label="Target">&lt;5ms</td>
                                        <td data-label="Status"><span class="badge badge-success">Optimal</span></td>
                                    </tr>
                                    <tr>
                                        <td data-label="Metric">Memory Usage</td>
                                        <td data-label="Current Value">45MB</td>
                                        <td data-label="Target">&lt;100MB</td>
                                        <td data-label="Status"><span class="badge badge-success">Normal</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Audit Logs Tab -->
                <div id="logs-tab" class="tab-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">
                            <div>
                                <h2 class="card-title">Audit Logs</h2>
                                <div class="card-subtitle">Authorization decisions and system events</div>
                            </div>
                        </div>
                        
                        <div class="table-responsive">
                            <table id="audit-logs" class="table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Event Type</th>
                                        <th>Principal</th>
                                        <th>Decision</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Dynamic content loaded by JavaScript -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>

            <script src="/_plugins/_cedarling/interface/js/cedarling-admin.js"></script>
        </body>
        </html>
        """;
    }
    
    private String getCedarlingAdminCss() {
        // Embedded CSS content - responsive mobile-friendly styles
        return """
        :root {
          --primary-color: #005ea8;
          --secondary-color: #00b8d9;
          --success-color: #00875a;
          --warning-color: #ffab00;
          --error-color: #de350b;
          --text-primary: #172b4d;
          --text-secondary: #6b778c;
          --background-light: #f7f8f9;
          --background-white: #ffffff;
          --border-color: #dfe1e6;
          --shadow-light: 0 1px 3px rgba(0, 0, 0, 0.1);
          --border-radius: 8px;
          --spacing-xs: 4px;
          --spacing-sm: 8px;
          --spacing-md: 16px;
          --spacing-lg: 24px;
        }

        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }

        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-size: 14px;
          line-height: 1.5;
          color: var(--text-primary);
          background-color: var(--background-light);
        }

        .container {
          max-width: 1200px;
          margin: 0 auto;
          padding: var(--spacing-md);
        }

        .header {
          background: var(--background-white);
          border-bottom: 1px solid var(--border-color);
          padding: var(--spacing-md) 0;
          margin-bottom: var(--spacing-lg);
          box-shadow: var(--shadow-light);
        }

        .header-content {
          display: flex;
          justify-content: space-between;
          align-items: center;
          flex-wrap: wrap;
          gap: var(--spacing-md);
        }

        .logo {
          display: flex;
          align-items: center;
          gap: var(--spacing-sm);
        }

        .logo-icon {
          width: 32px;
          height: 32px;
          background: var(--primary-color);
          border-radius: var(--border-radius);
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: bold;
          font-size: 16px;
        }

        .logo-text {
          font-size: 18px;
          font-weight: 600;
          color: var(--text-primary);
        }

        .status-indicator {
          display: flex;
          align-items: center;
          gap: var(--spacing-sm);
          padding: var(--spacing-sm) var(--spacing-md);
          background: var(--success-color);
          color: white;
          border-radius: var(--border-radius);
          font-size: 12px;
          font-weight: 500;
        }

        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: white;
        }

        .nav-tabs {
          display: flex;
          background: var(--background-white);
          border-radius: var(--border-radius);
          padding: var(--spacing-xs);
          margin-bottom: var(--spacing-lg);
          box-shadow: var(--shadow-light);
          overflow-x: auto;
        }

        .tab-button {
          flex: 1;
          min-width: 120px;
          padding: var(--spacing-sm) var(--spacing-md);
          border: none;
          background: transparent;
          color: var(--text-secondary);
          font-size: 14px;
          font-weight: 500;
          border-radius: calc(var(--border-radius) - 2px);
          cursor: pointer;
          transition: all 0.2s ease;
          white-space: nowrap;
        }

        .tab-button:hover {
          background: var(--background-light);
          color: var(--text-primary);
        }

        .tab-button.active {
          background: var(--primary-color);
          color: white;
        }

        .card {
          background: var(--background-white);
          border-radius: var(--border-radius);
          padding: var(--spacing-lg);
          margin-bottom: var(--spacing-lg);
          box-shadow: var(--shadow-light);
          border: 1px solid var(--border-color);
        }

        .card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: var(--spacing-md);
          flex-wrap: wrap;
          gap: var(--spacing-sm);
        }

        .card-title {
          font-size: 16px;
          font-weight: 600;
          color: var(--text-primary);
        }

        .card-subtitle {
          font-size: 12px;
          color: var(--text-secondary);
          margin-top: var(--spacing-xs);
        }

        .btn {
          display: inline-flex;
          align-items: center;
          gap: var(--spacing-sm);
          padding: var(--spacing-sm) var(--spacing-md);
          border: none;
          border-radius: var(--border-radius);
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s ease;
          text-decoration: none;
          white-space: nowrap;
        }

        .btn-primary {
          background: var(--primary-color);
          color: white;
        }

        .btn-primary:hover {
          background: #004a87;
        }

        .metrics-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: var(--spacing-md);
          margin-bottom: var(--spacing-lg);
        }

        .metric-card {
          background: var(--background-white);
          padding: var(--spacing-md);
          border-radius: var(--border-radius);
          border: 1px solid var(--border-color);
          text-align: center;
        }

        .metric-value {
          font-size: 24px;
          font-weight: 700;
          color: var(--primary-color);
          margin-bottom: var(--spacing-xs);
        }

        .metric-label {
          font-size: 12px;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .table-responsive {
          overflow-x: auto;
          margin-bottom: var(--spacing-lg);
        }

        .table {
          width: 100%;
          border-collapse: collapse;
          background: var(--background-white);
          border-radius: var(--border-radius);
          overflow: hidden;
          box-shadow: var(--shadow-light);
        }

        .table th,
        .table td {
          padding: var(--spacing-sm) var(--spacing-md);
          text-align: left;
          border-bottom: 1px solid var(--border-color);
        }

        .table th {
          background: var(--background-light);
          font-weight: 600;
          color: var(--text-primary);
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .table tr:hover {
          background: #f8f9fa;
        }

        .badge {
          display: inline-flex;
          align-items: center;
          gap: var(--spacing-xs);
          padding: var(--spacing-xs) var(--spacing-sm);
          border-radius: 12px;
          font-size: 11px;
          font-weight: 500;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .badge-success {
          background: rgba(0, 135, 90, 0.1);
          color: var(--success-color);
        }

        /* Mobile Responsive */
        @media (max-width: 768px) {
          .container {
            padding: var(--spacing-sm);
          }
          
          .header-content {
            flex-direction: column;
            align-items: flex-start;
          }
          
          .card {
            padding: var(--spacing-md);
          }
          
          .card-header {
            flex-direction: column;
            align-items: flex-start;
          }
          
          .table th,
          .table td {
            padding: var(--spacing-sm);
            font-size: 12px;
          }
          
          .metrics-grid {
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: var(--spacing-sm);
          }
        }

        @media (max-width: 480px) {
          .tab-button {
            min-width: 80px;
            padding: var(--spacing-sm);
            font-size: 12px;
          }
          
          .metrics-grid {
            grid-template-columns: 1fr 1fr;
          }
        }
        """;
    }
    
    private String getCedarlingAdminJs() {
        // Embedded JavaScript content - responsive mobile interface functionality
        return """
        class CedarlingAdmin {
          constructor() {
            this.apiBase = window.location.origin;
            this.currentTab = 'dashboard';
            this.init();
          }

          init() {
            this.setupEventListeners();
            this.loadInitialData();
            this.setupMobileOptimizations();
          }

          setupEventListeners() {
            document.querySelectorAll('.tab-button').forEach(button => {
              button.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
              });
            });

            document.addEventListener('click', (e) => {
              if (e.target.matches('.btn-force-sync')) {
                this.forceSync();
              }
            });
          }

          setupMobileOptimizations() {
            const navTabs = document.querySelector('.nav-tabs');
            if (navTabs && 'ontouchstart' in window) {
              let startX = 0;
              let scrollLeft = 0;

              navTabs.addEventListener('touchstart', (e) => {
                startX = e.touches[0].pageX - navTabs.offsetLeft;
                scrollLeft = navTabs.scrollLeft;
              });

              navTabs.addEventListener('touchmove', (e) => {
                const x = e.touches[0].pageX - navTabs.offsetLeft;
                const walk = (x - startX) * 2;
                navTabs.scrollLeft = scrollLeft - walk;
              });
            }
          }

          async loadInitialData() {
            try {
              await this.loadDashboardData();
            } catch (error) {
              console.error('Failed to load initial data:', error);
            }
          }

          async loadDashboardData() {
            try {
              const response = await fetch(this.apiBase + '/_plugins/_cedarling/sync/status');
              const data = await response.json();
              
              this.updateMetrics({
                policyVersion: data.current_version,
                policiesCount: data.sync_metrics?.policies_count || 0,
                healthStatus: data.health_status?.overall_health || 'UNKNOWN',
                syncStrategy: data.sync_strategy
              });
            } catch (error) {
              console.error('Dashboard data load failed:', error);
            }
          }

          updateMetrics(data) {
            const metrics = {
              'policy-version': data.policyVersion,
              'policies-count': data.policiesCount,
              'health-status': data.healthStatus,
              'sync-strategy': data.syncStrategy
            };

            Object.entries(metrics).forEach(([key, value]) => {
              const element = document.querySelector(`[data-metric="${key}"]`);
              if (element) {
                element.textContent = value;
              }
            });
          }

          switchTab(tabName) {
            document.querySelectorAll('.tab-button').forEach(btn => {
              btn.classList.toggle('active', btn.dataset.tab === tabName);
            });

            document.querySelectorAll('.tab-content').forEach(content => {
              content.style.display = content.id === tabName + '-tab' ? 'block' : 'none';
            });

            this.currentTab = tabName;
            this.loadTabData(tabName);
          }

          async loadTabData(tabName) {
            switch (tabName) {
              case 'dashboard':
                await this.loadDashboardData();
                break;
              case 'monitoring':
                await this.loadMonitoringData();
                break;
            }
          }

          async loadMonitoringData() {
            try {
              const response = await fetch(this.apiBase + '/_plugins/_cedarling/sync/cluster/status');
              const data = await response.json();
              
              const elements = {
                'cluster-nodes': data.total_nodes,
                'cluster-sync-nodes': data.synchronized_nodes,
                'cluster-health': data.sync_health_percentage + '%',
                'cluster-leader': data.current_leader
              };

              Object.entries(elements).forEach(([key, value]) => {
                const element = document.querySelector(`[data-cluster="${key}"]`);
                if (element) {
                  element.textContent = value;
                }
              });
            } catch (error) {
              console.error('Monitoring data load failed:', error);
            }
          }

          async forceSync() {
            try {
              const response = await fetch(this.apiBase + '/_plugins/_cedarling/sync/force', {
                method: 'POST'
              });
              
              if (response.ok) {
                this.showNotification('Policy synchronization initiated', 'success');
                await this.loadDashboardData();
              }
            } catch (error) {
              this.showNotification('Failed to force synchronization', 'error');
            }
          }

          showNotification(message, type) {
            const notification = document.createElement('div');
            notification.style.cssText = `
              position: fixed;
              top: 20px;
              right: 20px;
              background: ${type === 'success' ? '#00875a' : '#de350b'};
              color: white;
              padding: 12px 16px;
              border-radius: 8px;
              z-index: 1001;
              max-width: 300px;
            `;
            notification.textContent = message;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
              notification.remove();
            }, 3000);
          }
        }

        document.addEventListener('DOMContentLoaded', () => {
          new CedarlingAdmin();
        });
        """;
    }
}