#!/usr/bin/env python3
"""
TBAC Live Demo - Integrates with OpenSearch Cedarling Plugin
Demonstrates real user authentication and document access control
"""

import json
import time
import base64
import hmac
import hashlib
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

class TBACLiveDemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.serve_tbac_demo()
        else:
            self.send_error(404)
            
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(post_data)
        except:
            data = {}
            
        if self.path == '/api/login':
            self.handle_login(data)
        elif self.path == '/api/cedarling-status':
            self.handle_cedarling_status()
        elif self.path == '/api/cedarling-authorize':
            self.handle_cedarling_authorize(data)
        else:
            self.send_error(404)
            
    def serve_tbac_demo(self):
        html = """<!DOCTYPE html>
<html>
<head>
    <title>TBAC Live Demo - OpenSearch Document Access</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #2196F3 0%, #21CBF3 100%); color: white; border-radius: 8px; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #e1e5e9; border-radius: 6px; background: white; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: 600; }
        input, textarea, select { width: 100%; padding: 10px; border: 1px solid #d1d5da; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
        button { background: #28a745; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; margin: 5px 0; }
        button:hover { background: #218838; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #c82333; }
        .token-display { background: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; font-size: 11px; word-break: break-all; max-height: 100px; overflow-y: auto; }
        .success { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; color: #155724; margin: 10px 0; }
        .error { background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; color: #721c24; margin: 10px 0; }
        .info { background: #e7f3ff; border-left: 4px solid #0366d6; padding: 15px; color: #0366d6; margin: 10px 0; }
        .user-info { background: #e8f5e8; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .result { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 15px; font-family: monospace; white-space: pre-wrap; font-size: 12px; max-height: 300px; overflow-y: auto; }
        .status { padding: 10px; border-radius: 4px; margin: 10px 0; }
        .status.connected { background: #d4edda; color: #155724; }
        .status.disconnected { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TBAC Live Demo - OpenSearch Document Access</h1>
            <p>Real token-based access control with Cedarling policy evaluation</p>
        </div>
        
        <div class="section">
            <h2>OpenSearch Cedarling Plugin Status</h2>
            <div id="pluginStatus" class="status disconnected">
                Checking connection to OpenSearch Cedarling plugin...
            </div>
            <button onclick="checkPluginStatus()">Refresh Status</button>
        </div>
        
        <div class="section">
            <h2>User Authentication</h2>
            <div id="authSection">
                <div class="form-group">
                    <label>Select Test User:</label>
                    <select id="userSelect">
                        <option value="">Choose a user...</option>
                        <option value="alice@engineering.corp">Alice Johnson - Engineering (Full Access)</option>
                        <option value="bob@sales.corp">Bob Smith - Sales (Limited Access)</option>
                        <option value="charlie@finance.corp">Charlie Brown - Finance (Read Only)</option>
                        <option value="guest@external.com">Guest User - External (Restricted)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Account ID:</label>
                    <input type="text" id="accountId" placeholder="acct_12345" value="acct_demo_123">
                </div>
                <button onclick="authenticateUser()">Authenticate & Generate Tokens</button>
            </div>
            
            <div id="userSession" style="display: none;">
                <div class="user-info">
                    <strong>Authenticated User:</strong> <span id="currentUser"></span><br>
                    <strong>Account:</strong> <span id="currentAccount"></span><br>
                    <strong>Department:</strong> <span id="currentDepartment"></span><br>
                    <strong>Access Level:</strong> <span id="currentAccess"></span>
                </div>
                <button class="danger" onclick="logout()">Logout</button>
            </div>
        </div>
        
        <div class="section" id="tokenSection" style="display: none;">
            <h2>Generated Tokens</h2>
            <div class="form-group">
                <label>Access Token (for authorization):</label>
                <div class="token-display" id="accessTokenDisplay"></div>
            </div>
            <div class="form-group">
                <label>ID Token (for identity):</label>
                <div class="token-display" id="idTokenDisplay"></div>
            </div>
        </div>
        
        <div class="section">
            <h2>Document Query Test</h2>
            <div class="form-group">
                <label>Document Type to Query:</label>
                <select id="queryType" onchange="updateQueryExample()">
                    <option value="customer_data">Customer Data (account-restricted)</option>
                    <option value="financial_reports">Financial Reports (finance department only)</option>
                    <option value="engineering_docs">Engineering Documentation (engineering only)</option>
                    <option value="public_data">Public Data (all users)</option>
                    <option value="confidential">Confidential Data (admin only)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Principal (User):</label>
                <input type="text" id="principal" placeholder="user:alice@engineering.corp" readonly>
            </div>
            <div class="form-group">
                <label>Action:</label>
                <input type="text" id="action" value="read" readonly>
            </div>
            <div class="form-group">
                <label>Resource:</label>
                <input type="text" id="resource" placeholder="index:customer-data">
            </div>
            <div class="form-group">
                <label>Context (JSON):</label>
                <textarea id="context" rows="4" placeholder="Additional context will be added automatically"></textarea>
            </div>
            <button onclick="testDocumentAccess()" id="queryBtn" disabled>Test Document Access with TBAC</button>
        </div>
        
        <div class="section">
            <h2>Authorization Result</h2>
            <div id="authResult">
                <div class="info">Authenticate a user and test document access to see TBAC results.</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Policy Evaluation Details</h2>
            <div id="policyDetails">
                <div class="info">Policy evaluation details will appear here after testing access.</div>
            </div>
        </div>
    </div>
    
    <script>
        let currentSession = null;
        const CEDARLING_BASE_URL = 'http://localhost:5000';
        
        // User database with realistic enterprise users
        const users = {
            'alice@engineering.corp': {
                name: 'Alice Johnson',
                department: 'engineering',
                access_level: 'full',
                roles: ['developer', 'data_reader', 'engineer']
            },
            'bob@sales.corp': {
                name: 'Bob Smith',
                department: 'sales', 
                access_level: 'limited',
                roles: ['sales_rep', 'customer_data_reader']
            },
            'charlie@finance.corp': {
                name: 'Charlie Brown',
                department: 'finance',
                access_level: 'read_only', 
                roles: ['financial_analyst', 'report_reader']
            },
            'guest@external.com': {
                name: 'Guest User',
                department: 'external',
                access_level: 'restricted',
                roles: ['guest']
            }
        };
        
        async function checkPluginStatus() {
            try {
                const response = await fetch('/api/cedarling-status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const status = await response.json();
                
                if (status.status === 'active') {
                    document.getElementById('pluginStatus').innerHTML = 
                        `Connected to OpenSearch Cedarling Plugin v${status.version} - Status: ${status.status}`;
                    document.getElementById('pluginStatus').className = 'status connected';
                } else {
                    throw new Error('Plugin not active');
                }
            } catch (error) {
                document.getElementById('pluginStatus').innerHTML = 
                    'Cannot connect to OpenSearch Cedarling plugin. Make sure it is running on port 5000.';
                document.getElementById('pluginStatus').className = 'status disconnected';
            }
        }
        
        async function authenticateUser() {
            const userEmail = document.getElementById('userSelect').value;
            const accountId = document.getElementById('accountId').value;
            
            if (!userEmail || !accountId) {
                alert('Please select a user and enter account ID');
                return;
            }
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: userEmail,
                        account_id: accountId
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentSession = result.session;
                    showUserSession(result.session);
                    updateQueryForm();
                } else {
                    showError('Authentication failed: ' + result.error);
                }
            } catch (error) {
                showError('Authentication error: ' + error.message);
            }
        }
        
        function showUserSession(session) {
            document.getElementById('authSection').style.display = 'none';
            document.getElementById('userSession').style.display = 'block';
            document.getElementById('tokenSection').style.display = 'block';
            
            document.getElementById('currentUser').textContent = session.email;
            document.getElementById('currentAccount').textContent = session.account_id;
            document.getElementById('currentDepartment').textContent = session.department;
            document.getElementById('currentAccess').textContent = session.access_level;
            
            document.getElementById('accessTokenDisplay').textContent = session.access_token;
            document.getElementById('idTokenDisplay').textContent = session.id_token;
            
            document.getElementById('queryBtn').disabled = false;
        }
        
        function updateQueryForm() {
            if (currentSession) {
                document.getElementById('principal').value = `user:${currentSession.email}`;
                updateQueryExample();
            }
        }
        
        function updateQueryExample() {
            const queryType = document.getElementById('queryType').value;
            let resource = '';
            let context = {};
            
            switch (queryType) {
                case 'customer_data':
                    resource = 'index:customer-data';
                    if (currentSession) {
                        context = {
                            account_id: currentSession.account_id,
                            document_type: 'customer_record'
                        };
                    }
                    break;
                case 'financial_reports':
                    resource = 'index:financial-reports';
                    context = { document_type: 'financial_report', classification: 'internal' };
                    break;
                case 'engineering_docs':
                    resource = 'index:engineering-docs';
                    context = { document_type: 'technical_spec', classification: 'technical' };
                    break;
                case 'public_data':
                    resource = 'index:public-data';
                    context = { document_type: 'public_announcement', classification: 'public' };
                    break;
                case 'confidential':
                    resource = 'index:confidential-data';
                    context = { document_type: 'confidential_report', classification: 'confidential' };
                    break;
            }
            
            document.getElementById('resource').value = resource;
            document.getElementById('context').value = JSON.stringify(context, null, 2);
        }
        
        async function testDocumentAccess() {
            if (!currentSession) {
                alert('Please authenticate first');
                return;
            }
            
            const principal = document.getElementById('principal').value;
            const action = document.getElementById('action').value;
            const resource = document.getElementById('resource').value;
            const contextText = document.getElementById('context').value;
            
            let context = {};
            try {
                context = JSON.parse(contextText || '{}');
            } catch (e) {
                showError('Invalid JSON in context field');
                return;
            }
            
            // Add user context from session
            context = {
                ...context,
                user_account_id: currentSession.account_id,
                user_department: currentSession.department,
                user_access_level: currentSession.access_level
            };
            
            try {
                // Test authorization with the OpenSearch Cedarling plugin via proxy
                const authResponse = await fetch('/api/cedarling-authorize', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        principal: principal,
                        action: action,
                        resource: resource,
                        context: context,
                        token: currentSession.access_token
                    })
                });
                
                const authResult = await authResponse.json();
                displayAuthorizationResult(authResult);
                
            } catch (error) {
                showError('TBAC test error: ' + error.message);
            }
        }
        
        function displayAuthorizationResult(result) {
            const authDiv = document.getElementById('authResult');
            const policyDiv = document.getElementById('policyDetails');
            
            let authHtml = '';
            if (result.decision === 'ALLOW') {
                authHtml = `
                    <div class="success">
                        <strong>Access Granted:</strong> User authorized to access the requested document<br>
                        <strong>Decision:</strong> ${result.decision}<br>
                        <strong>Execution Time:</strong> ${result.execution_time_ms}ms
                    </div>
                `;
            } else {
                authHtml = `
                    <div class="error">
                        <strong>Access Denied:</strong> User not authorized to access the requested document<br>
                        <strong>Decision:</strong> ${result.decision}<br>
                        <strong>Execution Time:</strong> ${result.execution_time_ms}ms
                    </div>
                `;
            }
            
            const policyHtml = `
                <div class="result">
<strong>TBAC Policy Evaluation Details:</strong>

Principal: ${result.principal}
Action: ${result.action}
Resource: ${result.resource}
Decision: ${result.decision}
Policies Applied: ${result.policies_applied ? result.policies_applied.join(', ') : 'None'}
Execution Time: ${result.execution_time_ms}ms
Timestamp: ${result.timestamp}

<strong>Token Information:</strong>
User: ${currentSession.email}
Account: ${currentSession.account_id}
Department: ${currentSession.department}
Access Level: ${currentSession.access_level}

<strong>Context Evaluated:</strong>
${JSON.stringify(result.context || {}, null, 2)}
                </div>
            `;
            
            authDiv.innerHTML = authHtml;
            policyDiv.innerHTML = policyHtml;
        }
        
        function logout() {
            currentSession = null;
            document.getElementById('authSection').style.display = 'block';
            document.getElementById('userSession').style.display = 'none';
            document.getElementById('tokenSection').style.display = 'none';
            document.getElementById('queryBtn').disabled = true;
            
            document.getElementById('authResult').innerHTML = 
                '<div class="info">Authenticate a user and test document access to see TBAC results.</div>';
            document.getElementById('policyDetails').innerHTML = 
                '<div class="info">Policy evaluation details will appear here after testing access.</div>';
        }
        
        function showError(message) {
            document.getElementById('authResult').innerHTML = 
                `<div class="error"><strong>Error:</strong> ${message}</div>`;
        }
        
        // Initialize
        checkPluginStatus();
        updateQueryExample();
    </script>
</body>
</html>"""
        self.send_html_response(html)
        
    def handle_login(self, data):
        email = data.get('email', '')
        account_id = data.get('account_id', '')
        
        # User info mapping
        users = {
            'alice@engineering.corp': {
                'name': 'Alice Johnson',
                'department': 'engineering',
                'access_level': 'full',
                'roles': ['developer', 'data_reader', 'engineer']
            },
            'bob@sales.corp': {
                'name': 'Bob Smith',
                'department': 'sales',
                'access_level': 'limited',
                'roles': ['sales_rep', 'customer_data_reader']
            },
            'charlie@finance.corp': {
                'name': 'Charlie Brown',
                'department': 'finance',
                'access_level': 'read_only',
                'roles': ['financial_analyst', 'report_reader']
            },
            'guest@external.com': {
                'name': 'Guest User',
                'department': 'external',
                'access_level': 'restricted',
                'roles': ['guest']
            }
        }
        
        user_info = users.get(email, {
            'name': 'Unknown User',
            'department': 'unknown',
            'access_level': 'none',
            'roles': []
        })
        
        # Generate tokens
        access_token = self.create_access_token(email, account_id, user_info)
        id_token = self.create_id_token(email, user_info)
        
        session = {
            'email': email,
            'account_id': account_id,
            'department': user_info['department'],
            'access_level': user_info['access_level'],
            'access_token': access_token,
            'id_token': id_token
        }
        
        self.send_json_response({'success': True, 'session': session})
        
    def handle_cedarling_status(self):
        """Proxy request to OpenSearch Cedarling plugin status endpoint"""
        try:
            req = urllib.request.Request('http://localhost:5000/_plugins/_cedarling/status')
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                self.send_json_response(data)
        except Exception as e:
            self.send_json_response({
                'error': f'Failed to connect to Cedarling plugin: {str(e)}',
                'status': 'disconnected'
            })
            
    def handle_cedarling_authorize(self, data):
        """Proxy authorization request to OpenSearch Cedarling plugin"""
        try:
            auth_data = json.dumps(data).encode()
            req = urllib.request.Request(
                'http://localhost:5000/_plugins/_cedarling/data-policies/authorize',
                data=auth_data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode())
                self.send_json_response(result)
        except Exception as e:
            self.send_json_response({
                'error': f'Authorization request failed: {str(e)}',
                'authorization': {'decision': 'DENY', 'reason': 'Plugin communication error'}
            })
        
    def create_access_token(self, email, account_id, user_info):
        """Create JWT access token"""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': email,
            'aud': 'opensearch-cedarling',
            'iss': 'https://jans.example.com',
            'exp': int(time.time()) + 3600,
            'iat': int(time.time()),
            'account_id': account_id,
            'department': user_info['department'],
            'access_level': user_info['access_level'],
            'roles': user_info['roles']
        }
        return self.encode_jwt(header, payload)
        
    def create_id_token(self, email, user_info):
        """Create JWT ID token"""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': email,
            'aud': 'opensearch-cedarling',
            'iss': 'https://jans.example.com',
            'exp': int(time.time()) + 3600,
            'iat': int(time.time()),
            'name': user_info['name'],
            'email': email,
            'department': user_info['department']
        }
        return self.encode_jwt(header, payload)
        
    def encode_jwt(self, header, payload):
        """Encode JWT token"""
        secret = 'demo-secret'
        
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(
            secret.encode(), 
            message.encode(), 
            hashlib.sha256
        ).digest()
        
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        
    def send_json_response(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
        
    def send_html_response(self, html):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
        
    def log_message(self, format, *args):
        pass

def main():
    port = 8080
    server = HTTPServer(('0.0.0.0', port), TBACLiveDemoHandler)
    
    print(f"TBAC Live Demo running on port {port}")
    print(f"Access: http://localhost:{port}/")
    print("This demo integrates with OpenSearch Cedarling plugin on port 5000")
    print("\nTest scenarios:")
    print("- Alice (Engineering): Full access to engineering docs, customer data")
    print("- Bob (Sales): Limited access to customer data only")
    print("- Charlie (Finance): Read-only access to financial reports")
    print("- Guest (External): Restricted access to public data only")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down TBAC Live Demo...")
        server.shutdown()

if __name__ == "__main__":
    main()