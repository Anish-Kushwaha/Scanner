// Terminal Output Manager
class Terminal {
    constructor(elementId) {
        this.terminal = document.getElementById(elementId);
        this.logs = [];
    }

    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = `[${timestamp}] ${message}`;
        const formattedEntry = `<span class="log-${type}">${logEntry}</span>`;
        
        this.logs.push(formattedEntry);
        this.terminal.innerHTML = this.logs.join('\n') + '\n';
        this.terminal.scrollTop = this.terminal.scrollHeight;
    }

    clear() {
        this.logs = [];
        this.terminal.innerHTML = '[+] Terminal cleared\n';
    }

    copyToClipboard() {
        const text = this.logs.map(log => 
            log.replace(/<[^>]*>/g, '')
        ).join('\n');
        
        navigator.clipboard.writeText(text).then(() => {
            this.log('Log copied to clipboard', 'success');
        });
    }
}

// Scan Manager
class ScanManager {
    constructor() {
        this.terminal = new Terminal('terminalOutput');
        this.currentScan = null;
        this.stages = [
            { id: 1, name: 'Reconnaissance', progress: 0 },
            { id: 2, name: 'Network Scan', progress: 0 },
            { id: 3, name: 'Web Vulnerabilities', progress: 0 },
            { id: 4, name: 'Plesk Scan', progress: 0 },
            { id: 5, name: 'Report Generation', progress: 0 }
        ];
    }

    async startScan(targetUrl) {
        try {
            this.terminal.log(`Starting scan for: ${targetUrl}`, 'info');
            
            // Show progress section
            document.getElementById('progressSection').style.display = 'block';
            document.getElementById('resultsDashboard').style.display = 'none';
            
            // Update progress
            this.updateProgress(0, 'Initializing scanner...');
            
            // Start API call
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target_url: targetUrl })
            });

            if (!response.ok) {
                throw new Error('Scan failed');
            }

            const results = await response.json();
            
            // Complete progress
            this.updateProgress(100, 'Scan completed!');
            
            // Show results
            this.displayResults(results);
            
            this.terminal.log('Scan completed successfully', 'success');
            
        } catch (error) {
            this.terminal.log(`Scan error: ${error.message}`, 'error');
            this.updateProgress(0, 'Scan failed');
        } finally {
            // Hide progress after delay
            setTimeout(() => {
                document.getElementById('progressSection').style.display = 'none';
            }, 2000);
        }
    }

    updateProgress(percent, message) {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        progressFill.style.width = `${percent}%`;
        progressText.textContent = message;
        
        // Update stage indicators
        const stagePercent = percent / 100;
        const activeStageIndex = Math.floor(stagePercent * this.stages.length);
        
        document.querySelectorAll('.stage').forEach((stage, index) => {
            if (index <= activeStageIndex) {
                stage.classList.add('active');
            } else {
                stage.classList.remove('active');
            }
        });
    }

    displayResults(results) {
        // Show results dashboard
        document.getElementById('resultsDashboard').style.display = 'block';
        
        // Update summary cards
        this.updateSummaryCards(results.summary);
        
        // Update target info
        this.updateTargetInfo(results.target_info);
        
        // Update geolocation
        this.updateGeolocation(results.geolocation);
        
        // Update DNS records
        this.updateDNSRecords(results.dns_records);
        
        // Update ports table
        this.updatePortsTable(results.network_scan);
        
        // Update vulnerabilities
        this.updateVulnerabilities(results.web_vulnerabilities);
        
        // Update Plesk results
        this.updatePleskResults(results.plesk_scan);
        
        // Store full results for report tab
        this.currentScan = results;
        
        this.terminal.log('Results displayed in dashboard', 'success');
    }

    updateSummaryCards(summary) {
        document.getElementById('openPortsCount').textContent = summary.open_ports;
        document.getElementById('vulnCount').textContent = summary.vulnerabilities_found;
        document.getElementById('pleskFindings').textContent = summary.plesk_findings;
        
        // Calculate risk level
        let riskLevel = 'LOW';
        if (summary.vulnerabilities_found > 5) {
            riskLevel = 'CRITICAL';
        } else if (summary.vulnerabilities_found > 2) {
            riskLevel = 'HIGH';
        } else if (summary.vulnerabilities_found > 0) {
            riskLevel = 'MEDIUM';
        }
        document.getElementById('riskLevel').textContent = riskLevel;
    }

    updateTargetInfo(targetInfo) {
        document.getElementById('infoDomain').textContent = targetInfo.domain;
        document.getElementById('infoIP').textContent = targetInfo.ip;
        document.getElementById('infoPort').textContent = targetInfo.port;
    }

    updateGeolocation(geo) {
        if (geo.error) {
            document.getElementById('geoCountry').textContent = 'Unknown';
            document.getElementById('geoISP').textContent = 'Unknown';
            document.getElementById('geoLocation').textContent = 'Unknown';
            return;
        }
        
        document.getElementById('geoCountry').textContent = geo.country;
        document.getElementById('geoISP').textContent = geo.isp;
        document.getElementById('geoLocation').textContent = `${geo.city}, ${geo.region}`;
    }

    updateDNSRecords(dnsRecords) {
        const container = document.getElementById('dnsRecords');
        container.innerHTML = '';
        
        for (const [type, values] of Object.entries(dnsRecords)) {
            if (type !== 'error' && values.length > 0) {
                values.forEach(value => {
                    const recordDiv = document.createElement('div');
                    recordDiv.className = 'dns-record';
                    recordDiv.innerHTML = `
                        <div class="dns-type">${type}</div>
                        <div class="dns-value">${value}</div>
                    `;
                    container.appendChild(recordDiv);
                });
            }
        }
    }

    updatePortsTable(ports) {
        const tbody = document.getElementById('portsTableBody');
        tbody.innerHTML = '';
        
        ports.forEach(port => {
            const row = document.createElement('tr');
            
            // Determine service name based on port
            const serviceNames = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 139: 'NetBIOS',
                143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
                3389: 'RDP', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
                8888: 'HTTP-Alt'
            };
            
            const service = serviceNames[port.port] || 'Unknown';
            const isOpen = port.status === 'open';
            
            row.innerHTML = `
                <td>${port.port}</td>
                <td>${service}</td>
                <td>${port.banner || 'No banner'}</td>
                <td>
                    <span class="vuln-status">
                        ${port.vuln_info.includes('⚠️') ? '⚠️ Vulnerable' : 'Secure'}
                    </span>
                </td>
                <td>
                    <button class="terminal-btn small" onclick="scanManager.testPort(${port.port})">
                        <i class="fas fa-bolt"></i> Test
                    </button>
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }

    updateVulnerabilities(vulns) {
        const container = document.getElementById('webVulnGrid');
        container.innerHTML = '';
        
        vulns.forEach(vuln => {
            const card = document.createElement('div');
            card.className = `vuln-card ${vuln.severity ? vuln.severity.toLowerCase() : ''}`;
            
            const severityClass = vuln.severity ? `severity-${vuln.severity.toLowerCase()}` : '';
            const severityText = vuln.severity || 'Info';
            
            card.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-type">${vuln.type}</div>
                    <div class="vuln-severity ${severityClass}">${severityText}</div>
                </div>
                ${vuln.url ? `<div class="vuln-url">${vuln.url}</div>` : ''}
                <div class="vuln-description">${vuln.description || 'No description available'}</div>
            `;
            
            container.appendChild(card);
        });
    }

    updatePleskResults(pleskResults) {
        const container = document.getElementById('pleskResults');
        container.innerHTML = '';
        
        if (!pleskResults || pleskResults.length === 0) {
            container.innerHTML = '<div class="info-card">No Plesk-specific findings.</div>';
            return;
        }
        
        pleskResults.forEach(result => {
            const card = document.createElement('div');
            card.className = 'vuln-card';
            
            let severity = 'medium';
            if (result.type.includes('SQLi')) severity = 'critical';
            if (result.severity) severity = result.severity.toLowerCase();
            
            card.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-type">${result.type}</div>
                    <div class="vuln-severity severity-${severity}">
                        ${result.severity || 'INFO'}
                    </div>
                </div>
                ${result.url ? `<div class="vuln-url">${result.url}</div>` : ''}
                <div class="vuln-description">
                    Status: ${result.status || 'N/A'} | ${result.description || 'No additional info'}
                </div>
            `;
            
            container.appendChild(card);
        });
    }

    testPort(port) {
        this.terminal.log(`Testing port ${port} manually...`, 'info');
        // Add manual port test logic here
    }

    loadDemoData() {
        this.terminal.log('Loading demo scan data...', 'info');
        
        const demoData = {
            timestamp: new Date().toISOString(),
            scan_duration: "00:45:23",
            target_info: {
                original_url: "https://demo.example.com:8443",
                domain: "demo.example.com",
                ip: "192.168.1.100",
                port: 8443
            },
            geolocation: {
                country: "United States",
                region: "California",
                city: "San Francisco",
                isp: "Demo ISP",
                lat: 37.7749,
                lon: -122.4194
            },
            whois: {
                registrar: "Demo Registrar Inc.",
                creation_date: "2020-01-15",
                expiration_date: "2025-01-15",
                name_servers: ["ns1.demo.com", "ns2.demo.com"]
            },
            dns_records: {
                A: ["192.168.1.100"],
                MX: ["mail.demo.example.com"],
                TXT: ["v=spf1 include:_spf.demo.com ~all"],
                CNAME: ["www.demo.example.com"]
            },
            network_scan: [
                { port: 22, banner: "SSH-2.0-OpenSSH_8.2", vuln_info: "Secure", status: "open" },
                { port: 80, banner: "nginx/1.18.0", vuln_info: "⚠️ Outdated nginx version", status: "open" },
                { port: 443, banner: "Apache/2.4.41", vuln_info: "Secure", status: "open" },
                { port: 3306, banner: "MySQL 5.7.33", vuln_info: "⚠️ Outdated MySQL version", status: "open" }
            ],
            plesk_scan: [
                { type: "Plesk Access", status: 200, title: "Plesk Panel", url: "https://demo.example.com:8443", severity: "INFO" },
                { type: "Exposed Path", status: 200, url: "https://demo.example.com:8443/.env", severity: "HIGH", description: "Environment file exposed" }
            ],
            web_vulnerabilities: [
                { type: "XSS", url: "https://demo.example.com/?test=payload", severity: "HIGH", description: "Potential Cross-Site Scripting vulnerability" },
                { type: "Exposed Directory", url: "https://demo.example.com/admin", severity: "MEDIUM", description: "Admin directory accessible" }
            ],
            summary: {
                open_ports: 4,
                vulnerabilities_found: 3,
                plesk_findings: 2
            }
        };
        
        this.displayResults(demoData);
        this.terminal.log('Demo data loaded successfully', 'success');
    }
}

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    const scanManager = new ScanManager();
    window.scanManager = scanManager; // Make accessible globally
    
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            
            // Update active tab button
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Show active tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`${tabId}Tab`).classList.add('active');
        });
    });
    
    // Start scan button
    document.getElementById('startScan').addEventListener('click', () => {
        const targetUrl = document.getElementById('targetUrl').value.trim();
        if (!targetUrl) {
            scanManager.terminal.log('Error: Please enter a target URL', 'error');
            return;
        }
        
        scanManager.startScan(targetUrl);
    });
    
    // Demo scan button
    document.getElementById('demoScan').addEventListener('click', () => {
        scanManager.loadDemoData();
    });
    
    // Clear terminal button
    document.getElementById('clearLog').addEventListener('click', () => {
        scanManager.terminal.clear();
    });
    
    // Copy terminal button
    document.getElementById('copyLog').addEventListener('click', () => {
        scanManager.terminal.copyToClipboard();
    });
    
    // Download report button
    document.getElementById('downloadReport').addEventListener('click', () => {
        if (!scanManager.currentScan) {
            scanManager.terminal.log('No scan data to download', 'warning');
            return;
        }
        
        const dataStr = JSON.stringify(scanManager.currentScan, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `anish_scanner_report_${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        scanManager.terminal.log('Report downloaded', 'success');
    });
    
    // View raw data button
    document.getElementById('viewRaw').addEventListener('click', () => {
        if (!scanManager.currentScan) {
            scanManager.terminal.log('No scan data to display', 'warning');
            return;
        }
        
        const jsonViewer = document.getElementById('jsonViewer');
        jsonViewer.textContent = JSON.stringify(scanManager.currentScan, null, 2);
        
        // Switch to report tab
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelector('[data-tab="report"]').classList.add('active');
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById('reportTab').classList.add('active');
    });
    
    // Enter key support for input
    document.getElementById('targetUrl').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('startScan').click();
        }
    });
    
    // Initial terminal message
    scanManager.terminal.log('Anish Security Scanner v3.2 initialized', 'success');
    scanManager.terminal.log('Ready for target acquisition', 'info');
});
