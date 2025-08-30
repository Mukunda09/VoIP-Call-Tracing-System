// VoIP Call Tracing System JavaScript
class VoIPTracingSystem {
    constructor() {
        this.data = {
            liveTraffic: {
                protocols: [
                    {"name": "SIP", "count": 245, "color": "#1FB8CD"},
                    {"name": "RTP", "count": 1823, "color": "#FFC185"},
                    {"name": "RTCP", "count": 156, "color": "#B4413C"},
                    {"name": "Other", "count": 67, "color": "#ECEBD5"}
                ],
                timeline: [
                    {"time": "14:30", "packets": 45},
                    {"time": "14:31", "packets": 52},
                    {"time": "14:32", "packets": 38},
                    {"time": "14:33", "packets": 67},
                    {"time": "14:34", "packets": 73},
                    {"time": "14:35", "packets": 41},
                    {"time": "14:36", "packets": 89},
                    {"time": "14:37", "packets": 124},
                    {"time": "14:38", "packets": 98},
                    {"time": "14:39", "packets": 156}
                ],
                topIPs: [
                    {"ip": "192.168.1.10", "packets": 234, "risk": "low"},
                    {"ip": "10.0.0.25", "packets": 189, "risk": "low"},
                    {"ip": "192.168.1.100", "packets": 167, "risk": "high"},
                    {"ip": "172.16.0.5", "packets": 145, "risk": "medium"},
                    {"ip": "203.0.113.15", "packets": 123, "risk": "critical"}
                ]
            },
            suspiciousActivity: [
                {
                    "timestamp": "2024-03-15 14:37:23",
                    "type": "Rapid SIP Flooding",
                    "sourceIP": "192.168.1.100",
                    "destIP": "10.0.0.25", 
                    "severity": "HIGH",
                    "description": "50+ INVITE requests in 30 seconds",
                    "riskScore": 85
                },
                {
                    "timestamp": "2024-03-15 14:35:41",
                    "type": "Unusual Time Pattern",
                    "sourceIP": "203.0.113.15",
                    "destIP": "Multiple",
                    "severity": "MEDIUM", 
                    "description": "75% of calls during night hours",
                    "riskScore": 67
                },
                {
                    "timestamp": "2024-03-15 14:33:12",
                    "type": "Geographic Anomaly",
                    "sourceIP": "198.51.100.25",
                    "destIP": "Multiple",
                    "severity": "MEDIUM",
                    "description": "Contacted 25+ different subnets",
                    "riskScore": 72
                }
            ],
            mlAnalysis: {
                anomalies: [
                    {"ip": "192.168.1.100", "score": 0.89, "features": "High call frequency, rapid requests"},
                    {"ip": "203.0.113.15", "score": 0.76, "features": "Unusual timing patterns, multiple destinations"},
                    {"ip": "198.51.100.25", "score": 0.71, "features": "Geographic spread, long duration calls"}
                ],
                patterns: [
                    {"pattern": "Brute Force Registration", "count": 3, "severity": "Critical"},
                    {"pattern": "Call Flooding", "count": 7, "severity": "High"}, 
                    {"pattern": "Time-based Anomaly", "count": 12, "severity": "Medium"},
                    {"pattern": "Geographic Spread", "count": 8, "severity": "Medium"}
                ]
            },
            ipReputation: [
                {"ip": "192.168.1.100", "risk": "CRITICAL", "score": 15, "incidents": 8, "lastSeen": "2024-03-15 14:37:23"},
                {"ip": "203.0.113.15", "risk": "HIGH", "score": 33, "incidents": 5, "lastSeen": "2024-03-15 14:35:41"},
                {"ip": "198.51.100.25", "risk": "HIGH", "score": 28, "incidents": 4, "lastSeen": "2024-03-15 14:33:12"},
                {"ip": "172.16.0.200", "risk": "MEDIUM", "score": 55, "incidents": 2, "lastSeen": "2024-03-15 14:29:15"}
            ],
            systemStats: {
                totalPackets: 2291,
                sipPackets: 245,
                rtpStreams: 34,
                suspiciousIPs: 8,
                activeAlerts: 15,
                uptime: "23:45:12"
            }
        };

        this.charts = {};
        this.isMonitoring = false;
        this.monitoringInterval = null;
        
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupEventListeners();
        this.populateInitialData();
        this.initializeCharts();
        this.startRealTimeUpdates();
    }

    setupNavigation() {
        const navButtons = document.querySelectorAll('.nav-btn');
        const sections = document.querySelectorAll('.content-section');

        navButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetSection = button.getAttribute('data-section');
                
                // Update active button
                navButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                
                // Update active section
                sections.forEach(section => section.classList.remove('active'));
                document.getElementById(targetSection).classList.add('active');
                
                // Refresh charts if needed
                this.refreshChartsInSection(targetSection);
            });
        });
    }

    setupEventListeners() {
        // Monitor controls
        document.getElementById('startMonitor')?.addEventListener('click', () => this.startMonitoring());
        document.getElementById('pauseMonitor')?.addEventListener('click', () => this.pauseMonitoring());
        document.getElementById('refreshData')?.addEventListener('click', () => this.refreshData());

        // Export buttons
        document.querySelectorAll('.export-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const format = e.target.getAttribute('data-format');
                this.exportData(format);
            });
        });

        // Report generation buttons
        document.querySelectorAll('.btn').forEach(btn => {
            if (btn.textContent.includes('Generate Report')) {
                btn.addEventListener('click', () => this.generateReport(btn));
            }
        });

        // Settings sliders
        document.querySelectorAll('input[type="range"]').forEach(slider => {
            slider.addEventListener('input', (e) => {
                const valueSpan = e.target.nextElementSibling;
                if (valueSpan && valueSpan.classList.contains('range-value')) {
                    valueSpan.textContent = e.target.value;
                }
            });
        });
    }

    populateInitialData() {
        // Update overview stats
        this.animateCounter('totalPackets', this.data.systemStats.totalPackets);
        this.animateCounter('sipPackets', this.data.systemStats.sipPackets);
        this.animateCounter('rtpStreams', this.data.systemStats.rtpStreams);
        this.animateCounter('activeAlerts', this.data.systemStats.activeAlerts);

        // Populate alerts
        this.populateAlerts();
        
        // Populate risk table
        this.populateRiskTable();
        
        // Populate pattern analysis
        this.populatePatternAnalysis();
        
        // Populate anomaly detection
        this.populateAnomalyDetection();
    }

    animateCounter(elementId, targetValue, duration = 2000) {
        const element = document.getElementById(elementId);
        if (!element) return;

        let startValue = 0;
        const increment = targetValue / (duration / 16);
        
        const animate = () => {
            startValue += increment;
            if (startValue < targetValue) {
                element.textContent = Math.floor(startValue).toLocaleString();
                requestAnimationFrame(animate);
            } else {
                element.textContent = targetValue.toLocaleString();
            }
        };
        
        animate();
    }

    populateAlerts() {
        const alertsList = document.getElementById('alertsList');
        if (!alertsList) return;

        alertsList.innerHTML = '';
        
        this.data.suspiciousActivity.forEach(alert => {
            const alertElement = document.createElement('div');
            alertElement.className = `alert-item ${alert.severity.toLowerCase()}`;
            
            alertElement.innerHTML = `
                <div class="alert-content">
                    <div class="alert-type">${alert.type}</div>
                    <div class="alert-description">${alert.description}</div>
                    <div class="alert-details">
                        <span>Source: ${alert.sourceIP}</span>
                        <span>Dest: ${alert.destIP}</span>
                        <span>Time: ${alert.timestamp}</span>
                    </div>
                </div>
                <div class="alert-severity ${alert.severity.toLowerCase()}">${alert.severity}</div>
            `;
            
            alertsList.appendChild(alertElement);
        });
    }

    populateRiskTable() {
        const riskTable = document.getElementById('riskTable');
        if (!riskTable) return;

        const tbody = riskTable.querySelector('tbody');
        if (!tbody) return;

        tbody.innerHTML = '';
        
        this.data.ipReputation.forEach(ip => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${ip.ip}</td>
                <td><span class="risk-level ${ip.risk.toLowerCase()}">${ip.risk}</span></td>
                <td>${ip.score}</td>
                <td>${ip.incidents}</td>
                <td>${ip.lastSeen}</td>
                <td>
                    <button class="btn btn--sm btn--outline">Block</button>
                    <button class="btn btn--sm btn--secondary">Details</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    populatePatternAnalysis() {
        const patternList = document.getElementById('patternList');
        if (!patternList) return;

        patternList.innerHTML = '';
        
        this.data.mlAnalysis.patterns.forEach(pattern => {
            const patternElement = document.createElement('div');
            patternElement.className = 'pattern-item';
            
            patternElement.innerHTML = `
                <span class="pattern-name">${pattern.pattern}</span>
                <span class="pattern-count">${pattern.count}</span>
            `;
            
            patternList.appendChild(patternElement);
        });
    }

    populateAnomalyDetection() {
        const anomalyList = document.getElementById('anomalyList');
        if (!anomalyList) return;

        anomalyList.innerHTML = '';
        
        this.data.mlAnalysis.anomalies.forEach(anomaly => {
            const anomalyElement = document.createElement('div');
            anomalyElement.className = 'anomaly-item';
            
            anomalyElement.innerHTML = `
                <div>
                    <div class="anomaly-ip">${anomaly.ip}</div>
                    <div class="anomaly-features">${anomaly.features}</div>
                </div>
                <div class="anomaly-score">${(anomaly.score * 100).toFixed(0)}%</div>
            `;
            
            anomalyList.appendChild(anomalyElement);
        });
    }

    initializeCharts() {
        this.createProtocolChart();
        this.createTimelineChart();
        this.createTopIPsChart();
        this.createFeatureChart();
    }

    createProtocolChart() {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;

        this.charts.protocol = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: this.data.liveTraffic.protocols.map(p => p.name),
                datasets: [{
                    data: this.data.liveTraffic.protocols.map(p => p.count),
                    backgroundColor: ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5'],
                    borderWidth: 2,
                    borderColor: '#1f2121'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#f5f5f5',
                            padding: 20
                        }
                    }
                }
            }
        });
    }

    createTimelineChart() {
        const ctx = document.getElementById('timelineChart');
        if (!ctx) return;

        this.charts.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.data.liveTraffic.timeline.map(t => t.time),
                datasets: [{
                    label: 'Packets per Minute',
                    data: this.data.liveTraffic.timeline.map(t => t.packets),
                    borderColor: '#1FB8CD',
                    backgroundColor: 'rgba(31, 184, 205, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#f5f5f5'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#a7a9a9'
                        },
                        grid: {
                            color: 'rgba(167, 169, 169, 0.2)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#a7a9a9'
                        },
                        grid: {
                            color: 'rgba(167, 169, 169, 0.2)'
                        }
                    }
                }
            }
        });
    }

    createTopIPsChart() {
        const ctx = document.getElementById('topIPsChart');
        if (!ctx) return;

        const colors = this.data.liveTraffic.topIPs.map(ip => {
            switch(ip.risk) {
                case 'critical': return '#B4413C';
                case 'high': return '#FFC185';
                case 'medium': return '#D2BA4C';
                default: return '#1FB8CD';
            }
        });

        this.charts.topIPs = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: this.data.liveTraffic.topIPs.map(ip => ip.ip),
                datasets: [{
                    label: 'Packet Count',
                    data: this.data.liveTraffic.topIPs.map(ip => ip.packets),
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#f5f5f5'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#a7a9a9',
                            maxRotation: 45
                        },
                        grid: {
                            color: 'rgba(167, 169, 169, 0.2)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#a7a9a9'
                        },
                        grid: {
                            color: 'rgba(167, 169, 169, 0.2)'
                        }
                    }
                }
            }
        });
    }

    createFeatureChart() {
        const ctx = document.getElementById('featureChart');
        if (!ctx) return;

        const features = ['Call Frequency', 'Request Rate', 'Timing Pattern', 'Geographic Spread', 'Duration'];
        const importance = [0.85, 0.72, 0.68, 0.61, 0.45];

        this.charts.feature = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: features,
                datasets: [{
                    label: 'Feature Importance',
                    data: importance,
                    backgroundColor: ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5', '#5D878F'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: {
                        labels: {
                            color: '#f5f5f5'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#a7a9a9'
                        },
                        grid: {
                            color: 'rgba(167, 169, 169, 0.2)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#a7a9a9'
                        },
                        grid: {
                            color: 'rgba(167, 169, 169, 0.2)'
                        }
                    }
                }
            }
        });
    }

    refreshChartsInSection(section) {
        setTimeout(() => {
            Object.values(this.charts).forEach(chart => {
                if (chart) {
                    chart.resize();
                }
            });
        }, 100);
    }

    startMonitoring() {
        this.isMonitoring = true;
        const startBtn = document.getElementById('startMonitor');
        const pauseBtn = document.getElementById('pauseMonitor');
        
        if (startBtn) startBtn.textContent = 'Monitoring...';
        if (pauseBtn) pauseBtn.disabled = false;
        
        this.showNotification('Monitoring started', 'success');
    }

    pauseMonitoring() {
        this.isMonitoring = false;
        const startBtn = document.getElementById('startMonitor');
        const pauseBtn = document.getElementById('pauseMonitor');
        
        if (startBtn) startBtn.textContent = 'Start Monitoring';
        if (pauseBtn) pauseBtn.disabled = true;
        
        this.showNotification('Monitoring paused', 'warning');
    }

    refreshData() {
        // Simulate data refresh
        this.updateLiveStats();
        this.showNotification('Data refreshed', 'success');
    }

    updateLiveStats() {
        // Update packets per second with random variation
        const packetsPerSecElement = document.getElementById('packetsPerSec');
        if (packetsPerSecElement) {
            const currentValue = parseInt(packetsPerSecElement.textContent);
            const variation = Math.floor(Math.random() * 40) - 20; // -20 to +20
            const newValue = Math.max(50, currentValue + variation);
            packetsPerSecElement.textContent = newValue;
        }

        // Update suspicious IPs count occasionally
        if (Math.random() < 0.3) {
            const suspiciousIPsElement = document.getElementById('suspiciousIPs');
            if (suspiciousIPsElement) {
                const currentValue = parseInt(suspiciousIPsElement.textContent);
                const newValue = Math.max(1, currentValue + (Math.random() < 0.5 ? -1 : 1));
                suspiciousIPsElement.textContent = newValue;
            }
        }

        // Update timeline chart with new data point
        if (this.charts.timeline) {
            const chart = this.charts.timeline;
            const newTime = new Date().toLocaleTimeString('en-US', { 
                hour12: false, 
                hour: '2-digit', 
                minute: '2-digit' 
            });
            const newPackets = Math.floor(Math.random() * 100) + 50;
            
            chart.data.labels.push(newTime);
            chart.data.datasets[0].data.push(newPackets);
            
            // Keep only last 10 data points
            if (chart.data.labels.length > 10) {
                chart.data.labels.shift();
                chart.data.datasets[0].data.shift();
            }
            
            chart.update('none');
        }
    }

    startRealTimeUpdates() {
        // Update every 5 seconds
        setInterval(() => {
            if (this.isMonitoring) {
                this.updateLiveStats();
            }
        }, 5000);

        // Update uptime every second
        setInterval(() => {
            this.updateUptime();
        }, 1000);
    }

    updateUptime() {
        const uptimeElement = document.getElementById('uptime');
        if (!uptimeElement) return;

        const currentUptime = uptimeElement.textContent;
        const parts = currentUptime.split(':');
        let hours = parseInt(parts[0]);
        let minutes = parseInt(parts[1]);
        let seconds = parseInt(parts[2]);

        seconds++;
        if (seconds === 60) {
            seconds = 0;
            minutes++;
            if (minutes === 60) {
                minutes = 0;
                hours++;
            }
        }

        const newUptime = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        uptimeElement.textContent = newUptime;
    }

    exportData(format) {
        const formats = {
            'pdf': 'PDF Report',
            'csv': 'CSV Data',
            'json': 'JSON Export',
            'xlsx': 'Excel Workbook'
        };

        this.showNotification(`Exporting ${formats[format]}...`, 'info');
        
        // Simulate export process
        setTimeout(() => {
            this.showNotification(`${formats[format]} exported successfully`, 'success');
        }, 2000);
    }

    generateReport(button) {
        const reportType = button.parentElement.querySelector('.template-name').textContent;
        button.textContent = 'Generating...';
        button.disabled = true;

        setTimeout(() => {
            button.textContent = 'Generate Report';
            button.disabled = false;
            this.showNotification(`${reportType} generated successfully`, 'success');
        }, 3000);
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--color-surface);
            border: 1px solid var(--color-primary);
            color: var(--color-text);
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 10000;
            transform: translateX(100%);
            transition: transform 0.3s ease;
        `;

        if (type === 'success') {
            notification.style.borderColor = '#00C851';
        } else if (type === 'warning') {
            notification.style.borderColor = '#ffbb33';
        } else if (type === 'error') {
            notification.style.borderColor = '#ff4444';
        }

        notification.textContent = message;
        document.body.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Auto remove after 3 seconds
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
}

// Initialize the system when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new VoIPTracingSystem();
});