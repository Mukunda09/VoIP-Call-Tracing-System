# VoIP Call Tracing System for Law Enforcement

## 🚀 Quick Start Guide 

### Overview
This system analyzes VoIP network traffic to trace calls, extract metadata, and identify suspicious activities for law enforcement purposes. It works with both encrypted and unencrypted VoIP traffic by analyzing signaling protocols (SIP) and media streams (RTP).

### ⚡ Setup 

#### 1. Install Dependencies (2 minutes)
```bash
# Install Python packages
pip install -r requirements.txt

# Or install manually:
pip install scapy flask pandas numpy plotly dash scikit-learn requests python-nmap cryptography psutil
```

#### 2. Test with Simulated Data (3 minutes)
```bash
# Generate test data and run analysis
python main.py --mode simulate --duration 5

# This will:
# - Create synthetic VoIP traffic data
# - Run complete analysis including ML anomaly detection
# - Generate comprehensive reports
```

#### 3. Launch Web Dashboard (2 minutes)
```bash
# Start the monitoring dashboard
python main.py --mode dashboard --port 8050

# Open browser to: http://localhost:8050
# Click "Start Capture" to begin monitoring
```

#### 4. View Results (3 minutes)
- Check generated files: `voip_analysis_report_*.json` and `voip_raw_data_*.json`
- Review suspicious activities in the dashboard
- Examine ML anomaly detection results

---

## 🎯 Core Features Implemented

### 1. VoIP Protocol Analysis
- **SIP Signaling Detection**: Identifies INVITE, BYE, REGISTER, OPTIONS, ACK messages
- **RTP Stream Analysis**: Detects and correlates media streams
- **Metadata Extraction**: Call duration, endpoints, user agents, timing patterns
- **Encrypted Traffic Handling**: Analyzes metadata even when content is encrypted

### 2. Deep Packet Inspection (DPI)
- Real-time packet capture using Scapy
- Protocol-aware filtering and analysis
- Flow correlation between SIP signaling and RTP media
- Heuristic-based encrypted traffic classification

### 3. Machine Learning Anomaly Detection
- **Isolation Forest**: Detects unusual calling patterns
- **DBSCAN Clustering**: Identifies outlier behaviors
- **Feature Engineering**: 15+ behavioral features per IP address
- **Pattern Recognition**: Rapid calling, unusual timing, geographic spread

### 4. Real-Time Monitoring Dashboard
- Live traffic visualization
- Suspicious activity alerts
- Protocol distribution charts
- IP activity heatmaps
- Comprehensive data tables

### 5. Behavioral Analysis
- Call frequency analysis
- Time-based pattern detection
- Multi-destination correlation
- IP reputation scoring
- Automated threat assessment

---

## 📊 System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Packet        │    │   VoIP           │    │   Machine       │
│   Capture       ├────┤   Analyzer       ├────┤   Learning      │
│   (Scapy)       │    │   (SIP/RTP)      │    │   (Anomaly)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         │                        │                        │
         └──────────────────────────────┬───────────────────┘
                                        │
                                        ▼
                                ┌─────────────────┐
                                │   Web Dashboard │
                                │   (Flask/Dash)  │
                                └─────────────────┘
```

---

## 🔧 Detailed Setup Instructions

### Environment Requirements
- **OS**: Linux (recommended), Windows, macOS
- **Python**: 3.7+
- **Privileges**: Administrator/sudo for packet capture
- **Memory**: 4GB+ recommended
- **Network**: Access to network interface for live capture

### Installation Steps

1. **Clone/Download Files**
   ```bash
   # All files should be in the same directory:
   - main.py
   - voip_analyzer.py
   - dashboard.py
   - anomaly_detector.py
   - voip_simulator.py
   - requirements.txt
   ```

2. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Platform-Specific Setup**

   **Linux:**
   ```bash
   # Install libpcap development files
   sudo apt-get install libpcap-dev  # Ubuntu/Debian
   # or
   sudo yum install libpcap-devel    # CentOS/RHEL
   ```

   **Windows:**
   ```bash
   # Install Npcap (WinPcap replacement)
   # Download from: https://nmap.org/npcap/
   # Run as Administrator
   ```

   **macOS:**
   ```bash
   # Install via Homebrew
   brew install libpcap
   ```

---

## 🎮 Usage Examples

### 1. Live Traffic Capture
```bash
# Capture on all interfaces for 10 minutes
python main.py --mode capture --duration 600

# Capture on specific interface
python main.py --mode capture --interface eth0 --duration 300
```

### 2. Simulation Mode (Best for Demo)
```bash
# Generate synthetic VoIP traffic and analyze
python main.py --mode simulate --duration 10

# This creates:
# - test_traffic.pcap (PCAP file)
# - test_metadata.json (Metadata)
# - Analysis reports
```

### 3. Analysis Mode
```bash
# Analyze existing data file
python main.py --mode analyze --data test_metadata.json

# Analyze current capture data
python main.py --mode analyze
```

### 4. Dashboard Mode
```bash
# Launch web dashboard on port 8050
python main.py --mode dashboard

# Custom port
python main.py --mode dashboard --port 9000
```

---

## 📈 Understanding the Results

### Suspicious Activity Detection
The system flags activities as suspicious based on:
- **Blacklisted IPs**: Known malicious addresses
- **Rapid Requests**: Multiple calls in short time
- **Unusual Patterns**: Night calls, geographic spread
- **Protocol Anomalies**: Malformed or unexpected packets

### Machine Learning Features
The ML system analyzes 15+ features per IP:
- Total packets and unique destinations
- Time patterns (gaps, frequency, duration)
- Protocol distribution (SIP vs RTP ratios)
- Method distribution (INVITE, REGISTER, etc.)
- Geographic and temporal anomalies

### Report Contents
Generated reports include:
- **metadata**: Raw packet information
- **sessions**: Active SIP call sessions  
- **rtp_streams**: Media stream data
- **suspicious_activity**: Flagged behaviors
- **statistics**: Aggregated metrics
- **anomalies**: ML-detected outliers
- **patterns**: Behavioral analysis results

---

## 🔒 Privacy and Legal Compliance

### Data Protection
- System focuses on **metadata only** (no voice content)
- Implements **privacy-by-design** principles
- Supports **data retention policies**
- Provides **audit trails** for all activities

### Legal Considerations
- **Authorization Required**: Only for authorized law enforcement use
- **Jurisdiction Compliance**: Follow local surveillance laws
- **Data Handling**: Secure storage and transmission
- **Documentation**: Maintain proper investigation records

### Compliance Features
- GDPR-compliant metadata handling
- HIPAA considerations for healthcare VoIP
- SOX compliance for financial communications
- Customizable privacy settings

---

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied (Packet Capture)**
   ```bash
   # Run with administrator privileges
   sudo python main.py --mode capture
   ```

2. **No Packets Captured**
   - Check network interface name
   - Verify interface is active
   - Try different interface (eth0, wlan0, etc.)

3. **Dashboard Not Loading**
   - Check port availability
   - Verify all dependencies installed
   - Try different port number

4. **Import Errors**
   ```bash
   # Reinstall dependencies
   pip install --upgrade -r requirements.txt
   ```

5. **Low Detection Rates**
   - Increase capture duration
   - Check network traffic volume
   - Use simulation mode for testing

---

