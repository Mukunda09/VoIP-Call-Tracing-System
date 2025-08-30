
#!/usr/bin/env python3
"""
VoIP Call Tracing System - Main Application
Law Enforcement VoIP Surveillance and Analysis Tool

Usage:
    python main.py --mode [capture|analyze|simulate|dashboard]
"""

import argparse
import sys
import os
import time
import json
from datetime import datetime
import threading

# Import our modules
try:
    from voip_analyzer import VoIPAnalyzer
    from anomaly_detector import VoIPAnomalyDetector
    from voip_simulator import VoIPTrafficSimulator
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all required files are in the same directory")
    sys.exit(1)

class VoIPTracingSystem:
    def __init__(self):
        self.analyzer = VoIPAnalyzer()
        self.ml_detector = VoIPAnomalyDetector()
        self.simulator = VoIPTrafficSimulator()

    def capture_mode(self, interface="any", duration=300):
        """Capture and analyze VoIP traffic"""
        print("="*60)
        print("VoIP TRAFFIC CAPTURE MODE")
        print("="*60)
        print(f"Interface: {interface}")
        print(f"Duration: {duration} seconds")
        print()

        try:
            # Start capture
            print("Starting packet capture...")
            print("Note: This requires administrator privileges")
            self.analyzer.start_capture(interface)

            print("Capture started! Press Ctrl+C to stop early")
            start_time = time.time()

            try:
                while (time.time() - start_time) < duration:
                    time.sleep(5)
                    stats = self.analyzer.get_call_statistics()
                    suspicious = len(self.analyzer.get_suspicious_activity())

                    print(f"\rElapsed: {int(time.time() - start_time)}s | "
                          f"Total packets: {sum(stats.values())} | "
                          f"Suspicious: {suspicious}", end="")

            except KeyboardInterrupt:
                print("\nStopping capture...")

            self.analyzer.stop_capture()
            print("\nCapture completed!")

            # Analyze results
            self.show_analysis_results()

        except Exception as e:
            print(f"Capture error: {e}")
            print("Make sure you're running with administrator privileges")

    def analyze_mode(self, data_file=None):
        """Analyze existing VoIP data"""
        print("="*60)
        print("VoIP TRAFFIC ANALYSIS MODE")
        print("="*60)

        if data_file and os.path.exists(data_file):
            print(f"Loading data from: {data_file}")
            # Load existing metadata
            with open(data_file, 'r') as f:
                metadata = json.load(f)
            self.analyzer.call_metadata = metadata
        else:
            print("Using current analyzer data")

        self.show_analysis_results()

    def simulate_mode(self, duration=5):
        """Generate simulated VoIP traffic for testing"""
        print("="*60)
        print("VoIP TRAFFIC SIMULATION MODE")
        print("="*60)
        print("Generating synthetic VoIP traffic for testing purposes")
        print(f"Duration: {duration} minutes")
        print()

        # Generate test data first
        print("1. Creating test PCAP file...")
        self.simulator.generate_pcap_file("test_traffic.pcap", 500)

        print("\n2. Creating test metadata...")
        self.simulator.create_test_metadata("test_metadata.json", 300)

        print("\n3. Loading test data into analyzer...")
        with open("test_metadata.json", 'r') as f:
            test_metadata = json.load(f)
        self.analyzer.call_metadata = test_metadata

        print("\n4. Running analysis on test data...")
        self.show_analysis_results()

    def dashboard_mode(self, port=8050):
        """Launch the web dashboard"""
        print("="*60)
        print("VoIP MONITORING DASHBOARD")
        print("="*60)

        try:
            from dashboard import VoIPDashboard
            dashboard = VoIPDashboard()
            print(f"Starting dashboard on http://localhost:{port}")
            print("Note: Dashboard requires administrator privileges for live capture")
            dashboard.run(debug=False, port=port)
        except ImportError:
            print("Dashboard dependencies not available")
            print("Install with: pip install dash plotly")
        except Exception as e:
            print(f"Dashboard error: {e}")

    def show_analysis_results(self):
        """Display comprehensive analysis results"""
        print("\n" + "="*60)
        print("ANALYSIS RESULTS")
        print("="*60)

        # Basic statistics
        stats = self.analyzer.get_call_statistics()
        sessions = self.analyzer.get_active_sessions()
        streams = self.analyzer.get_rtp_streams()
        suspicious = self.analyzer.get_suspicious_activity()

        print(f"\n📊 BASIC STATISTICS:")
        print(f"   Total SIP packets: {sum(v for k, v in stats.items() if k.startswith('sip_'))}")
        print(f"   Total RTP packets: {stats.get('rtp_packets', 0)}")
        print(f"   Active sessions: {len(sessions)}")
        print(f"   RTP streams: {len(streams)}")
        print(f"   Suspicious activities: {len(suspicious)}")

        # Show suspicious activities
        if suspicious:
            print(f"\n🚨 SUSPICIOUS ACTIVITIES:")
            for i, activity in enumerate(suspicious[-5:], 1):  # Last 5
                print(f"   {i}. {activity['type']} - {activity['src_ip']} -> {activity['dst_ip']}")
                print(f"      Reason: {activity['reason']}")
                print(f"      Time: {activity['timestamp']}")
                print()

        # Machine Learning Analysis
        metadata_df = self.analyzer.get_metadata_dataframe()
        if not metadata_df.empty:
            print("\n🤖 MACHINE LEARNING ANALYSIS:")

            # Extract features and train if enough data
            features_df = self.ml_detector.extract_features(metadata_df)

            if not features_df.empty and len(features_df) >= 5:
                print("   Training anomaly detection models...")
                self.ml_detector.train_models(features_df)

                # Detect anomalies
                anomaly_results = self.ml_detector.detect_anomalies(features_df)
                high_anomalies = anomaly_results[anomaly_results['anomaly_score'] > 0.5]

                print(f"   Anomalies detected: {len(high_anomalies)}")

                if not high_anomalies.empty:
                    print("   Top anomalous IPs:")
                    for _, row in high_anomalies.head(3).iterrows():
                        print(f"     - {row['src_ip']}: Score {row['anomaly_score']:.2f}")

            # Behavioral analysis
            patterns = self.ml_detector.analyze_call_patterns(metadata_df)
            if patterns:
                print(f"\n🎯 BEHAVIORAL PATTERNS DETECTED:")
                for pattern in patterns[-3:]:  # Last 3 patterns
                    print(f"   • {pattern['pattern_type']} ({pattern['severity']})")
                    print(f"     IP: {pattern['src_ip']}")
                    print(f"     Details: {pattern['description']}")
                    print()

        # Generate comprehensive report
        if not metadata_df.empty:
            print("\n📋 GENERATING COMPREHENSIVE REPORT...")
            report = self.ml_detector.generate_report(metadata_df)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"voip_analysis_report_{timestamp}.json"

            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            print(f"   Report saved to: {report_file}")

        # Export raw data
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_file = f"voip_raw_data_{timestamp}.json"
        self.analyzer.export_data(export_file)

        print(f"\n💾 DATA EXPORTED:")
        print(f"   Raw data: {export_file}")

        # Privacy and legal notice
        print("\n⚖️  LEGAL NOTICE:")
        print("   This tool is designed for authorized law enforcement use only.")
        print("   Ensure compliance with local privacy laws and regulations.")
        print("   All data should be handled according to legal standards.")

def main():
    parser = argparse.ArgumentParser(
        description="VoIP Call Tracing System for Law Enforcement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py --mode capture --interface eth0 --duration 600
    python main.py --mode simulate --duration 10
    python main.py --mode analyze --data test_metadata.json
    python main.py --mode dashboard --port 8080
        """
    )

    parser.add_argument('--mode', 
                       choices=['capture', 'analyze', 'simulate', 'dashboard'],
                       required=True,
                       help='Operating mode')

    parser.add_argument('--interface', 
                       default='any',
                       help='Network interface for capture (default: any)')

    parser.add_argument('--duration', 
                       type=int, 
                       default=300,
                       help='Duration in seconds for capture/simulate (default: 300)')

    parser.add_argument('--data', 
                       help='Data file for analysis mode')

    parser.add_argument('--port', 
                       type=int, 
                       default=8050,
                       help='Port for dashboard mode (default: 8050)')

    args = parser.parse_args()

    # Banner
    print("\n" + "="*60)
    print("VoIP CALL TRACING SYSTEM")
    print("Law Enforcement Surveillance Tool")
    print("="*60)

    system = VoIPTracingSystem()

    try:
        if args.mode == 'capture':
            system.capture_mode(args.interface, args.duration)
        elif args.mode == 'analyze':
            system.analyze_mode(args.data)
        elif args.mode == 'simulate':
            system.simulate_mode(args.duration)
        elif args.mode == 'dashboard':
            system.dashboard_mode(args.port)

    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
