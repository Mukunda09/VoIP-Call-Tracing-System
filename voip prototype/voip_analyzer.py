
"""
VoIP Traffic Analyzer for Law Enforcement
Core module for VoIP call tracing and analysis
"""

import time
import threading
import queue
import pandas as pd
from datetime import datetime
from collections import defaultdict, deque
import json

try:
    from scapy.all import *
except ImportError:
    print("Scapy not installed. Install using: pip install scapy")

class VoIPAnalyzer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.sip_sessions = {}
        self.rtp_streams = {}
        self.call_metadata = []
        self.suspicious_patterns = []
        self.running = False
        self.blacklisted_ips = set()
        self.call_stats = defaultdict(int)

        # Load blacklisted IPs (example data)
        self.blacklisted_ips = {
            "192.168.1.100", "10.0.0.50", "172.16.1.200"
        }

    def start_capture(self, interface="any"):
        """Start packet capture in a separate thread"""
        self.running = True
        capture_thread = threading.Thread(
            target=self._capture_packets, 
            args=(interface,)
        )
        capture_thread.daemon = True
        capture_thread.start()

        # Start analysis thread
        analysis_thread = threading.Thread(target=self._analyze_packets)
        analysis_thread.daemon = True
        analysis_thread.start()

    def stop_capture(self):
        """Stop packet capture"""
        self.running = False

    def _capture_packets(self, interface):
        """Capture packets using Scapy"""
        try:
            sniff(
                iface=interface,
                prn=self._packet_handler,
                filter="udp or tcp",
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            print(f"Capture error: {e}")

    def _packet_handler(self, packet):
        """Handle captured packets"""
        if not self.running:
            return

        try:
            self.packet_queue.put(packet, timeout=1)
        except queue.Full:
            pass  # Skip packet if queue is full

    def _analyze_packets(self):
        """Analyze packets from the queue"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Analysis error: {e}")

    def _process_packet(self, packet):
        """Process individual packets for VoIP analysis"""
        try:
            # Check for SIP packets
            if packet.haslayer(Raw) and (packet.haslayer(UDP)):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # SIP Detection
                if any(sip_method in payload for sip_method in 
                       ['INVITE', 'BYE', 'REGISTER', 'OPTIONS', 'ACK']):
                    self._analyze_sip(packet, payload)

            # Check for RTP packets (common UDP ports)
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                if self._is_likely_rtp(packet):
                    self._analyze_rtp(packet)

        except Exception as e:
            pass  # Continue processing other packets

    def _analyze_sip(self, packet, payload):
        """Analyze SIP signaling packets"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.now()

            # Extract SIP method
            sip_method = None
            for method in ['INVITE', 'BYE', 'REGISTER', 'OPTIONS', 'ACK']:
                if method in payload:
                    sip_method = method
                    break

            # Extract Call-ID
            call_id = None
            for line in payload.split('\n'):
                if line.startswith('Call-ID:'):
                    call_id = line.split(':', 1)[1].strip()
                    break

            # Extract User-Agent
            user_agent = None
            for line in payload.split('\n'):
                if line.startswith('User-Agent:'):
                    user_agent = line.split(':', 1)[1].strip()
                    break

            # Create metadata entry
            metadata = {
                'timestamp': timestamp,
                'type': 'SIP',
                'method': sip_method,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'call_id': call_id,
                'user_agent': user_agent,
                'suspicious': self._check_suspicious_sip(src_ip, dst_ip, sip_method)
            }

            self.call_metadata.append(metadata)
            self.call_stats[f'sip_{sip_method.lower()}'] += 1

            # Track sessions
            if call_id and sip_method == 'INVITE':
                self.sip_sessions[call_id] = {
                    'start_time': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'user_agent': user_agent
                }

        except Exception as e:
            print(f"SIP analysis error: {e}")

    def _analyze_rtp(self, packet):
        """Analyze RTP media packets"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            timestamp = datetime.now()

            stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

            if stream_key not in self.rtp_streams:
                self.rtp_streams[stream_key] = {
                    'start_time': timestamp,
                    'packet_count': 0,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port
                }

            self.rtp_streams[stream_key]['packet_count'] += 1
            self.rtp_streams[stream_key]['last_seen'] = timestamp

            # Create metadata entry
            metadata = {
                'timestamp': timestamp,
                'type': 'RTP',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'stream_key': stream_key,
                'suspicious': self._check_suspicious_rtp(src_ip, dst_ip)
            }

            self.call_metadata.append(metadata)
            self.call_stats['rtp_packets'] += 1

        except Exception as e:
            print(f"RTP analysis error: {e}")

    def _is_likely_rtp(self, packet):
        """Heuristic to identify RTP packets"""
        if not packet.haslayer(UDP):
            return False

        udp_layer = packet[UDP]

        # RTP typically uses even port numbers in range 1024-65535
        if udp_layer.dport >= 1024 and udp_layer.dport % 2 == 0:
            return True

        # Common RTP port ranges
        rtp_port_ranges = [(16384, 32767), (49152, 65535)]
        for start, end in rtp_port_ranges:
            if start <= udp_layer.dport <= end:
                return True

        return False

    def _check_suspicious_sip(self, src_ip, dst_ip, method):
        """Check for suspicious SIP activity"""
        suspicious = False

        # Check blacklisted IPs
        if src_ip in self.blacklisted_ips or dst_ip in self.blacklisted_ips:
            suspicious = True

        # Check for rapid INVITE attempts (potential flooding)
        recent_invites = sum(1 for m in self.call_metadata[-50:] 
                           if m.get('method') == 'INVITE' and m.get('src_ip') == src_ip)
        if recent_invites > 10:
            suspicious = True

        if suspicious:
            self.suspicious_patterns.append({
                'timestamp': datetime.now(),
                'type': 'Suspicious SIP',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'method': method,
                'reason': 'Blacklisted IP or rapid requests'
            })

        return suspicious

    def _check_suspicious_rtp(self, src_ip, dst_ip):
        """Check for suspicious RTP activity"""
        suspicious = False

        # Check blacklisted IPs
        if src_ip in self.blacklisted_ips or dst_ip in self.blacklisted_ips:
            suspicious = True

        if suspicious:
            self.suspicious_patterns.append({
                'timestamp': datetime.now(),
                'type': 'Suspicious RTP',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'reason': 'Blacklisted IP'
            })

        return suspicious

    def get_call_statistics(self):
        """Get current call statistics"""
        return dict(self.call_stats)

    def get_active_sessions(self):
        """Get currently active SIP sessions"""
        return self.sip_sessions.copy()

    def get_rtp_streams(self):
        """Get RTP stream information"""
        return self.rtp_streams.copy()

    def get_metadata_dataframe(self):
        """Get metadata as pandas DataFrame"""
        if not self.call_metadata:
            return pd.DataFrame()

        return pd.DataFrame(self.call_metadata)

    def get_suspicious_activity(self):
        """Get suspicious activity patterns"""
        return self.suspicious_patterns.copy()

    def export_data(self, filename):
        """Export collected data to JSON"""
        data = {
            'metadata': self.call_metadata,
            'sessions': self.sip_sessions,
            'rtp_streams': self.rtp_streams,
            'suspicious_activity': self.suspicious_patterns,
            'statistics': dict(self.call_stats)
        }

        # Convert datetime objects to strings for JSON serialization
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: convert_datetime(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_datetime(item) for item in obj]
            return obj

        data = convert_datetime(data)

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Data exported to {filename}")

# Example usage and testing
if __name__ == "__main__":
    analyzer = VoIPAnalyzer()
    print("VoIP Analyzer initialized successfully!")
    print("Use analyzer.start_capture() to begin packet capture")
