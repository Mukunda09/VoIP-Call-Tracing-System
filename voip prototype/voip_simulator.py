
"""
VoIP Traffic Simulator
Generates synthetic VoIP traffic patterns for testing and demonstration
"""

import random
import time
import threading
from datetime import datetime, timedelta
import json
from scapy.all import *

class VoIPTrafficSimulator:
    def __init__(self):
        self.running = False
        self.legitimate_ips = [
            "192.168.1.10", "192.168.1.20", "192.168.1.30",
            "10.0.0.10", "10.0.0.20", "172.16.0.10"
        ]
        self.suspicious_ips = [
            "192.168.1.100", "10.0.0.50", "172.16.1.200",
            "203.0.113.15", "198.51.100.25"
        ]
        self.sip_methods = ['INVITE', 'BYE', 'REGISTER', 'OPTIONS', 'ACK']
        self.user_agents = [
            'Asterisk PBX 18.0.0',
            'FreeSWITCH-mod_sofia/1.10.0',
            'SIP.js/0.15.0',
            'Linphone/4.2.0',
            'MaliciousBot/1.0'
        ]

    def generate_sip_packet(self, src_ip, dst_ip, method='INVITE', suspicious=False):
        """Generate a synthetic SIP packet"""
        call_id = f"call-{random.randint(1000, 9999)}@{src_ip}"
        user_agent = random.choice(self.user_agents)

        if suspicious and method == 'REGISTER':
            # Make suspicious registration attempts
            user_agent = 'MaliciousBot/1.0'

        sip_payload = f"""{method} sip:{dst_ip} SIP/2.0
Via: SIP/2.0/UDP {src_ip}:5060;branch=z9hG4bK{random.randint(100000, 999999)}
From: <sip:{src_ip}>
To: <sip:{dst_ip}>
Call-ID: {call_id}
CSeq: 1 {method}
User-Agent: {user_agent}
Content-Length: 0

"""

        # Create packet
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=5060, dport=5060) / Raw(load=sip_payload)
        return packet

    def generate_rtp_packet(self, src_ip, dst_ip, src_port=None, dst_port=None):
        """Generate a synthetic RTP packet"""
        if not src_port:
            src_port = random.randint(16384, 32767)
        if not dst_port:
            dst_port = random.randint(16384, 32767)

        # Simple RTP-like payload
        rtp_payload = b'\x80\x00' + random.randbytes(158)  # Typical RTP packet size

        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=rtp_payload)
        return packet

    def simulate_normal_call(self, src_ip, dst_ip):
        """Simulate a normal VoIP call sequence"""
        packets = []

        # SIP INVITE
        packets.append(self.generate_sip_packet(src_ip, dst_ip, 'INVITE'))
        time.sleep(0.1)

        # SIP Response (simulated)
        packets.append(self.generate_sip_packet(dst_ip, src_ip, 'ACK'))
        time.sleep(0.2)

        # RTP stream (simulate 10 seconds of voice)
        rtp_src_port = random.randint(16384, 32767)
        rtp_dst_port = random.randint(16384, 32767)

        for _ in range(500):  # ~10 seconds at 50 packets/second
            if not self.running:
                break
            packets.append(self.generate_rtp_packet(src_ip, dst_ip, rtp_src_port, rtp_dst_port))
            packets.append(self.generate_rtp_packet(dst_ip, src_ip, rtp_dst_port, rtp_src_port))
            time.sleep(0.02)  # 20ms between packets

        # SIP BYE
        packets.append(self.generate_sip_packet(src_ip, dst_ip, 'BYE'))

        return packets

    def simulate_suspicious_activity(self, src_ip):
        """Simulate suspicious VoIP activity"""
        packets = []

        # Rapid REGISTER attempts (potential brute force)
        for _ in range(20):
            if not self.running:
                break
            dst_ip = random.choice(self.legitimate_ips)
            packets.append(self.generate_sip_packet(src_ip, dst_ip, 'REGISTER', suspicious=True))
            time.sleep(0.05)  # Very rapid attempts

        # Multiple INVITE floods
        for _ in range(50):
            if not self.running:
                break
            dst_ip = random.choice(self.legitimate_ips)
            packets.append(self.generate_sip_packet(src_ip, dst_ip, 'INVITE', suspicious=True))
            time.sleep(0.02)

        return packets

    def start_simulation(self, duration_minutes=5, interface="lo"):
        """Start traffic simulation"""
        self.running = True
        print(f"Starting VoIP traffic simulation for {duration_minutes} minutes...")

        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)

        # Simulation thread
        def simulation_worker():
            while self.running and time.time() < end_time:
                try:
                    # Generate normal calls (80% of traffic)
                    if random.random() < 0.8:
                        src_ip = random.choice(self.legitimate_ips)
                        dst_ip = random.choice([ip for ip in self.legitimate_ips if ip != src_ip])

                        # Simulate call in background thread
                        call_thread = threading.Thread(
                            target=self.simulate_normal_call,
                            args=(src_ip, dst_ip)
                        )
                        call_thread.daemon = True
                        call_thread.start()

                    # Generate suspicious activity (20% of traffic)
                    else:
                        src_ip = random.choice(self.suspicious_ips)
                        suspicious_thread = threading.Thread(
                            target=self.simulate_suspicious_activity,
                            args=(src_ip,)
                        )
                        suspicious_thread.daemon = True
                        suspicious_thread.start()

                    # Wait before next activity
                    time.sleep(random.uniform(1, 5))

                except Exception as e:
                    print(f"Simulation error: {e}")

        # Start simulation
        sim_thread = threading.Thread(target=simulation_worker)
        sim_thread.daemon = True
        sim_thread.start()

        print("Simulation started! Traffic is being generated...")
        print("Note: This generates synthetic packets for testing purposes only")

    def stop_simulation(self):
        """Stop traffic simulation"""
        self.running = False
        print("Traffic simulation stopped")

    def generate_pcap_file(self, filename="voip_test_traffic.pcap", packet_count=1000):
        """Generate a PCAP file with synthetic VoIP traffic for testing"""
        packets = []

        print(f"Generating {packet_count} synthetic packets...")

        for i in range(packet_count):
            if i % 100 == 0:
                print(f"Generated {i} packets...")

            # 70% normal traffic, 30% suspicious
            if random.random() < 0.7:
                src_ip = random.choice(self.legitimate_ips)
                dst_ip = random.choice([ip for ip in self.legitimate_ips if ip != src_ip])

                # Mix of SIP and RTP
                if random.random() < 0.3:  # 30% SIP
                    method = random.choice(self.sip_methods)
                    packet = self.generate_sip_packet(src_ip, dst_ip, method)
                else:  # 70% RTP
                    packet = self.generate_rtp_packet(src_ip, dst_ip)

            else:  # Suspicious traffic
                src_ip = random.choice(self.suspicious_ips)
                dst_ip = random.choice(self.legitimate_ips)

                # Mostly REGISTER and INVITE attempts
                method = random.choice(['REGISTER', 'INVITE', 'INVITE'])
                packet = self.generate_sip_packet(src_ip, dst_ip, method, suspicious=True)

            packets.append(packet)

        # Write to PCAP file
        wrpcap(filename, packets)
        print(f"Generated PCAP file: {filename}")
        print(f"Contains {len(packets)} packets for testing")

    def create_test_metadata(self, filename="test_metadata.json", entry_count=500):
        """Create test metadata in the same format as the analyzer"""
        metadata = []

        print(f"Creating {entry_count} metadata entries...")

        base_time = datetime.now() - timedelta(hours=2)

        for i in range(entry_count):
            timestamp = base_time + timedelta(seconds=random.randint(0, 7200))  # 2 hours spread

            # 70% normal, 30% suspicious
            if random.random() < 0.7:
                src_ip = random.choice(self.legitimate_ips)
                dst_ip = random.choice([ip for ip in self.legitimate_ips if ip != src_ip])
                suspicious = False
            else:
                src_ip = random.choice(self.suspicious_ips)
                dst_ip = random.choice(self.legitimate_ips)
                suspicious = True

            # Mix of SIP and RTP
            if random.random() < 0.4:  # 40% SIP
                entry = {
                    'timestamp': timestamp.isoformat(),
                    'type': 'SIP',
                    'method': random.choice(self.sip_methods),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'call_id': f"call-{random.randint(1000, 9999)}@{src_ip}",
                    'user_agent': random.choice(self.user_agents),
                    'suspicious': suspicious
                }
            else:  # 60% RTP
                entry = {
                    'timestamp': timestamp.isoformat(),
                    'type': 'RTP',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': random.randint(16384, 32767),
                    'dst_port': random.randint(16384, 32767),
                    'stream_key': f"{src_ip}:{random.randint(16384, 32767)}-{dst_ip}:{random.randint(16384, 32767)}",
                    'suspicious': suspicious
                }

            metadata.append(entry)

        # Save to file
        with open(filename, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"Created test metadata file: {filename}")
        print(f"Contains {len(metadata)} entries for testing")

# Example usage
if __name__ == "__main__":
    simulator = VoIPTrafficSimulator()

    print("VoIP Traffic Simulator")
    print("1. Generate PCAP file for testing")
    print("2. Generate test metadata")
    print("3. Start live simulation")

    choice = input("Enter choice (1-3): ").strip()

    if choice == "1":
        simulator.generate_pcap_file()
    elif choice == "2":
        simulator.create_test_metadata()
    elif choice == "3":
        duration = int(input("Simulation duration in minutes (default 5): ") or "5")
        simulator.start_simulation(duration)
        try:
            time.sleep(duration * 60)
        except KeyboardInterrupt:
            print("\nStopping simulation...")
        simulator.stop_simulation()
    else:
        print("Invalid choice")
