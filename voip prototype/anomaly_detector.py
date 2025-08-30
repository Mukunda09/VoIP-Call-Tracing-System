
"""
Machine Learning Module for VoIP Anomaly Detection
Advanced pattern recognition and suspicious activity detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from datetime import datetime, timedelta
import joblib
import warnings
warnings.filterwarnings('ignore')

class VoIPAnomalyDetector:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        self.trained = False
        self.feature_columns = []

        # Behavioral patterns
        self.call_patterns = {}
        self.ip_reputation = {}

    def extract_features(self, metadata_df):
        """Extract features from VoIP metadata for ML analysis"""
        if metadata_df.empty:
            return pd.DataFrame()

        features_list = []

        # Group by source IP for behavioral analysis
        for src_ip in metadata_df['src_ip'].unique():
            ip_data = metadata_df[metadata_df['src_ip'] == src_ip].copy()

            if len(ip_data) < 2:  # Need at least 2 records for meaningful features
                continue

            # Temporal features
            ip_data['timestamp'] = pd.to_datetime(ip_data['timestamp'])
            ip_data = ip_data.sort_values('timestamp')

            # Calculate time differences
            time_diffs = ip_data['timestamp'].diff().dt.total_seconds().fillna(0)

            # Basic statistics
            features = {
                'src_ip': src_ip,
                'total_packets': len(ip_data),
                'unique_destinations': ip_data['dst_ip'].nunique(),
                'avg_time_between_packets': time_diffs.mean(),
                'std_time_between_packets': time_diffs.std() if len(time_diffs) > 1 else 0,
                'min_time_between_packets': time_diffs.min(),
                'max_time_between_packets': time_diffs.max(),
                'suspicious_count': ip_data['suspicious'].sum() if 'suspicious' in ip_data.columns else 0,
            }

            # Protocol distribution features
            protocol_counts = ip_data['type'].value_counts()
            features['sip_ratio'] = protocol_counts.get('SIP', 0) / len(ip_data)
            features['rtp_ratio'] = protocol_counts.get('RTP', 0) / len(ip_data)

            # Method distribution for SIP packets
            sip_data = ip_data[ip_data['type'] == 'SIP']
            if not sip_data.empty and 'method' in sip_data.columns:
                method_counts = sip_data['method'].value_counts()
                features['invite_ratio'] = method_counts.get('INVITE', 0) / len(sip_data)
                features['register_ratio'] = method_counts.get('REGISTER', 0) / len(sip_data)
                features['bye_ratio'] = method_counts.get('BYE', 0) / len(sip_data)
            else:
                features['invite_ratio'] = 0
                features['register_ratio'] = 0
                features['bye_ratio'] = 0

            # Time-based features
            time_span = (ip_data['timestamp'].max() - ip_data['timestamp'].min()).total_seconds()
            features['activity_duration'] = time_span
            features['packets_per_minute'] = len(ip_data) / (time_span / 60) if time_span > 0 else 0

            # Hour of day analysis
            hours = ip_data['timestamp'].dt.hour
            features['avg_hour'] = hours.mean()
            features['hour_variance'] = hours.var()

            # Destination spread
            features['avg_destinations_per_hour'] = features['unique_destinations'] / (time_span / 3600) if time_span > 0 else 0

            features_list.append(features)

        if not features_list:
            return pd.DataFrame()

        features_df = pd.DataFrame(features_list)

        # Replace infinity and NaN values
        features_df = features_df.replace([np.inf, -np.inf], np.nan)
        features_df = features_df.fillna(0)

        return features_df

    def train_models(self, features_df):
        """Train anomaly detection models"""
        if features_df.empty:
            print("No features available for training")
            return

        # Select numerical features only
        numerical_features = features_df.select_dtypes(include=[np.number]).columns.tolist()
        if 'src_ip' in numerical_features:
            numerical_features.remove('src_ip')

        self.feature_columns = numerical_features
        X = features_df[numerical_features]

        if X.empty or len(X) < 5:
            print("Insufficient data for training")
            return

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.isolation_forest.fit(X_scaled)

        # Train DBSCAN clustering
        self.dbscan.fit(X_scaled)

        self.trained = True
        print(f"Models trained on {len(X)} samples with {len(numerical_features)} features")

    def detect_anomalies(self, features_df):
        """Detect anomalies using trained models"""
        if not self.trained or features_df.empty:
            return pd.DataFrame()

        X = features_df[self.feature_columns]
        if X.empty:
            return pd.DataFrame()

        X_scaled = self.scaler.transform(X)

        # Isolation Forest predictions (-1 for anomalies, 1 for normal)
        isolation_predictions = self.isolation_forest.predict(X_scaled)
        isolation_scores = self.isolation_forest.score_samples(X_scaled)

        # DBSCAN clustering (-1 for outliers)
        cluster_labels = self.dbscan.fit_predict(X_scaled)

        # Combine results
        results = features_df.copy()
        results['isolation_anomaly'] = isolation_predictions == -1
        results['isolation_score'] = isolation_scores
        results['cluster_outlier'] = cluster_labels == -1
        results['cluster_label'] = cluster_labels

        # Combined anomaly score
        results['anomaly_score'] = (
            results['isolation_anomaly'].astype(int) * 0.6 +
            results['cluster_outlier'].astype(int) * 0.4
        )

        return results

    def analyze_call_patterns(self, metadata_df):
        """Analyze calling patterns for behavioral detection"""
        patterns = []

        if metadata_df.empty:
            return patterns

        # Group by source IP
        for src_ip in metadata_df['src_ip'].unique():
            ip_data = metadata_df[metadata_df['src_ip'] == src_ip].copy()

            if len(ip_data) < 3:
                continue

            ip_data['timestamp'] = pd.to_datetime(ip_data['timestamp'])
            ip_data = ip_data.sort_values('timestamp')

            # Detect rapid-fire calling
            time_diffs = ip_data['timestamp'].diff().dt.total_seconds()
            rapid_calls = (time_diffs < 5).sum()  # Calls within 5 seconds

            if rapid_calls > 5:
                patterns.append({
                    'pattern_type': 'Rapid Calling',
                    'src_ip': src_ip,
                    'severity': 'HIGH',
                    'description': f'{rapid_calls} calls within 5-second intervals',
                    'timestamp': datetime.now()
                })

            # Detect unusual time patterns
            hours = ip_data['timestamp'].dt.hour
            night_calls = ((hours >= 22) | (hours <= 6)).sum()

            if night_calls > len(ip_data) * 0.7:  # More than 70% night calls
                patterns.append({
                    'pattern_type': 'Unusual Time Pattern',
                    'src_ip': src_ip,
                    'severity': 'MEDIUM',
                    'description': f'{night_calls} out of {len(ip_data)} calls during night hours',
                    'timestamp': datetime.now()
                })

            # Detect geographic anomalies (simplified)
            unique_destinations = ip_data['dst_ip'].nunique()
            if unique_destinations > 20:  # Too many different destinations
                patterns.append({
                    'pattern_type': 'Geographic Spread',
                    'src_ip': src_ip,
                    'severity': 'MEDIUM',
                    'description': f'Contacted {unique_destinations} different destinations',
                    'timestamp': datetime.now()
                })

        return patterns

    def update_ip_reputation(self, src_ip, behavior_type, severity):
        """Update IP reputation based on behavior"""
        if src_ip not in self.ip_reputation:
            self.ip_reputation[src_ip] = {
                'reputation_score': 100,  # Start with good reputation
                'incidents': [],
                'first_seen': datetime.now(),
                'last_activity': datetime.now()
            }

        # Decrease reputation based on severity
        severity_penalties = {'LOW': -5, 'MEDIUM': -15, 'HIGH': -30}
        penalty = severity_penalties.get(severity, -10)

        self.ip_reputation[src_ip]['reputation_score'] += penalty
        self.ip_reputation[src_ip]['reputation_score'] = max(0, self.ip_reputation[src_ip]['reputation_score'])

        self.ip_reputation[src_ip]['incidents'].append({
            'type': behavior_type,
            'severity': severity,
            'timestamp': datetime.now()
        })

        self.ip_reputation[src_ip]['last_activity'] = datetime.now()

    def get_risk_assessment(self, src_ip):
        """Get risk assessment for an IP address"""
        if src_ip not in self.ip_reputation:
            return {'risk_level': 'UNKNOWN', 'score': 50, 'details': 'No historical data'}

        info = self.ip_reputation[src_ip]
        score = info['reputation_score']

        if score >= 80:
            risk_level = 'LOW'
        elif score >= 50:
            risk_level = 'MEDIUM'
        elif score >= 20:
            risk_level = 'HIGH'
        else:
            risk_level = 'CRITICAL'

        return {
            'risk_level': risk_level,
            'score': score,
            'incident_count': len(info['incidents']),
            'first_seen': info['first_seen'],
            'last_activity': info['last_activity'],
            'details': f"Based on {len(info['incidents'])} incidents"
        }

    def save_models(self, filepath):
        """Save trained models to disk"""
        if not self.trained:
            print("No trained models to save")
            return

        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'ip_reputation': self.ip_reputation
        }

        joblib.dump(model_data, filepath)
        print(f"Models saved to {filepath}")

    def load_models(self, filepath):
        """Load trained models from disk"""
        try:
            model_data = joblib.load(filepath)
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.feature_columns = model_data['feature_columns']
            self.ip_reputation = model_data.get('ip_reputation', {})
            self.trained = True
            print(f"Models loaded from {filepath}")
        except Exception as e:
            print(f"Error loading models: {e}")

    def generate_report(self, metadata_df):
        """Generate comprehensive anomaly detection report"""
        report = {
            'timestamp': datetime.now(),
            'total_records': len(metadata_df) if not metadata_df.empty else 0,
            'anomalies': [],
            'patterns': [],
            'high_risk_ips': [],
            'summary': {}
        }

        if metadata_df.empty:
            report['summary']['status'] = 'No data available'
            return report

        # Extract features and detect anomalies
        features_df = self.extract_features(metadata_df)

        if not features_df.empty and self.trained:
            anomaly_results = self.detect_anomalies(features_df)

            # Identify high-score anomalies
            high_anomalies = anomaly_results[anomaly_results['anomaly_score'] > 0.5]
            report['anomalies'] = high_anomalies.to_dict('records')

        # Analyze behavioral patterns
        patterns = self.analyze_call_patterns(metadata_df)
        report['patterns'] = patterns

        # Update IP reputation based on findings
        for pattern in patterns:
            self.update_ip_reputation(
                pattern['src_ip'], 
                pattern['pattern_type'], 
                pattern['severity']
            )

        # Identify high-risk IPs
        high_risk_ips = []
        for ip, info in self.ip_reputation.items():
            risk = self.get_risk_assessment(ip)
            if risk['risk_level'] in ['HIGH', 'CRITICAL']:
                high_risk_ips.append({
                    'ip': ip,
                    'risk_level': risk['risk_level'],
                    'score': risk['score'],
                    'incident_count': risk['incident_count']
                })

        report['high_risk_ips'] = sorted(high_risk_ips, key=lambda x: x['score'])

        # Summary statistics
        report['summary'] = {
            'total_anomalies': len(report['anomalies']),
            'behavioral_patterns': len(report['patterns']),
            'high_risk_ips': len(report['high_risk_ips']),
            'status': 'Analysis complete'
        }

        return report

# Example usage and testing
if __name__ == "__main__":
    detector = VoIPAnomalyDetector()
    print("VoIP Anomaly Detector initialized successfully!")
    print("Use detector.extract_features() and detector.train_models() to begin analysis")
