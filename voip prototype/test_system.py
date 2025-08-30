#!/usr/bin/env python3
"""
System Verification and Test Script
Validates all components of the VoIP Tracing System
"""

import sys
import os
import json
import time
from datetime import datetime

def test_imports():
    """Test if all required modules can be imported"""
    print("🔍 Testing imports...")

    try:
        import pandas as pd
        print("  ✅ pandas")
    except ImportError:
        print("  ❌ pandas - Install: pip install pandas")
        return False

    try:
        import numpy as np
        print("  ✅ numpy")
    except ImportError:
        print("  ❌ numpy - Install: pip install numpy")
        return False

    try:
        from scapy.all import *
        print("  ✅ scapy")
    except ImportError:
        print("  ❌ scapy - Install: pip install scapy")
        return False

    try:
        from sklearn.ensemble import IsolationForest
        print("  ✅ scikit-learn")
    except ImportError:
        print("  ❌ scikit-learn - Install: pip install scikit-learn")
        return False

    try:
        import dash
        from dash import dcc, html
        import plotly.graph_objs as go
        print("  ✅ dash/plotly")
    except ImportError:
        print("  ❌ dash/plotly - Install: pip install dash plotly")
        return False

    print("  ✅ All imports successful!")
    return True

def test_core_modules():
    """Test core system modules"""
    print("\n🧪 Testing core modules...")

    try:
        from voip_analyzer import VoIPAnalyzer
        analyzer = VoIPAnalyzer()
        print("  ✅ VoIPAnalyzer initialized")
    except Exception as e:
        print(f"  ❌ VoIPAnalyzer error: {e}")
        return False

    try:
        from anomaly_detector import VoIPAnomalyDetector
        detector = VoIPAnomalyDetector()
        print("  ✅ VoIPAnomalyDetector initialized")
    except Exception as e:
        print(f"  ❌ VoIPAnomalyDetector error: {e}")
        return False

    try:
        from voip_simulator import VoIPTrafficSimulator
        simulator = VoIPTrafficSimulator()
        print("  ✅ VoIPTrafficSimulator initialized")
    except Exception as e:
        print(f"  ❌ VoIPTrafficSimulator error: {e}")
        return False

    print("  ✅ All core modules working!")
    return True

def test_data_generation():
    """Test data generation and processing"""
    print("\n📊 Testing data generation...")

    try:
        from voip_simulator import VoIPTrafficSimulator
        simulator = VoIPTrafficSimulator()

        # Test metadata generation
        simulator.create_test_metadata("test_verify.json", 50)
        if os.path.exists("test_verify.json"):
            with open("test_verify.json", 'r') as f:
                data = json.load(f)
            print(f"  ✅ Generated {len(data)} test metadata entries")
            os.remove("test_verify.json")  # Cleanup
        else:
            print("  ❌ Failed to create test metadata")
            return False

    except Exception as e:
        print(f"  ❌ Data generation error: {e}")
        return False

    return True

def test_analysis_pipeline():
    """Test the complete analysis pipeline"""
    print("\n🔬 Testing analysis pipeline...")

    try:
        from voip_analyzer import VoIPAnalyzer
        from anomaly_detector import VoIPAnomalyDetector
        from voip_simulator import VoIPTrafficSimulator

        # Generate test data
        simulator = VoIPTrafficSimulator()
        simulator.create_test_metadata("pipeline_test.json", 100)

        # Load into analyzer
        with open("pipeline_test.json", 'r') as f:
            test_metadata = json.load(f)

        analyzer = VoIPAnalyzer()
        analyzer.call_metadata = test_metadata

        # Test basic statistics
        stats = analyzer.get_call_statistics()
        print(f"  ✅ Basic statistics: {len(stats)} metrics")

        # Test dataframe conversion
        df = analyzer.get_metadata_dataframe()
        print(f"  ✅ DataFrame conversion: {len(df)} rows")

        # Test ML analysis
        detector = VoIPAnomalyDetector()
        features_df = detector.extract_features(df)

        if not features_df.empty and len(features_df) >= 3:
            detector.train_models(features_df)
            anomalies = detector.detect_anomalies(features_df)
            print(f"  ✅ ML analysis: {len(anomalies)} analyzed entities")
        else:
            print("  ⚠️  ML analysis: Limited data for full ML test")

        # Cleanup
        os.remove("pipeline_test.json")

        print("  ✅ Analysis pipeline working!")
        return True

    except Exception as e:
        print(f"  ❌ Analysis pipeline error: {e}")
        return False

def test_dashboard_components():
    """Test dashboard components without running server"""
    print("\n🌐 Testing dashboard components...")

    try:
        from dashboard import VoIPDashboard
        dashboard = VoIPDashboard()
        print("  ✅ Dashboard initialization")

        # Test layout components
        layout = dashboard.app.layout
        print("  ✅ Dashboard layout")

        print("  ✅ Dashboard components working!")
        return True

    except Exception as e:
        print(f"  ❌ Dashboard error: {e}")
        return False

def run_complete_test():
    """Run a complete end-to-end test"""
    print("\n🚀 Running complete system test...")

    try:
        from main import VoIPTracingSystem
        system = VoIPTracingSystem()

        # Test simulation mode
        print("  🔄 Testing simulation mode...")
        system.simulate_mode(duration=1)  # 1 minute simulation

        # Check if files were created
        files_created = 0
        if os.path.exists("test_traffic.pcap"):
            files_created += 1
            print("  ✅ PCAP file generated")

        if os.path.exists("test_metadata.json"):
            files_created += 1
            print("  ✅ Metadata file generated")

        # Check for report files
        for filename in os.listdir("."):
            if filename.startswith("voip_analysis_report_"):
                files_created += 1
                print(f"  ✅ Analysis report: {filename}")
                break

        if files_created >= 2:
            print("  ✅ Complete system test passed!")
            return True
        else:
            print(f"  ❌ Complete system test failed - only {files_created} files created")
            return False

    except Exception as e:
        print(f"  ❌ Complete system test error: {e}")
        return False

def main():
    """Main test runner"""
    print("=" * 60)
    print("VoIP TRACING SYSTEM - VERIFICATION TEST")
    print("=" * 60)
    print(f"Test started at: {datetime.now()}")
    print()

    tests = [
        ("Import Test", test_imports),
        ("Core Modules Test", test_core_modules), 
        ("Data Generation Test", test_data_generation),
        ("Analysis Pipeline Test", test_analysis_pipeline),
        ("Dashboard Components Test", test_dashboard_components),
        ("Complete System Test", run_complete_test),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"  ❌ {test_name} crashed: {e}")
            results.append((test_name, False))

        time.sleep(1)  # Brief pause between tests

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = 0
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1

    print(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 ALL TESTS PASSED! System is ready for demonstration.")
        print("\n📋 Next Steps:")
        print("   1. Run: python main.py --mode simulate")
        print("   2. Run: python main.py --mode dashboard")
        print("   3. Demo the system!")
    else:
        print(f"\n⚠️  {total - passed} tests failed. Check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("   1. Install missing dependencies: pip install -r requirements.txt")
        print("   2. Check file permissions")
        print("   3. Verify Python version (3.7+ required)")

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
