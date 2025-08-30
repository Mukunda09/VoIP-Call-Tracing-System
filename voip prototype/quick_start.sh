#!/bin/bash
# Quick Start Script for VoIP Tracing System

echo "VoIP Call Tracing System - Quick Start"
echo "===================================="
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7+"
    exit 1
fi

echo "✅ Python 3 found"

# Install requirements
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"
echo

# Run simulation mode
echo "🚀 Running simulation mode..."
echo "This will generate test data and run analysis"
echo

python3 main.py --mode simulate --duration 3

echo
echo "✅ Simulation completed!"
echo
echo "Generated files:"
echo "  - test_traffic.pcap (Packet capture)"
echo "  - test_metadata.json (Metadata)"  
echo "  - voip_analysis_report_*.json (Analysis report)"
echo "  - voip_raw_data_*.json (Raw data)"
echo
echo "🌐 To launch the web dashboard, run:"
echo "   python3 main.py --mode dashboard"
echo
echo "🎯 System is ready for demonstration!"
