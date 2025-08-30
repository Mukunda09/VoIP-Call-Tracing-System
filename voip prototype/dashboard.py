
"""
Real-time VoIP Monitoring Dashboard
Flask/Dash application for law enforcement VoIP surveillance
"""

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import json
from datetime import datetime, timedelta
import threading
import time
from voip_analyzer import VoIPAnalyzer

class VoIPDashboard:
    def __init__(self):
        self.analyzer = VoIPAnalyzer()
        self.app = dash.Dash(__name__)
        self.setup_layout()
        self.setup_callbacks()
        self.data_update_thread = None

    def setup_layout(self):
        """Setup the dashboard layout"""
        self.app.layout = html.Div([
            html.H1("VoIP Traffic Analysis Dashboard", 
                   style={'textAlign': 'center', 'color': '#2c3e50', 'marginBottom': 30}),

            # Control Panel
            html.Div([
                html.Button('Start Capture', id='start-btn', n_clicks=0, 
                           className='btn btn-success', 
                           style={'margin': '10px', 'padding': '10px 20px'}),
                html.Button('Stop Capture', id='stop-btn', n_clicks=0,
                           className='btn btn-danger',
                           style={'margin': '10px', 'padding': '10px 20px'}),
                html.Button('Export Data', id='export-btn', n_clicks=0,
                           className='btn btn-info',
                           style={'margin': '10px', 'padding': '10px 20px'}),
            ], style={'textAlign': 'center', 'marginBottom': 30}),

            # Status indicator
            html.Div(id='status-indicator', style={'textAlign': 'center', 'marginBottom': 20}),

            # Statistics Cards
            html.Div([
                html.Div([
                    html.H4("Total SIP Sessions"),
                    html.H2(id='total-sip', children="0")
                ], className='stat-card', style={'width': '24%', 'display': 'inline-block', 
                                               'textAlign': 'center', 'backgroundColor': '#3498db',
                                               'color': 'white', 'padding': '20px', 'margin': '0.5%',
                                               'borderRadius': '10px'}),

                html.Div([
                    html.H4("Active RTP Streams"),
                    html.H2(id='active-rtp', children="0")
                ], className='stat-card', style={'width': '24%', 'display': 'inline-block',
                                               'textAlign': 'center', 'backgroundColor': '#2ecc71',
                                               'color': 'white', 'padding': '20px', 'margin': '0.5%',
                                               'borderRadius': '10px'}),

                html.Div([
                    html.H4("Suspicious Activities"),
                    html.H2(id='suspicious-count', children="0")
                ], className='stat-card', style={'width': '24%', 'display': 'inline-block',
                                               'textAlign': 'center', 'backgroundColor': '#e74c3c',
                                               'color': 'white', 'padding': '20px', 'margin': '0.5%',
                                               'borderRadius': '10px'}),

                html.Div([
                    html.H4("Total Packets"),
                    html.H2(id='total-packets', children="0")
                ], className='stat-card', style={'width': '24%', 'display': 'inline-block',
                                               'textAlign': 'center', 'backgroundColor': '#9b59b6',
                                               'color': 'white', 'padding': '20px', 'margin': '0.5%',
                                               'borderRadius': '10px'}),
            ], style={'marginBottom': 30}),

            # Charts Row 1
            html.Div([
                html.Div([
                    dcc.Graph(id='protocol-distribution')
                ], style={'width': '50%', 'display': 'inline-block'}),

                html.Div([
                    dcc.Graph(id='traffic-timeline')
                ], style={'width': '50%', 'display': 'inline-block'}),
            ]),

            # Charts Row 2
            html.Div([
                html.Div([
                    dcc.Graph(id='ip-activity')
                ], style={'width': '50%', 'display': 'inline-block'}),

                html.Div([
                    dcc.Graph(id='suspicious-timeline')
                ], style={'width': '50%', 'display': 'inline-block'}),
            ]),

            # Data Tables
            html.Div([
                html.H3("Recent VoIP Activity", style={'color': '#2c3e50'}),
                dash_table.DataTable(
                    id='activity-table',
                    columns=[
                        {'name': 'Timestamp', 'id': 'timestamp'},
                        {'name': 'Type', 'id': 'type'},
                        {'name': 'Source IP', 'id': 'src_ip'},
                        {'name': 'Destination IP', 'id': 'dst_ip'},
                        {'name': 'Method/Stream', 'id': 'method'},
                        {'name': 'Suspicious', 'id': 'suspicious'}
                    ],
                    style_cell={'textAlign': 'left'},
                    style_data_conditional=[
                        {
                            'if': {'row_index': 'odd'},
                            'backgroundColor': 'rgb(248, 248, 248)'
                        },
                        {
                            'if': {'filter_query': '{suspicious} = true'},
                            'backgroundColor': '#ffebee',
                            'color': 'black',
                        }
                    ],
                    page_size=10
                ),
            ], style={'marginTop': 30}),

            html.Div([
                html.H3("Suspicious Activity Alerts", style={'color': '#e74c3c'}),
                dash_table.DataTable(
                    id='suspicious-table',
                    columns=[
                        {'name': 'Timestamp', 'id': 'timestamp'},
                        {'name': 'Type', 'id': 'type'},
                        {'name': 'Source IP', 'id': 'src_ip'},
                        {'name': 'Destination IP', 'id': 'dst_ip'},
                        {'name': 'Reason', 'id': 'reason'}
                    ],
                    style_cell={'textAlign': 'left'},
                    style_data={'backgroundColor': '#ffebee'},
                    page_size=5
                ),
            ], style={'marginTop': 30}),

            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=2*1000,  # Update every 2 seconds
                n_intervals=0
            ),

            # Hidden div to store state
            html.Div(id='capture-state', style={'display': 'none'}, children='stopped')
        ])

    def setup_callbacks(self):
        """Setup dashboard callbacks"""

        @self.app.callback(
            [Output('capture-state', 'children'),
             Output('status-indicator', 'children')],
            [Input('start-btn', 'n_clicks'),
             Input('stop-btn', 'n_clicks')]
        )
        def control_capture(start_clicks, stop_clicks):
            ctx = dash.callback_context
            if not ctx.triggered:
                return 'stopped', html.Div("Status: Stopped", style={'color': 'red'})

            button_id = ctx.triggered[0]['prop_id'].split('.')[0]

            if button_id == 'start-btn' and start_clicks > 0:
                try:
                    self.analyzer.start_capture()
                    return 'running', html.Div("Status: Capturing packets...", style={'color': 'green'})
                except Exception as e:
                    return 'stopped', html.Div(f"Error: {str(e)}", style={'color': 'red'})

            elif button_id == 'stop-btn' and stop_clicks > 0:
                self.analyzer.stop_capture()
                return 'stopped', html.Div("Status: Stopped", style={'color': 'red'})

            return 'stopped', html.Div("Status: Stopped", style={'color': 'red'})

        @self.app.callback(
            [Output('total-sip', 'children'),
             Output('active-rtp', 'children'),
             Output('suspicious-count', 'children'),
             Output('total-packets', 'children')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_statistics(n):
            stats = self.analyzer.get_call_statistics()
            suspicious = len(self.analyzer.get_suspicious_activity())

            sip_total = sum(v for k, v in stats.items() if k.startswith('sip_'))
            rtp_count = len(self.analyzer.get_rtp_streams())
            total_packets = sum(stats.values())

            return str(sip_total), str(rtp_count), str(suspicious), str(total_packets)

        @self.app.callback(
            Output('protocol-distribution', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_protocol_chart(n):
            stats = self.analyzer.get_call_statistics()

            if not stats:
                return go.Figure().add_annotation(
                    text="No data available",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False
                )

            sip_data = {k.replace('sip_', '').upper(): v for k, v in stats.items() if k.startswith('sip_')}
            rtp_packets = stats.get('rtp_packets', 0)

            labels = list(sip_data.keys()) + (['RTP'] if rtp_packets > 0 else [])
            values = list(sip_data.values()) + ([rtp_packets] if rtp_packets > 0 else [])

            fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
            fig.update_layout(title="Protocol Distribution", height=400)
            return fig

        @self.app.callback(
            Output('traffic-timeline', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_timeline_chart(n):
            df = self.analyzer.get_metadata_dataframe()

            if df.empty:
                return go.Figure().add_annotation(
                    text="No data available",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False
                )

            # Group by minute
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['minute'] = df['timestamp'].dt.floor('T')
            timeline_data = df.groupby(['minute', 'type']).size().reset_index(name='count')

            fig = px.line(timeline_data, x='minute', y='count', color='type',
                         title="Traffic Timeline (Packets per Minute)")
            fig.update_layout(height=400)
            return fig

        @self.app.callback(
            Output('ip-activity', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_ip_chart(n):
            df = self.analyzer.get_metadata_dataframe()

            if df.empty:
                return go.Figure().add_annotation(
                    text="No data available",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False
                )

            ip_counts = df['src_ip'].value_counts().head(10)

            fig = go.Figure(data=[go.Bar(x=ip_counts.index, y=ip_counts.values)])
            fig.update_layout(title="Top Source IP Addresses", height=400)
            return fig

        @self.app.callback(
            Output('suspicious-timeline', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_suspicious_chart(n):
            suspicious = self.analyzer.get_suspicious_activity()

            if not suspicious:
                return go.Figure().add_annotation(
                    text="No suspicious activity detected",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False
                )

            df_sus = pd.DataFrame(suspicious)
            df_sus['timestamp'] = pd.to_datetime(df_sus['timestamp'])
            df_sus['hour'] = df_sus['timestamp'].dt.floor('H')
            sus_timeline = df_sus.groupby('hour').size().reset_index(name='count')

            fig = px.bar(sus_timeline, x='hour', y='count',
                        title="Suspicious Activity Timeline")
            fig.update_layout(height=400)
            return fig

        @self.app.callback(
            Output('activity-table', 'data'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_activity_table(n):
            df = self.analyzer.get_metadata_dataframe()

            if df.empty:
                return []

            # Get last 20 entries
            recent_df = df.tail(20).copy()
            recent_df['timestamp'] = recent_df['timestamp'].astype(str)
            recent_df['method'] = recent_df.get('method', recent_df.get('stream_key', ''))

            return recent_df[['timestamp', 'type', 'src_ip', 'dst_ip', 'method', 'suspicious']].to_dict('records')

        @self.app.callback(
            Output('suspicious-table', 'data'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_suspicious_table(n):
            suspicious = self.analyzer.get_suspicious_activity()

            if not suspicious:
                return []

            # Convert timestamps to strings
            for item in suspicious:
                item['timestamp'] = str(item['timestamp'])

            return suspicious[-10:]  # Last 10 suspicious activities

        @self.app.callback(
            Output('export-btn', 'children'),
            [Input('export-btn', 'n_clicks')]
        )
        def export_data(n_clicks):
            if n_clicks and n_clicks > 0:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"voip_analysis_{timestamp}.json"
                self.analyzer.export_data(filename)
                return f"Exported to {filename}"
            return "Export Data"

    def run(self, debug=False, port=8050):
        """Run the dashboard"""
        print(f"Starting VoIP Dashboard on http://localhost:{port}")
        print("Note: Run with administrator privileges for packet capture")
        self.app.run_server(debug=debug, port=port, host='0.0.0.0')

if __name__ == '__main__':
    dashboard = VoIPDashboard()
    dashboard.run(debug=True)
