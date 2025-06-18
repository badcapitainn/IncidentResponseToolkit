from graphviz import Digraph

# Initialize the sequence diagram
diagram = Digraph("SequenceDiagram", format="png")
diagram.attr(rankdir="LR")

# Add nodes (actors and objects)
diagram.node("User", "User/Admin", shape="actor")
diagram.node("WebInterface", "WebInterface")
diagram.node("IncidentResponse", "IncidentResponse")
diagram.node("LogAnalysis", "LogAnalysis")
diagram.node("MalwareDetection", "MalwareDetection")
diagram.node("NetworkMonitoring", "NetworkMonitoring")
diagram.node("Alert", "Alert")

# Add interactions (sequence of actions)
# User to WebInterface
diagram.edge("User", "WebInterface", label="Log in / View Alerts")
diagram.edge("WebInterface", "IncidentResponse", label="Initialize Toolkit")

# WebInterface to LogAnalysis
diagram.edge("IncidentResponse", "LogAnalysis", label="Collect & Analyze Logs")
diagram.edge("LogAnalysis", "IncidentResponse", label="Return Analyzed Data")

# WebInterface to MalwareDetection
diagram.edge("IncidentResponse", "MalwareDetection", label="Scan for Malware")
diagram.edge("MalwareDetection", "IncidentResponse", label="Return Malware Alerts")

# WebInterface to NetworkMonitoring
diagram.edge("IncidentResponse", "NetworkMonitoring", label="Monitor Traffic")
diagram.edge("NetworkMonitoring", "IncidentResponse", label="Return Traffic Anomalies")

# IncidentResponse to Alert
diagram.edge("IncidentResponse", "Alert", label="Generate Alert")
diagram.edge("Alert", "WebInterface", label="Display Alerts")

# User to WebInterface (Admin actions)
diagram.edge("User", "WebInterface", label="Select Action (e.g., Block IP)")
diagram.edge("WebInterface", "IncidentResponse", label="Execute Action")

# Final system updates
diagram.edge("IncidentResponse", "LogAnalysis", label="Log Actions")

# Render the diagram
output_path = "C:\\Users\\madza\\Desktop\\capstone_sequence_diagram"
diagram.render(output_path, cleanup=True)
print(f"Sequence diagram saved at: {output_path}.png")
