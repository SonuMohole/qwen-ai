# backend/ai_analysis_app/knowledge_base.py

# =======================================================================
# === KNOWLEDGE BASE DATA (Python Dict) ===
# =======================================================================

SUPPORT_FALLBACK = """
📞 I'm not sure how to help with that. For more specific help, please contact our support team:
- Email: support@qstellar.com
- Phone: (555) 123-4567
"""

# Combined Dictionary for fast lookup
# Keys are lowercase keywords to match against user input
PLATFORM_KNOWLEDGE = {
    # --- Identity & Capabilities ---
    "who are you": "I'm the Qstellar Assistant! I can help you find information about the platform's features, analyze reports, and query your security data. 🤖",
    "what are you": "I'm a helpful security analyst bot for the Qstellar platform. 🤖",
    "capabilities": "I can analyze uploaded security reports (PDF/CSV), query your vulnerability database via SQL, and explain Qstellar platform features like the Dashboard, Assets, and Agent Center.",
    "what can you do": "I can analyze uploaded security reports (PDF/CSV), query your vulnerability database via SQL, and explain Qstellar platform features like the Dashboard, Assets, and Agent Center.",
    
    # --- Settings/Account ---
    "settings": "⚙️ The **'Account & Settings'** page is your central hub for configuration. You can manage **'Platform'** settings, **'User Access'**, **'Audit Logs'**, **'Notifications'**, and **'Billing'**.",
    "user access": "⚙️ The **'User Access'** tab in Settings is where you manage **'Roles & Groups'**. You can define permissions for roles like 'Admin', 'Analyst', and 'Read-Only'.",
    "audit logs": "⚙️ The **'Audit Logs'** tab in Settings shows all user activity. You can filter by 'User Email' or 'Action' and **'Export'** a CSV report.",
    
    # --- Dashboard ---
    "dashboard": "📊 The 'Dashboard' is the main overview page. It shows key metrics like 'Total Issues', 'Agents Online', 'Total Assets', 'Total Technologies', and your 'QCT Score'.",
    "qct score": "🎯 The 'QCT Score' is a custom 'Quality, Compliance, Threat' index that measures your overall security posture.",
    "total issues": "📉 The 'Total Issues' card shows the total number of open vulnerabilities and problems, including a trend percentage.",
    
    # --- Assets ---
    "asset": "🖥️ The 'Assets' page provides a comprehensive overview of all discovered devices. You can manage 'Asset Priority' and view details like OS, IP, and Last Seen.",
    "asset priority": "🛡️ 'Asset Priority' allows you to classify assets based on the CIA triad (Confidentiality, Integrity, Availability) to determine their impact level.",
    
    # --- Agent Center ---
    "agent center": "🤖 The 'Agent Center' is where you download, monitor, and manage security agents. It has tabs for 'Download Center' and 'Monitoring'.",
    "download agent": "⬇️ You can download agents for Windows (.exe), Linux (.deb), and macOS from the 'Download Center' tab inside the Agent Center.",
    
    # --- Vulnerabilities ---
    "vulnerability": "🛡️ The 'Vulnerabilities' page tracks all detected issues. You can filter by severity, search for specific CVEs, and export reports.",
    
    # --- News ---
    "news": "📰 The 'News & Recommendations' page shows trending threat activity, latest security news, and AI-driven patching recommendations.",
    "ransomware": "🚨 The 'Active Ransomware' panel on the News page tracks active campaigns that might affect your sector.",
    
    # --- Reports ---
    "report": "📄 The 'Reports' page is where you access generated security reports. You can filter by type (Security, Compliance) and export to PDF or CSV.",
    
    # --- AI Assistant ---
    "ai assistant": "🤖 That's me! I'm located on the main menu. You can upload reports (PDF, CSV, XLSX) for me to analyze, or ask me general questions about the platform.",
    
    # --- General ---
    "qstellar": "🤖 Qstellar is a cybersecurity management platform for Attack Surface Management & Security Intelligence, built by QuasarCybertech.",
    "support": "🆘 For complex issues, contact support at 'support@qstellar.com' or call (555) 123-4567."
}

def lookup_knowledge_base(user_query: str) -> str:
    """
    Simple keyword matcher. Returns the most relevant value if a key is found.
    """
    query = user_query.lower()
    
    # Check for exact keyword matches
    for key, response in PLATFORM_KNOWLEDGE.items():
        if key in query:
            return response
            
    return ""