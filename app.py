import streamlit as st
from logic_checker import get_forensic_trust_index
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Sentinel-AI | Safe Link Checker",
    page_icon="🛡️",
    layout="centered"
)

# --- ULTIMATE CYBERPUNK CSS (Now with Mobile & Overflow Patches) ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700&family=Share+Tech+Mono&display=swap');

    .stApp {
        background: radial-gradient(ellipse at bottom, #0d1d31 0%, #0c0d13 100%);
        color: #00ff41; 
        font-family: 'Share Tech Mono', monospace;
    }
    
    .stApp::before {
        content: "";
        position: fixed;
        top: 0; left: 0; width: 100%; height: 100%;
        background-image: 
            linear-gradient(rgba(0, 255, 65, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 65, 0.1) 1px, transparent 1px);
        background-size: 30px 30px;
        background-position: center center;
        z-index: -1;
        animation: moveGrid 20s linear infinite;
        opacity: 0.3;
    }
    @keyframes moveGrid {
        0% { transform: translateY(0) translateZ(0) perspective(1000px) rotateX(45deg); }
        100% { transform: translateY(30px) translateZ(0) perspective(1000px) rotateX(45deg); }
    }

    @keyframes flicker {
        0%, 19%, 21%, 23%, 25%, 54%, 56%, 100% { text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 40px #00ff41; opacity: 1; }
        20%, 24%, 55% { text-shadow: none; opacity: 0.8; }
    }
    
    .mega-logo {
        font-family: 'Orbitron', sans-serif;
        font-size: 4rem; 
        white-space: nowrap !important; 
        font-weight: 800;
        text-align: center;
        color: #fff;
        animation: flicker 3s infinite alternate;
        letter-spacing: 2px;
        margin-top: 10px;
    }
    .cyber-subtitle {
        text-align: center;
        font-family: 'Orbitron', sans-serif;
        color: #00ff41;
        letter-spacing: 2px;
        font-size: 1rem;
        margin-bottom: 50px;
        opacity: 0.9;
    }

    /* 🛠️ PATCH 1: MOBILE RESPONSIVENESS (Phone Screen Fix) */
    @media (max-width: 768px) {
        .mega-logo {
            font-size: 2.2rem !important; /* Auto shrinks on mobile! */
            letter-spacing: 1px;
        }
        .cyber-subtitle {
            font-size: 0.8rem !important;
            margin-bottom: 30px;
        }
    }

    .stTextInput input {
        background-color: rgba(0, 20, 0, 0.7) !important;
        color: #00ff41 !important;
        border: 2px solid #00ff41 !important;
        border-radius: 4px !important; 
        padding: 18px !important;
        font-family: 'Orbitron', sans-serif;
        font-size: 16px !important;
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.3) !important;
        transition: all 0.3s ease-in-out;
    }
    .stTextInput input:focus {
        box-shadow: 0 0 30px rgba(0, 255, 65, 0.8), inset 0 0 10px rgba(0,255,65,0.5) !important;
    }

    button[kind="primaryFormSubmit"] {
        background: linear-gradient(45deg, #00ff41, #033500) !important;
        color: #000 !important;
        border: none !important;
        border-radius: 4px !important;
        padding: 12px 30px !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900;
        font-size: 16px !important;
        letter-spacing: 1px;
        clip-path: polygon(10% 0, 100% 0, 90% 100%, 0 100%); 
        transition: all 0.3s ease;
    }
    button[kind="primaryFormSubmit"]:hover {
        transform: scale(1.05) skewX(-10deg);
        box-shadow: 0 0 30px #00ff41;
    }

    /* 🛠️ PATCH 2: LONG URL OVERFLOW FIX (word-wrap added) */
    .terminal-box {
        background: rgba(0, 10, 0, 0.9);
        border: 1px solid #00ff41;
        border-left: 5px solid #00ff41;
        padding: 15px;
        font-family: 'Share Tech Mono', monospace;
        color: #00ff41;
        font-size: 14px;
        box-shadow: inset 0 0 20px rgba(0,255,65,0.2);
        margin-bottom: 20px;
        word-wrap: break-word !important; 
        overflow-wrap: break-word !important;
    }

    .cyber-panel {
        background: rgba(0, 20, 0, 0.6);
        border: 1px solid rgba(0, 255, 65, 0.5);
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.2), inset 0 0 10px rgba(0, 20, 0, 0.8);
        backdrop-filter: blur(5px);
        border-radius: 10px;
        padding: 25px;
        margin-top: 20px;
        animation: fadeInUp 0.8s ease-out;
        word-wrap: break-word !important; 
        overflow-wrap: break-word !important;
    }
    
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(40px) scale(0.9); }
        to { opacity: 1; transform: translateY(0) scale(1); }
    }

    div[data-testid="stMetricLabel"] { color: #00ff41 !important; font-family: 'Orbitron'; letter-spacing: 1px; }
    div[data-testid="stMetricValue"] { color: #fff !important; text-shadow: 0 0 15px #00ff41; font-size: 3.5rem !important; font-family: 'Orbitron'; }
    .stAlert { background: rgba(0,0,0,0.7) !important; border: 1px solid currentColor; }
    </style>
""", unsafe_allow_html=True)

# --- USER-FRIENDLY HEADER IN CYBER STYLE ---
st.markdown('<div class="mega-logo">🛡️ SENTINEL-AI</div>', unsafe_allow_html=True)
st.markdown('<div class="cyber-subtitle">Advanced Web Safety Scanner</div>', unsafe_allow_html=True)

# --- SIMPLE INPUT AREA (With Enter Key Support) ---
with st.form("cyber_scan_form", clear_on_submit=False):
    url_input = st.text_input("###", placeholder="> Paste a link here to check if it's safe...", label_visibility="collapsed")
    
    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        scan_btn = st.form_submit_button(">> SCAN LINK SAFELY <<", use_container_width=True)

st.write("")

# --- LOGIC & FRIENDLY ANIMATION ---
if scan_btn:
    if not url_input:
        st.error("⚠️ [ERROR]: Please paste a link before scanning.")
    else:
        terminal_placeholder = st.empty()
        logs = [
            "Starting safety engine...",
            "Checking website reputation...",
            "Looking for hidden scams and traps...",
            "Verifying security certificates...",
            "Calculating final safety score..."
        ]
        terminal_text = ""
        for log in logs:
            terminal_text += f"> [SENTINEL_CORE]: {log}<br>"
            terminal_placeholder.markdown(f'<div class="terminal-box">{terminal_text}</div>', unsafe_allow_html=True)
            time.sleep(0.12) 
            
        with st.spinner("Preparing your safety report..."):
            result = get_forensic_trust_index(url_input)
            
        terminal_placeholder.empty() 
        
        fti = result["FTI"]
        status = result["Status"]
        
        # --- FRIENDLY RESULTS PANEL IN CYBER STYLE ---
        st.markdown('<div class="cyber-panel">', unsafe_allow_html=True)
        
        st.markdown(f"<h2 style='text-align:center; font-family:Orbitron; color:#fff; letter-spacing:2px;'>SAFETY REPORT</h2>", unsafe_allow_html=True)
        st.divider()
        
        m_col1, m_col2 = st.columns(2)
        with m_col1:
            st.metric("SAFETY SCORE (Out of 100)", f"{fti}")
        with m_col2:
            st.write("") 
            if fti >= 80:
                 st.success(f"**STATUS: {status}**")
                 st.markdown(f"<div style='color:#0f0; font-family:Orbitron;'>✓ SAFE TO BROWSE</div>", unsafe_allow_html=True)
            elif fti >= 50:
                 st.warning(f"**STATUS: {status}**")
                 st.markdown(f"<div style='color:orange; font-family:Orbitron;'>⚠ BE CAREFUL</div>", unsafe_allow_html=True)
            elif "OFFLINE" in status or "DENIED" in status:
                 st.info(f"**STATUS: {status}**")
                 st.markdown(f"<div style='color:#00ff41; font-family:Orbitron;'>■ SCAN STOPPED</div>", unsafe_allow_html=True)
            else:
                 st.error(f"**STATUS: {status}**")
                 st.markdown(f"<div style='color:red; font-family:Orbitron;'>🛑 HIGHLY DANGEROUS</div>", unsafe_allow_html=True)
        
        st.progress(fti / 100.0 if fti > 0 else 0)
        
        st.divider()
        
        st.markdown("<h4 style='font-family:Orbitron; color:#00ff41;'>Simple Advice For You:</h4>", unsafe_allow_html=True)
        for tip in result["Takeaways"]:
            st.info(f"> {tip}")
            
        with st.expander("View Technical Logs (For Developers)"):
            for finding in result["Findings"]:
                cln = finding.replace('[SAFE] ', '').replace('[INFO] ', '').replace('[WARNING] ', '').replace('[DANGER] ', '').replace('[ALERT] ', '')
                if "✅" in finding: st.write(f"`✅ {cln}`")
                elif "ℹ️" in finding: st.write(f"`ℹ️ {cln}`")
                elif "⚠️" in finding: st.warning(f"`⚠️ {cln}`")
                else: st.error(f"`🚨 {cln}`")
                
        st.markdown('</div>', unsafe_allow_html=True)

