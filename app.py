import streamlit as st
import psutil
import socket
import random
import time
import numpy as np
import wmi
from together import Together
import plotly.graph_objects as go
from PyPDF2 import PdfReader

# Initialize TogetherAI client with API key
client = Together(api_key="2f9578a2cd37cbed0e838815645995334ffc14793a8db525114f048e31e677ed")

# Function to analyze security data with TogetherAI
def analyze_security_data(data):
    try:
        response = client.chat.completions.create(
            model="meta-llama/Llama-3.2-11B-Vision-Instruct-Turbo",
            messages=[{"role": "system", "content": "Analyze security layer data or detect malware."},
                      {"role": "user", "content": str(data)}],
            max_tokens=50,
            temperature=0.7,
            top_p=0.7,
            top_k=50,
            repetition_penalty=1,
            stop=["<|eot_id|>", "<|eom_id|>"],
            stream=True
        )
        analysis = ""
        for token in response:
            if hasattr(token, 'choices') and token.choices and 'delta' in token.choices[0]:
                analysis += token.choices[0].delta.content
        return analysis if analysis else "No analysis available"
    except Exception as e:
        return f"Error analyzing data: {e}"

# Function to detect malware in file content
def detect_malware_in_text(text):
    suspicious_keywords = ['virus', 'malware', 'phishing', 'ransomware', 'trojan', 'spyware']
    if any(keyword in text.lower() for keyword in suspicious_keywords):
        return "Potential malware detected in the content."
    return "No malware detected in the content."

# Function to read PDF content (using PdfReader from PyPDF2)
def read_pdf(file):
    try:
        pdf_reader = PdfReader(file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text()
        return text
    except Exception as e:
        return f"Error reading PDF file: {e}"

# Function to get system's local IP address and MAC address using WMI
def get_system_ip_and_mac():
    w = wmi.WMI()
    for interface in w.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        ip_address = interface.IPAddress[0]
        mac_address = interface.MACAddress
        return ip_address, mac_address
    return None, None

# Function to retrieve currently connected IPs using psutil
def get_connected_ips():
    connections = psutil.net_connections()
    connected_ips = set()
    for conn in connections:
        if conn.raddr:
            connected_ips.add(conn.raddr.ip)
    return list(connected_ips)

# Function to display real-time 3D visualization of security layers data
def display_3d_security_layers(layer_data):
    x = np.arange(len(layer_data))
    y = np.random.random(len(layer_data)) * 100
    z = np.array(list(layer_data.values()))

    fig = go.Figure(data=[go.Scatter3d(
        x=x, y=y, z=z,
        mode='markers',
        marker=dict(size=8, color=z, colorscale='Viridis', opacity=0.8)
    )])

    fig.update_layout(
        title="Real-Time 3D Security Layer Visualization",
        scene=dict(
            xaxis_title="Layer Index",
            yaxis_title="Random Value",
            zaxis_title="Layer Value"
        ),
        margin=dict(l=0, r=0, b=0, t=30)
    )
    return fig

# Main function to manage layout and updates
def display_security_dashboard():
    st.title("Real-Time Cybersecurity Dashboard")
    st.write("A dashboard to help you monitor and secure your system in real-time.")

    # **File Upload and Malware Detection**
    st.header("Malware Detection in Uploaded Files")
    uploaded_file = st.file_uploader("Upload a PDF or Text file for malware detection:", type=["pdf", "txt"])

    if uploaded_file is not None:
        if uploaded_file.type == "application/pdf":
            file_content = read_pdf(uploaded_file)
        else:  # Text file
            file_content = uploaded_file.read().decode("utf-8")

        # Display file content and analyze for malware
        st.write("File Content:")
        st.write(file_content[:1000] + "...")  # Display first 1000 characters
        malware_analysis = detect_malware_in_text(file_content)
        st.write("Malware Analysis Result:")
        st.write(malware_analysis)

        # Analyze content with TogetherAI
        analysis = analyze_security_data(file_content)
        st.write("Detailed Analysis:")
        st.write(analysis)

    # **Connected IPs and System IP Display**
    st.sidebar.header("Network Monitoring")
    system_ip, mac_address = get_system_ip_and_mac()
    if system_ip and mac_address:
        st.sidebar.write(f"System IP: {system_ip}")
        st.sidebar.write(f"MAC Address: {mac_address}")
    else:
        st.sidebar.write("Unable to fetch system IP and MAC address.")
    
    connected_ips = get_connected_ips()
    st.sidebar.write("Connected IPs:")
    st.sidebar.write(connected_ips)

    # **Security Layers Data with Real-Time 3D Visualization**
    st.header("Security Layers Analysis")
    layer_box = st.empty()

    # Displaying updated 3D visualization for security layers in real-time
    num_layers = 5
    while True:
        updated_layer_data = {f"Layer {i+1}": random.randint(1, 100) for i in range(num_layers)}
        
        # Display updated layer data and 3D plot
        with layer_box.container():
            st.write("Current Layer Data:")
            st.write(updated_layer_data)
            fig = display_3d_security_layers(updated_layer_data)
            st.plotly_chart(fig, use_container_width=True)

            # Analyze data with TogetherAI
            analysis = analyze_security_data(updated_layer_data)
            st.write("Security Analysis:")
            st.write(analysis)

        time.sleep(3)  # Refresh every 3 seconds to prevent constant reloading

    # **Chatbox for Security Discussions**
    st.sidebar.header("Security Assistant")
    user_input = st.sidebar.text_input("Discuss with Security Assistant:")
    if user_input:
        st.sidebar.write(f"You: {user_input}")
        analysis = analyze_security_data(user_input)
        st.sidebar.write(f"Assistant: {analysis}")

    # **Real-Time Attack Detection**
    st.sidebar.header("System Status")
    attack_detected = random.random() < 0.1  # Sample attack detection logic
    attack_color = "red" if attack_detected else "green"
    attack_status = "Hacker Attack Detected!" if attack_detected else "System Secure."
    st.sidebar.markdown(f'<h3 style="color:{attack_color};">{attack_status}</h3>', unsafe_allow_html=True)

# Initialize session state for blocked IPs
if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = set()

# Run the app
if __name__ == "__main__":
    display_security_dashboard()
