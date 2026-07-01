import pandas as pd
from sklearn.ensemble import IsolationForest
import warnings

# Suppress warnings for clean terminal output
warnings.filterwarnings('ignore')

print("[*] SRE Anomaly Detection Engine Initializing...")

# 1. Load the Baseline Data (The "Normal" State)
try:
    df = pd.read_csv("./telemetry_data/server_baseline.csv")
    # We only want the math columns, not the timestamp
    features = df[['CPU_Percent', 'RAM_Percent', 'Net_Connections']]
except FileNotFoundError:
    print("[-] ERROR: Run baseline_sensor.py first to gather data!")
    exit(1)

# 2. Train the Machine Learning Model
print("[*] Training Isolation Forest on historical baseline...")
# contamination=0.05 means we assume 5% of our baseline data might be noise
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(features)
print("[+] Training Complete.\n")

# 3. The "Chaos Sandbox" (Testing the AI)
print("--- RUNNING SIMULATED SERVER STATES ---")

# State A: Normal operations (Low CPU, normal RAM, few connections)
normal_state = pd.DataFrame([[12.5, 65.0, 15]], columns=['CPU_Percent', 'RAM_Percent', 'Net_Connections'])

# State B: A simulated DDoS Attack or Ransomware (Maxed CPU, Max RAM, huge connections)
attack_state = pd.DataFrame([[99.9, 98.0, 450]], columns=['CPU_Percent', 'RAM_Percent', 'Net_Connections'])

# 4. Evaluate the States
for state_name, system_state in [("Routine Nextcloud Sync", normal_state), ("Simulated DDoS Attack", attack_state)]:
    
    # The AI predicts: 1 = Normal, -1 = Anomaly
    prediction = model.predict(system_state)
    
    print(f"\nEvaluating: {state_name}")
    print(f"Metrics: CPU {system_state['CPU_Percent'][0]}% | RAM {system_state['RAM_Percent'][0]}% | Conns {system_state['Net_Connections'][0]}")
    
    if prediction[0] == 1:
        print("[$ STATUS: HEALTHY] System operating within baseline parameters.")
    else:
        print("[[X] STATUS: ANOMALY] Critical deviation! Waking up Llama 3 for log analysis...")

print("\n[*] Evaluation Finished.")
