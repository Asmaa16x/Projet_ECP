import streamlit as st
import pandas as pd
import joblib
import os

# Configuration
st.set_page_config(page_title="IDS Dashboard Pro", page_icon="🛡️", layout="wide")

# 1. DÉFINITION DES COLONNES (Indispensable)
features = ['same_srv_rate', 'logged_in', 'dst_host_srv_count', 'flag', 
            'dst_host_same_srv_rate', 'protocol_type', 'dst_host_srv_serror_rate', 
            'serror_rate', 'dst_host_serror_rate', 'dst_host_same_src_port_rate', 'srv_serror_rate']

# Chargement du modèle et du scaler
@st.cache_resource
def load_assets():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Chemin vers notebooks/joblib (ajusté selon ton arborescence)
    base_path = os.path.join(current_dir, "..", "notebooks", "joblib")
    
    model_path = os.path.join(base_path, "final_voting_model.joblib")
    scaler_path = os.path.join(base_path, "scaler.joblib")
    
    if not os.path.exists(model_path):
        st.error(f"Fichier introuvable : {model_path}")
        st.stop()
        
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    return model, scaler

model, scaler = load_assets()

st.title("🛡️ Network Intrusion Detection System")

tab1, tab2 = st.tabs(["📝 Saisie Manuelle", "📁 Analyse de Fichier (CSV)"])

# --- ONGLET 1 : SAISIE MANUELLE ---
with tab1:
    st.subheader("Entrez les caractéristiques d'une trame unique")
    col1, col2 = st.columns(2)
    inputs = {}
    for i, feat in enumerate(features):
        with col1 if i % 2 == 0 else col2:
            inputs[feat] = st.number_input(f"{feat}", value=0.0, key=f"manual_{feat}")

    if st.button("🔍 Analyser la trame"):
        input_df = pd.DataFrame([inputs])
        
        # --- CORRECTION : AJOUT DU SCALING ---
        input_scaled = scaler.transform(input_df)
        prediction = model.predict(input_scaled)
        
        if prediction[0] == 1:
            st.error("🚨 ALERTE : INTRUSION DÉTECTÉE")
        else:
            st.success("✅ TRAFIC NORMAL")

# --- ONGLET 2 : ANALYSE CSV ---
with tab2:
    st.subheader("Télécharger un log réseau pour une analyse de masse")
    uploaded_file = st.file_uploader("Choisir un fichier CSV", type="csv")

    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        
        if all(col in data.columns for col in features):
            df_to_predict = data[features]
            
            # --- CORRECTION : AJOUT DU SCALING ---
            df_scaled = scaler.transform(df_to_predict)
            predictions = model.predict(df_scaled)
            
            data['Résultat'] = ["🚨 Attaque" if p == 1 else "✅ Normal" for p in predictions]
            
            st.write(f"Analyse de {len(data)} lignes terminée :")
            st.dataframe(data)
            
            nb_attaques = sum(predictions)
            st.metric("Attaque(s) détectée(s)", nb_attaques, 
                      delta=f"{nb_attaques/len(data)*100:.1f}% du trafic", delta_color="inverse")
        else:
            st.warning(f"Le fichier doit contenir les colonnes suivantes : {features}")