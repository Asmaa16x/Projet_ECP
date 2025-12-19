import csv
import time
import os

# Chemin vers le fichier que Streamlit va lire
DATA_FILE = "data/live_traffic.csv"

def write_to_csv(is_attack=False):
    if not os.path.exists('data'):
        os.makedirs('data')
        
    header = ['same_srv_rate', 'logged_in', 'dst_host_srv_count', 'flag', 
              'dst_host_same_srv_rate', 'protocol_type', 'dst_host_srv_serror_rate', 
              'serror_rate', 'dst_host_serror_rate', 'dst_host_same_src_port_rate', 'srv_serror_rate']
    
    if is_attack:
        # Valeurs qui déclenchent une alerte (Taux d'erreur serror à 100%)
        row = [0.05, 0.0, 10.0, 0.0, 0.05, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0]
        print(" [BRIDGE] Envoi d'une simulation d'ATTAQUE...")
    else:
        # Valeurs de trafic fluide et normal
        row = [1.0, 1.0, 255.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        print("[BRIDGE] Envoi de trafic NORMAL.")

    file_exists = os.path.isfile(DATA_FILE)
    with open(DATA_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(header)
        writer.writerow(row)

if __name__ == "__main__":
    print(" BRIDGE CONNECTÉ À L'IA")
    print("--------------------------")
    
    while True:
        print("\nQue voulez-vous simuler sur le réseau ?")
        print("1. Trafic normal (Ping classique)")
        print("2. Attaque SYN Flood (Anomalie)")
        
        choix = input("Votre choix (1 ou 2) : ")
        
        if choix == "2":
            write_to_csv(is_attack=True)
            print(" Trame d'attaque envoyée au CSV !")
        else:
            write_to_csv(is_attack=False)
            print(" Trame normale envoyée au CSV.")
            
        time.sleep(1) # Petit délai pour laisser Streamlit lire le fichier