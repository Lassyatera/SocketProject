import os
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def receive_public_key_file(connection):
    file_name = connection.recv(1024).decode('utf-8')
    return file_name

def load_public_key_from_file(file_name):
    with open(file_name, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def decrypt_file(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)
    try:
        client_socket.connect(server_address)
        print("Connected to server.")
        # Recevoir le nom du fichier contenant la clé publique
        public_key_file = receive_public_key_file(client_socket)
        print("Received public key file:", public_key_file)
        # Charger la clé publique à partir du fichier
        public_key = load_public_key_from_file(public_key_file)
        # Envoyer une demande pour la clé privée
        client_socket.sendall(b"private_key")
        # Recevoir la clé privée du serveur
        private_key_data = client_socket.recv(4096)
        # Charger la clé privée
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
            backend=default_backend()
        )
        # Déchiffrer les données reçues
        while True:
            ciphertext = client_socket.recv(4096)
            if not ciphertext:
                break
            plaintext = decrypt_file(private_key, ciphertext)
            # Faites quelque chose avec le plaintext (par exemple,
 
