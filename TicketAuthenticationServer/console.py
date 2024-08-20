import socket
import json
import logging

SERVER_ADDRESS = ('localhost', 8888)
AUTHENTICATION_SERVER_ADDRESS = ('localhost', 8889)

logging.basicConfig(level=logging.INFO)

def update_server_key():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(AUTHENTICATION_SERVER_ADDRESS)

            logging.info("Sending update request for server key...")
            client_socket.send(b"update-key_server")

            # Receive the update result from the authentication server
            result = client_socket.recv(1024).decode('utf-8').strip()
            logging.info(result)
    except Exception as e:
        logging.error(f"Error updating server key: {e}")

def update_client_key(username):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(AUTHENTICATION_SERVER_ADDRESS)

            logging.info(f"Sending update request for client key with username: {username}...")
            client_socket.send(f"update-key_client_{username}".encode('utf-8'))

            # Receive the update result from the authentication server
            result = client_socket.recv(1024).decode('utf-8').strip()
            logging.info(result)
    except Exception as e:
        logging.error(f"Error updating client key: {e}")

def key_update_interface():
    while True:
        print("\nKey Update Interface:")
        print("1. Update Server Key")
        print("2. Update Client Key")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            update_server_key()
        elif choice == "2":
            username = input("Enter the username to update client key: ")
            update_client_key(username)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == '__main__':
    key_update_interface()
