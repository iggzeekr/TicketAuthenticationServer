import socket
import json
import getpass
import base64
import logging

SERVER_ADDRESS = ('localhost', 8888)
AUTHENTICATION_SERVER_ADDRESS = ('localhost', 8889)

logging.basicConfig(level=logging.INFO)

def get_ticket(username):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(AUTHENTICATION_SERVER_ADDRESS)

            logging.info(f"Requesting a ticket for {username}...")
            client_socket.send(f"generate-ticket_{username}".encode('utf-8'))

            # Receive the authentication result from the authentication server
            result = client_socket.recv(1024).decode('utf-8').strip()
            logging.info(f"Received ticket for {username}: {result}")
            return json.loads(result)
    except Exception as e:
        logging.error(f"Error handling client: {e}")

def main(username):
    ticket_json = get_ticket(username)
    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(SERVER_ADDRESS)

        # Receive the welcome message
        welcome_message = client_socket.recv(1024).decode('utf-8')
        logging.info(welcome_message)

        logging.info(f"Sending request to the server for {username}...")
        client_socket.send(f"{username}_{ticket_json}_time".encode('utf-8'))

        # Receive and print the server response
        response = client_socket.recv(1024).decode('utf-8')
        logging.info(f"Received response from the server: {response}")

if __name__ == '__main__':
    logging.info("Starting client...")
    main("test")
