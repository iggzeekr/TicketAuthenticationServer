import socket
import threading
import json
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

logging.basicConfig(level=logging.INFO)

TICKETS = {}
SERVER_KEYS = {}

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def sign_data(data, private_key):
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def generate_ticket(username, private_key):
    # Generate a ticket with a digital signature
    ticket_data = {
        "username": username,
        "expiration": 600,  # 10 minutes
    }

    ticket_json = json.dumps(ticket_data)

    # Sign the ticket data with the private key
    signature = sign_data(ticket_json, private_key)

    # Include the signature in the ticket
    ticket_data["signature"] = signature.hex()

    return json.dumps(ticket_data)

def validate_ticket(ticket, public_key):
    # Validate the ticket using the public key
    ticket_data = json.loads(ticket.replace("'", '"'))
    signature = bytes.fromhex(ticket_data["signature"])
    ticket_data.pop("signature")

    ticket_json = json.dumps(ticket_data)

    try:
        public_key.verify(
            signature,
            ticket_json.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        logging.error("Invalid signature. Ticket is not valid.")
        return False
    
def update_server_key():
    private_key, public_key = generate_key_pair()
    SERVER_KEYS["private_key"] = private_key
    SERVER_KEYS["public_key"] = public_key
    logging.info("Server key updated.")

def update_client_key(username):
    if username in TICKETS:
        private_key, public_key = generate_key_pair()
        TICKETS[username] = (private_key, public_key)
        logging.info(f"Client key for {username} updated.")
    else:
        logging.warning(f"Client key update failed for {username}. User not found.")


def handle_client(client_socket, address):
    logging.info(f"Accepted connection from {address}")

    try:
        # Receive username and password from the client
        temp = client_socket.recv(1024).decode('utf-8')
        messages = temp.split('_')
        if messages[0] == "generate-ticket":
            logging.info(f"Generating ticket for {messages[1]}...")
            username = messages[1]
            private_key, public_key = generate_key_pair()

            # Generate a ticket for a user
            ticket = generate_ticket(username, private_key)
            client_socket.send(ticket.encode('utf-8'))
            TICKETS[username] = (private_key, public_key)
            logging.info(f"Ticket generated successfully for {username}.")
        elif messages[0] == "authenticate":
            logging.info(f"Authenticating for {messages[1]}...")
            username = messages[1]
            ticket = messages[2]
            if validate_ticket(ticket, TICKETS[username][1]):
                client_socket.send(b"Ok")
                logging.info(f"Authentication successful for {username}.")
            else:
                client_socket.send(b"Invalid ticket.")
                logging.warning(f"Authentication failed for {username}. Invalid ticket.")
                return
            
        elif messages[0] == "update-key":
            logging.info(f"Received key update request from {address[0]}:{address[1]}.")
            update_client_key(messages[1])
            client_socket.send(b"Key updated successfully.")
        else:
            client_socket.send(b"Invalid request.")
            logging.warning("Invalid request received.")
            return


        
    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        client_socket.close()

def start_auth_ticket_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8889)
    server_socket.bind(server_address)
    server_socket.listen(5)
    logging.info(f"Auth and Ticket server listening on {server_address[0]}:{server_address[1]}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            client_handler = threading.Thread(target=handle_client, args=(client_socket, address))
            client_handler.start()
    except KeyboardInterrupt:
        logging.info("Auth and Ticket server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_auth_ticket_server()
