import socket
import threading
import time
import logging

AUTHENTICATION_SERVER_ADDRESS = ('localhost', 8889)

logging.basicConfig(level=logging.INFO)

def handle_client(client_socket):
    try:
        # Send a welcome message to the client
        client_socket.send(b"Hello Human!\n")

        # Receive and process client requests
        while True:
            request = client_socket.recv(1024).decode('utf-8').strip()
            if not request:
                break  # Break the loop if no data received
            logging.info(f"Received request: {request}")
            messages = request.split('_')
            username, ticket, request = messages[0], messages[1], messages[2]
            if not validate_ticket(username, ticket):
                client_socket.send(b"Invalid ticket.")
                logging.warning(f"Invalid ticket received for {username}.")
                return

            if request.lower() == "time":
                current_time = time.time()
                client_socket.send(str(current_time).encode('utf-8') + b"\n")
                logging.info(f"Sent current time to {username}.")
            else:
                client_socket.send(b"Invalid request. Please send 'time'.\n")
                logging.warning(f"Invalid request received from {username}.")

    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        # Close the client socket when done
        client_socket.close()

def validate_ticket(username, ticket):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(AUTHENTICATION_SERVER_ADDRESS)

        logging.info(f"Authenticating for {username} with ticket {ticket}")
        # Send the username and ticket to the authentication server
        client_socket.send(f"authenticate_{username}_{ticket}".encode('utf-8'))

        # Receive the authentication result from the authentication server
        result = client_socket.recv(1024).decode('utf-8').strip()
        logging.info(f"Authentication result for {username}: {result}")
        if result == "Ok":
            return True
        else:
            return False

def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_address = ('localhost', 8888)
    server_socket.bind(server_address)

    # Enable the server to accept connections
    server_socket.listen(10)
    logging.info(f"Server listening on {server_address[0]}:{server_address[1]}")

    try:
        while True:
            # Wait for a connection
            client_socket, client_address = server_socket.accept()
            logging.info(f"Accepted connection from {client_address}")

            # Create a new thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()

    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    finally:
        # Close the server socket when done
        server_socket.close()

if __name__ == '__main__':
    start_server()
