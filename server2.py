import socket
import ssl
import logging

# Configure the logging module to log to a file and print to console
logging.basicConfig(
    level=logging.INFO,             # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    handlers=[
        logging.StreamHandler(),    # Print to the console
        logging.FileHandler('server_log.txt')  # Log to a file
    ]
)

# Log that the server is starting
logging.info("Server is starting...")

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create an SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Wrap the socket with SSL
server_socket = context.wrap_socket(server_socket, server_side=True)

# Bind the socket to a specific address and port
server_socket.bind(('localhost', 12345))

# Start listening for incoming connections
server_socket.listen(5)
logging.info("Server is listening on port 12345...")

try:
    while True:
        # Accept a connection from the client
        client_socket, client_address = server_socket.accept()
        logging.info(f"Connection established with {client_address}")

        try:
            # Receive data from the client (biometric data or authentication request)
            data = client_socket.recv(1024)
            if not data:
                logging.warning("No data received from the client.")
            else:
                logging.info(f"Received data: {data.decode()}")

                # Simulate processing biometric data and authentication
                # In a real application, you would validate the data here
                response = "Authentication success!"
                client_socket.sendall(response.encode())
                logging.info(f"Sent response: {response}")

        except Exception as e:
            logging.error(f"Error occurred during data processing: {e}")
        finally:
            # Close the client connection
            client_socket.close()
            logging.info(f"Connection with {client_address} closed.")

except Exception as e:
    logging.error(f"Server error: {e}")
finally:
    server_socket.close()
    logging.info("Server socket closed.")
