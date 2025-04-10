import socket
import ssl

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket with SSL for secure communication
server_socket = ssl.wrap_socket(server_socket, keyfile="server.key", certfile="server.crt", server_side=True)

# Bind the socket to a specific address and port
server_socket.bind(('localhost', 12345))

# Start listening for incoming connections
server_socket.listen(5)
print("Server is listening...")

# Accept a connection from the client
client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address} established.")

# Receive data from the client (biometric data or authentication result)
data = client_socket.recv(1024)
print(f"Received data: {data.decode()}")

# Respond to the client
client_socket.sendall("Authentication success!".encode())

# Close the connection
client_socket.close()
server_socket.close()
