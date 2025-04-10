import socket
import ssl

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket with SSL for secure communication
client_socket = ssl.wrap_socket(client_socket, keyfile=None, certfile=None, server_side=False)

# Connect to the server (authentication engine)
client_socket.connect(('localhost', 12345))

# Send biometric data (fingerprint, face, iris, etc.)
biometric_data = "Fingerprint data: XYZ"
client_socket.sendall(biometric_data.encode())

# Receive response from the server
response = client_socket.recv(1024)
print(f"Server response: {response.decode()}")
# Close the connection
client_socket.close()
