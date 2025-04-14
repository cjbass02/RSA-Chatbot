#!/usr/bin/env python3
import socket
import threading
import struct
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def send_msg(sock, msg_bytes):
    """
    Send a message preceded by its 4-byte length.
    """
    msg_len = len(msg_bytes)
    sock.sendall(struct.pack('>I', msg_len) + msg_bytes)

def recvall(sock, n):
    """
    Helper function to receive exactly n bytes (or return None if EOF is reached).
    """
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(sock):
    """
    Receive a message prefixed by its 4-byte length.
    """
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msg_len = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msg_len)

# --- Thread functions for sending and receiving messages ---

def sender_thread(conn, recipient_public_key, termination_event):
    """
    Thread that reads user input, encrypts it with the recipient's public key,
    and sends it over the socket.
    """
    # Create an RSA cipher object for encryption
    cipher = PKCS1_OAEP.new(recipient_public_key)
    while not termination_event.is_set():
        try:
            message = input("You: ")
        except EOFError:
            message = "quit"
        msg_bytes = message.encode('utf-8')
        try:
            encrypted_msg = cipher.encrypt(msg_bytes)
        except Exception as e:
            print("Encryption error:", e)
            continue
        try:
            send_msg(conn, encrypted_msg)
        except Exception as e:
            print("Send error:", e)
            termination_event.set()
            break
        if message.strip().lower() == "quit":
            termination_event.set()
            break

def receiver_thread(conn, own_private_key, termination_event, log_file):
    """
    Thread that receives messages from the socket, decrypts them using its own
    private key, prints them, and (for the server) logs them to a file.
    """
    cipher = PKCS1_OAEP.new(own_private_key)
    while not termination_event.is_set():
        try:
            encrypted_msg = recv_msg(conn)
            if encrypted_msg is None:
                print("Connection closed by client.")
                termination_event.set()
                break
            try:
                decrypted_msg = cipher.decrypt(encrypted_msg)
            except Exception as e:
                print("Decryption error:", e)
                continue
            message = decrypted_msg.decode('utf-8')
            print("--\nBob:", message + "\nYou: ", end="")
            # Log the received message with a timestamp.
            with open(log_file, "a") as f:
                f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + "Bob: " + message + "\n")
            if message.strip().lower() == "quit":
                termination_event.set()
                #close the connection
                #conn.close()
                # Send a "quit" message to the server
                
                send_msg(conn, "quit".encode('utf-8'))

        except Exception as e:
            print("Receive error:", e)
            termination_event.set()
            break

# --- Main server function ---

def main():
    HOST = "0.0.0.0"      # Listen on all interfaces
    PORT = 8009          # Port number
    log_file = "server_chat.log"  # Log file for the chat

    # Generate the server's RSA key pair (2048-bit)
    server_key = RSA.generate(2048)
    server_public_key = server_key.publickey()

    # Create a TCP socket, bind, and listen for a connection.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        print("Connected by", addr)
        with conn:
            # --- Key Exchange ---
            # Send the server's public key first.
            server_pub_pem = server_public_key.export_key()
            send_msg(conn, server_pub_pem)
            # Receive the client's public key.
            client_pub_pem = recv_msg(conn)
            if client_pub_pem is None:
                print("Failed to receive client's public key.")
                return
            try:
                client_public_key = RSA.import_key(client_pub_pem)
            except Exception as e:
                print("Error importing client's public key:", e)
                return

            # --- Start Chat Threads ---
            termination_event = threading.Event()
            send_thread = threading.Thread(target=sender_thread, args=(conn, client_public_key, termination_event))
            recv_thread = threading.Thread(target=receiver_thread, args=(conn, server_key, termination_event, log_file))

            send_thread.start()
            recv_thread.start()

            send_thread.join()
            recv_thread.join()
            print("Chat ended.")

if __name__ == "__main__":
    main()
