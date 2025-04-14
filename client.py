#!/usr/bin/env python3
import socket
import threading
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# --- Helper functions for sending and receiving messages over TCP ---

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

def sender_thread(sock, recipient_public_key, termination_event):
    """
    Thread that reads user input, encrypts it with the recipient's public key,
    and sends it over the socket.
    """
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
            send_msg(sock, encrypted_msg)
        except Exception as e:
            print("Send error:", e)
            termination_event.set()
            break
        if message.strip().lower() == "quit":
            termination_event.set()
            break

def receiver_thread(sock, own_private_key, termination_event):
    """
    Thread that receives messages from the socket, decrypts them using its own
    private key, and prints them.
    """
    cipher = PKCS1_OAEP.new(own_private_key)
    while not termination_event.is_set():
        try:
            encrypted_msg = recv_msg(sock)
            if encrypted_msg is None:
                print("Connection closed by server.")
                termination_event.set()
                break
            try:
                decrypted_msg = cipher.decrypt(encrypted_msg)
            except Exception as e:
                print("Decryption error:", e)
                continue
            message = decrypted_msg.decode('utf-8')
            print("--\nAlice:", message + "\nYou: ", end="")
            if message.strip().lower() == "quit":
                termination_event.set()
                # Send a "quit" message to the server
                try:
                    send_msg(sock, b"quit")
                except Exception as e:
                    print("Send error:", e)
                break
        except Exception as e:
            print("Receive error:", e)
            termination_event.set()
            break


def main():
    HOST = "127.0.0.1"  # Change to the server's IP address if needed
    PORT = 8009        # Must match the server's port

    # Generate the client's RSA key pair (2048-bit)
    client_key = RSA.generate(2048)
    client_public_key = client_key.publickey()

    # Create a TCP socket and connect to the server.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print("Failed to connect to server:", e)
            return

        # --- Key Exchange ---
        # First, receive the server's public key.
        server_pub_pem = recv_msg(s)
        if server_pub_pem is None:
            print("Failed to receive server's public key.")
            return
        try:
            server_public_key = RSA.import_key(server_pub_pem)
        except Exception as e:
            print("Error importing server's public key:", e)
            return
        # Now, send the client's public key.
        client_pub_pem = client_public_key.export_key()
        send_msg(s, client_pub_pem)

        # --- Start Chat Threads ---
        termination_event = threading.Event()
        send_thread = threading.Thread(target=sender_thread, args=(s, server_public_key, termination_event))
        recv_thread = threading.Thread(target=receiver_thread, args=(s, client_key, termination_event))

        send_thread.start()
        recv_thread.start()

        send_thread.join()
        recv_thread.join()
        print("Chat ended.")

if __name__ == "__main__":
    main()
