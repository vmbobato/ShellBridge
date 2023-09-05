import hashlib
import os
import socket
import subprocess
import time
import ssl

class Server:
    def __init__(self, IP, cert_file, key_file):
        self.CERTFILE = cert_file
        self.KEYFILE = key_file
        self.IP = IP
        self.PORT = 9999
        self.server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile=self.CERTFILE, keyfile=self.KEYFILE)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def go_online(self):
        self.server_s.bind((self.IP, self.PORT))
        self.server_s.listen(1)
        print("Server is up! Waiting on connection...")
        client_socket, client_addr = self.server_s.accept()
        self.secure_conn = self.ssl_context.wrap_socket(client_socket, server_side=True, do_handshake_on_connect=True)
        msg = self.secure_conn.recv(1024 * 60).decode()
        self.secure_conn.sendall(os.getcwd().encode())
        return client_socket, client_addr

    def send(self, msg):
        self.secure_conn.sendall(msg.encode())

    def receive(self):
        msg = self.secure_conn.recv(1024 * 60).decode()
        return msg

    def close(self):
        self.server_s.close()


class Client:
    def __init__(self, skt, addr):
        self.addr = addr
        self.sockt = skt

    def get_addr(self):
        return self.addr


def ip_choice(list_of_ips):
    print("Welcome to FTA Rev")
    ip_to_bind = input("To begin would you like to bind to localhost (127.0.0.1) (Y/n)? ")
    if ip_to_bind.lower() == "y":
        ip = "localhost"
        print(f"Binding socket to {ip}...")
    else:
        print("Ohh you want to go online :) ")
        print("Here are a few options of IP addresses to bind: ")
        i = 1

        for address in list_of_ips:
            print(f"     {i}. {address[4][0]}")
            i += 1

        ip_chosen = int(input("Make a choice based on the number shown before each address: "))
        ip = list_of_ips[ip_chosen - 1][4][0]
        time.sleep(1)
        print(f"Binding socket to {ip}...")
    return ip


#starting up
name = socket.gethostname()
addrs = socket.getaddrinfo(name, None)
ip_socket = ip_choice(addrs)
server = Server(ip_socket, 'server_cert.pem', 'server_key.pem')
client_socket, client_addr = server.go_online()
client = Client(client_socket, client_addr)
remote_dir_active = False
sep = ":"


while True:
    message = server.receive()

    print(f"Command Received: '{message}'")

    if message[0:4] == "put ":
        cmd_div = message.split()

        with open(cmd_div[1], "w") as file:
            while True:
                content = server.receive()
                if not content:
                    file.write(content)
                    break
                file.write(content)
            file.close()

        with open(cmd_div[1], "r") as file2:
            content = file2.read()
            file2.close()
            hash_object = hashlib.sha256(content.encode())
            hex_dig = hash_object.hexdigest()
            file2.close()

        client_hex = server.receive()
        print("\nFile Hash:      ", client_hex)
        print("\nHash Generated: ", hex_dig)

        if client_hex != hex_dig:
            print("\n[!] Cannot confirm file is original. Deleting Now. [!]\n")
            server.send("[!]")
            os.remove(cmd_div[1])
        else:
            server.send("[.]")
            print("\n[.] File is original.")

    elif message[0:4] == "get ":
        cmd_split = message.split()
        with open(cmd_split[1], "r") as filehex:
            file_data = filehex.read()
            hash_object = hashlib.sha256(file_data.encode())
            hex_dig = hash_object.hexdigest()
            print(hex_dig)
            filehex.close()

        with open(cmd_split[1], "r") as file:
            while True:
                content = file.read(1024)
                if not content:
                    server.send(content)
                    break
                server.send(content)
            file.close()
        server.send(hex_dig)
        confirmation = server.receive()

        if confirmation == "[!]":
            print("\n[!] Unable to upload file.\n")
        else:
            print("\nUpload Successful!\n")

    elif message == "exit":
        print("\nClosing Connection.")
        break

    elif message == "chdir":
        if remote_dir_active:
            remote_dir_active = False
        else:
            remote_dir_active = True

    elif message == "ls":
        file_list = os.listdir(os.getcwd())
        file_string = sep.join(file_list)
        server.send(file_string)

    elif message[0:4] == "cdr ":
        if remote_dir_active:
            splt = message.split()
            try:
                os.chdir(splt[1])
                server.send(os.getcwd())
            except:
                print("No dir found.")
        else:
            server.send(os.getcwd())

    elif message[0:3] == "cd ":
        pass

    else:
        output = subprocess.getoutput(message)
        server.send(output)

server.close()
