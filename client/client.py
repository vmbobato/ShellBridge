import hashlib
import os
import socket
import time
import ssl
from pyfiglet import Figlet
from encryption_scripts import Encryption_Object, knapsack_publicKey_gen


class Client:
    def __init__(self, IP, cert_file, key_file):
        self.CERTFILE = cert_file
        self.KEYFILE = key_file
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverAddr = IP
        self.serverPort = 9999
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.ssl_context.load_cert_chain(certfile=self.CERTFILE, keyfile=self.KEYFILE)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def connect(self):
        self.client_socket.connect((self.serverAddr, self.serverPort))
        self.secure_client_socket = self.ssl_context.wrap_socket(self.client_socket, server_hostname=self.serverAddr)
        self.secure_client_socket.sendall('CON'.encode())
        dir = self.secure_client_socket.recv(1024 * 60).decode()
        print("MESSAGE:::::::::::", dir)
        return self.serverAddr, dir


    def send(self, msg):
        self.secure_client_socket.sendall(msg.encode())

    def receive(self):
        msg = self.secure_client_socket.recv(1024 * 60).decode()
        return msg


class Server:
    def __init__(self, addr, dir):
        self.addr = addr
        self.current_directory = dir

    def get_addr(self):
        return self.addr

    def get_cd(self):
        return self.current_directory

    def update_cwd(self, directory):
        self.current_directory = directory


def ip_choice():
    valid = False
    IP_val = input("Enter IP (_._._._): ")
    while not valid:
        ip_list = IP_val.split(".")
        if len(ip_list) == 4:
            i = 0
            for value in ip_list:
                try:
                    int(value)
                    i += 1
                except ValueError:
                    continue
            if i == 4:
                print("Thank you, connecting now...")
                valid = True
            else:
                IP_val = input("Not valid format, try again: ")
        else:
            IP_val = input("Not valid format, try again: ")
    return IP_val


figlet = Figlet(font='slant')
text = figlet.renderText('Shell Bridge')

print(text)
print("You will be offered a command line to download and upload files to a remote server. ")
print("You will also be able to navigate through your machine and the remote machine with commands similar")
print("to Linux/UNIX systems. REMINDER this application is case sensitive!")
print("\nType 'h' or 'help' for help on the commands.\n")
print("But first input an IP address of the server to connect to...")

# Include the server Address
client = Client(ip_choice(), 'client_cert.pem', 'client_key.pem')
server_addr, dir = client.connect()
server = Server(server_addr, dir)
remote_dir_active = False
sep = ':'

while True:

    if not remote_dir_active:
        directory = os.getcwd()
    else:
        directory = server.get_cd()

    command = input(f"\n{directory}>$ ")
    client.send(command)

    if command[0:4] == "get ":
        cmd_div = command.split()

        with open(cmd_div[1], "w") as file:
            while True:
                content = client.receive()
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

        client_hex = client.receive()
        print("\nFile Hash Received         : ", client_hex)
        print("\nHash Generated (SHA 256):  : ", hex_dig)

        if client_hex != hex_dig:
            client.send("[!]")
            decision = input("\n[!] Cannot confirm file is safe. Delete it (Y/n)? ")
            if decision.lower() == "y":
                try:
                    os.remove(cmd_div[1])
                    print("\n[.] File has been deleted.")
                except FileNotFoundError:
                    print("\n[!] File can't be deleted. Try again later.")
            else:
                print("\nOkay... File will not be deleted.")
        else:
            client.send("[.]")
            print("\n[.] File Download Successful.")

    elif command[0:4] == "put ":
        cmd_split = command.split()
        with open(cmd_split[1], "r") as filehex:
            file_data = filehex.read()
            hash_object = hashlib.sha256(file_data.encode())
            hex_dig = hash_object.hexdigest()
            filehex.close()

        with open(cmd_split[1], "r") as file:
            while True:
                content = file.read(1024)
                if not content:
                    client.send(content)
                    break
                client.send(content)
            file.close()
        client.send(hex_dig)
        confirmation = client.receive()

        if confirmation == "[!]":
            print("\n[!] Unable to upload file. Server could not confirm whether file is original.")
        else:
            print("\n[.] Upload Successful!")

    elif command == "exit":
        client.send(command)
        print("\nClosing connection...")
        time.sleep(2)
        print("\n[.] Done!")
        client.send(command)
        break

    elif command == "chdir":
        print("\nChanging machine file system...")
        if remote_dir_active:
            remote_dir_active = False
        else:
            remote_dir_active = True
        print("\nDone!")

    elif command == "ls":
        if remote_dir_active:
            print()
            file_str = client.receive()
            file_list = file_str.split(sep)
            i = 1
            for files in file_list:
                print(f"{i}. {files}")
                i += 1
        else:
            file_list = os.listdir(os.getcwd())
            i = 1
            print()
            for files in file_list:
                print(f"{i}. {files}")
                i += 1

    elif command[0:3] == "cd ":
        if remote_dir_active:
            print("\n[!] Remote Dir Active, to navigate in your machine deactivate remote dir.")
            pass
        else:
            cmd = command.split()
            try:
                os.chdir(cmd[1])
            except:
                print("\n[!] No Dir Found!")

    elif command[0:4] == "cdr ":
        if remote_dir_active:
            output = client.receive()
            server.update_cwd(output)
        else:
            print("\n[!] Remote machine Not active")

    elif command.lower() == "help" or command.lower() == "h":
        print("""\nThe commands for the application:\n
        - put ___ : upload a file to the server.
        - get ___ : download file from server.
        - ls ____ : list contents of current directory.
        - chdir _ : change in between machines (local/machine/client <--> remote/machine/server).
        - cdr ___ : change directory. (remote machine).
        - cd ____ : change directory. (local machine).
        - exit __ : close application on both sides.""")

    else:
        output = client.receive()
        print("\n" + output)

client.s.close()
