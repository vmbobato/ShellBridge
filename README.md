# ShellBridge

This project uses sockets and SSL to create a client/server application. The client connects to a remote server where it gains access of the remote machine. The client can navigate, download and upload files, as well as execute commands for Windows/Linux depending on the OS of the server. 

First run the server:
python3 ShellBridge/server/server.py

The server is given the option on which IP to bind, can be localhost (127.0.0.1) or your private IP address.

When the server is up and running, connect the client:
python3 ShellBridge/client/client.py
