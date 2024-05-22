#!/usr/bin/python
# Name: Chen Liang
# College: Dublin Institute of Technology
# Date: 06 Apr 2012
# Description: SSH server program

import socket
import sys
import os
import threading


class ClientThread (threading.Thread):
    def __init__(self, channel, details):
        self.conn = channel
        self.addr = details
        threading.Thread.__init__(self)

    def run(self):
        print('Received connection from ', self.addr[0])
        f = open('ssh.key', 'r')  # open ssh.key to read the key
        key_info = f.readline()
        key_info_list = key_info.split(';', 3)

        st_info = self.conn.recv(1024)
        username, st = st_info.split(';', 1)

        if key_info_list[3] == st:
            # Create home directory for the user if the directory doesn't exist
            # d = os.path.dirname(username)

            if os.path.exists(username):
                os.chdir(username)
            else:
                os.makedirs(username)
                os.chdir(username)

            print("Authenticated the service ticket")
            self.conn.send('foreign remote shell~>')
            print("Shell name sent")

            # while True:
            try:
                print('Waiting for command')

                command = self.conn.recv(1024)
                print(command)
                result = ''
                command_list = command.split(' ', 1)

                if command_list[0] == 'ls':
                    print('Client request ls')
                    for dirname, dirnames, filenames in os.walk('.'):
                        for subdirname in dirnames:
                            result += os.path.join(dirname, subdirname)
                            result += '\n'
                        for filename in filenames:
                            result += os.path.join(dirname, filename)
                            result += '\n'
                    self.conn.send(result)
                    print('results returned')

                elif command_list[0] == 'touch':
                    # os.walk(username)
                    print('Client created file')
                    f = open(command_list[1], 'w')
                    f.close
                    self.conn.send("File " + command_list[1] + " created")
                    print('results returned')

                elif command_list[0] == 'exit':
                    print('Client request exit')
                    self.conn.send('exit_confirm')
                    print('Exit confirmed')

                elif command_list[0] == 'hostname':
                    print('Client request hostname')
                    self.conn.send(HOST)
                    print('Hostname returned')

                elif command_list[0] == 'ifconfig':
                    print('Client request IP address')
                    self.conn.send(IP)
                    print('IP address returned')

                else:
                    print('Client entered incorrect command')
                    self.conn.send('ls\tifconfig\thostname\texit\ttouch')
                    print('List of command returned')

            except (KeyboardInterrupt, SystemExit):
                return 0

            os.chdir("..")
        else:
            print("Fail to authenticat the service ticket")
            self.conn.send('fail')
            print("Result of failed authentication sent")

        self.conn.close()


SERVICE_NAME = "ssh"  # The service name
HOST = socket.gethostname()  # The host name
DOMAIN = 'foreign.virtual.vm'  # The domain name
IP = socket.gethostbyname(HOST)  # The IP address

SSHD_HOST = socket.gethostname()  # Get SSH Server Hostname
SSHD_PORT = 2222  # Port to simuate ssh server

KRB_HOST = socket.gethostname()  # Get Kerberos key Distribution Centre Hostname
KRB_PORT = 50001  # The KDC simulation's port number


def sshd_sim():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", SSHD_PORT))
        s.listen(1)
        print('SSH Server simulation started.')

        # create a thread for every connection
        while True:
            channel, details = s.accept()
            c_th = ClientThread(channel, details)
            c_th.start()

        s.close()
        sys.exit(0)

    except (KeyboardInterrupt, SystemExit):
        s.close()
        print("\nKeyboard interrupted, existing...")
        sys.exit(1)

    else:
        s.close()
        sys.exit(1)


def request_shared_key():
    # Get shared secure ticket from KDC (kdc_sim.py)
    krb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    krb_socket.connect(("127.0.0.1", KRB_PORT))
    message = ''
    message += 'req_sk;'
    message += (SERVICE_NAME + ';')
    message += (DOMAIN + ';')
    message += (IP)

    krb_socket.send(message)  # Send service information to KDC
    share_key = krb_socket.recv(1024)  # Recieve reply from KDC

    # Check the replied message
    if share_key != 'fail':
        f = open(SERVICE_NAME + '.key', 'w')  # Save the shared key
        f.write(share_key)
        f.close
        krb_socket.close
        return True
    else:
        krb_socket.close
        return False


if __name__ == '__main__':
    if request_shared_key():
        print('Received shared key from KDC')
        sshd_sim()
    else:
        print('Service was not found in KDC\'s service database.')

    sys.exit(0)
