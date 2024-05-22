#!/usr/bin/python
# Name: Chen Liang
# College: Dublin Institute of Technology
# Date: 06 Apr 2012
# Description: Middleware to request service ticket for end-users

import socket
import sys
import threading


class ClientThread (threading.Thread):
    FOREIGN_MIDDLE_HOST = socket.gethostname()  # Get middleware Server Hostname
    FOREIGN_MIDDLE_PORT = 1234  # Port to middleware server

    def __init__(self, channel, details):
        self.conn = channel
        self.addr = details
        threading.Thread.__init__(self)

    def run(self):
        print('Received connection from ', self.addr[0])
        f = open('saml-aai-kerberos.key', 'r')  # open ssh.key to read the key
        key_info = f.readline()
        key_info_list = key_info.split(';', 3)

        st_info = self.conn.recv(1024)
        username, st = st_info.split(';', 1)

        if key_info_list[3] == st:
            # Create home directory for the user if the directory doesn't exist
            # d = os.path.dirname(username)

            print("Authenticated the service ticket")
            self.conn.send('ok')
            assertion = self.conn.recv(1024)

            foreign_st_info = self.send_assertion(assertion)
            self.conn.send(foreign_st_info)
            print(foreign_st_info)
            # self.s4u2selfuser(provisioned_user_info)

        else:
            print("Fail to authenticat the service ticket")
            self.conn.send('fail')
            print("Result of failed authentication sent")

        self.conn.close()

    def send_assertion(self, assertion):
        foreign_sak_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        foreign_sak_socket.connect(
            (self.FOREIGN_MIDDLE_HOST, self.FOREIGN_MIDDLE_PORT))

        message = 'req_st_foreign;'
        message += assertion
        print(message)
        foreign_sak_socket.send(message)  # Send assertion message
        # Wait for the reply from service provider's SAML-AAI/Kerberos middleware
        foreign_st_info = foreign_sak_socket.recv(1024)

        foreign_sak_socket.close()

        return foreign_st_info


HOST = socket.gethostname()  # The host name
DOMAIN = 'home.virtual.vm'  # The domain name
IP = socket.gethostbyname(HOST)  # The IP address
SERVICE_NAME = 'saml-aai-kerberos'  # Service name

MIDDLE_HOST = socket.gethostname()  # Get middleware Server Hostname
MIDDLE_PORT = 1235  # Port to middleware server

KRB_HOST = socket.gethostname()  # Get Kerberos key Distribution Centre Hostname
KRB_PORT = 50002  # The KDC simulation's port number


def saml_aai_kerberos_sim():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((MIDDLE_HOST, MIDDLE_PORT))
        s.listen(1)
        print('Middle Server simulation started.')

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
    krb_socket.connect((KRB_HOST, KRB_PORT))
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
    request_shared_key()
    saml_aai_kerberos_sim()
    sys.exit(0)
