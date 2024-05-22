#!/usr/bin/python
# Name: Chen Liang
# College: Dublin Institute of Technology
# Date: 06 Apr 2012
# Description: Middleware to request service ticket for end-users

import socket
import sys
import threading
import xml.etree.ElementTree as xml


class ClientThread (threading.Thread):

    KRB_HOST = socket.gethostname()  # Get Kerberos key Distribution Centre Hostname
    KRB_PORT = 50001  # The KDC simulation's port number

    def __init__(self, channel, details):
        self.conn = channel
        self.addr = details
        threading.Thread.__init__(self)

    def run(self):
        print('Received connection from ', self.addr[0])

        foreign_user_info = self.conn.recv(1024)

        foreign_user_info_list = foreign_user_info.split(';', 1)

        if foreign_user_info_list[0] == 'req_tgt_foreign':
            print(foreign_user_info_list[1])
            detailed_info = foreign_user_info_list[1].split(';', 2)
            username = detailed_info[0]
            domain = detailed_info[1]
            permission = detailed_info[2]

            provisioned_user_info = self.exist_user(username,
                                                    domain, permission)

            if provisioned_user_info == 'fail':
                provisioned_user_info = self.provision_user(username,
                                                            domain, permission)
            else:
                pass

            print(provisioned_user_info)
            # Request TGT on behalf of the end-user from home.virtual.vm
            tgt_info = self.s4u2selfuser(provisioned_user_info)
            # Reqeust ST on behalf of the end-user from home.virtual.vm
            st_info = self.s4u2selfproxy(tgt_info)
            self.conn.send(st_info)
            print(st_info)
            print('Reply sent')

        else:
            pass

        self.conn.close()

    # Request TGT on behalf of the end-user from the "home.virtual.vm"
    def s4u2selfuser(self, provisioned_user_info):
        detailed_info = provisioned_user_info.split(';', 3)
        username = detailed_info[0]
        password = detailed_info[1]

        krb_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)  # SSH socket
        krb_socket.connect(("127.0.0.1", KRB_PORT))

        message = 'req_tgt;'
        message += username
        message += ';'
        message += password

        # Request TGT
        krb_socket.send(message)
        tgt_info = krb_socket.recv(1024)
        krb_socket.close()
        return tgt_info

    def s4u2selfproxy(self, tgt_info):
        krb_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)  # KRB socket
        krb_socket.connect(("127.0.0.1", KRB_PORT))

        message = 'req_st;'
        message += tgt_info

        krb_socket.send(message)

        answer = krb_socket.recv(1024)

        if answer == 'fail':
            krb_socket.close()
            return 'fail'
        else:
            krb_socket.send('ssh')
            st_info = krb_socket.recv(1024)
            krb_socket.close()
            return st_info

    def exist_user(self, username, domain, permission):
        try:
            # Parse the user database
            tree = xml.parse("foreignuserdatabase.xml")
            doc = tree.getroot()  # Get the root node

            # Check the username and password
            for user in doc:
                if user[0].text == username:
                    self.user = user
                    provisioned_user_info = ''
                    provisioned_user_info += user[0].text
                    provisioned_user_info += ';'
                    provisioned_user_info += user[1].text
                    provisioned_user_info += ';'
                    provisioned_user_info += user[2].text
                    provisioned_user_info += ';'
                    provisioned_user_info += user[3].text

                    return provisioned_user_info

            return 'fail'
        except:
            return 'fail'
        else:
            pass

    # Provisioning the user to the foreign user database
    def provision_user(self, foreign_username, foreign_domain, foreign_permission):
        try:
            user_info = ''

            # Parse the user database
            tree = xml.parse("foreignuserdatabase.xml")
            doc = tree.getroot()  # Get the root node

            user = xml.Element('user')

            username = xml.SubElement(user, 'username')
            username.text = foreign_username
            user_info += foreign_username
            user_info += ';'

            password = xml.SubElement(user, 'password')
            password.text = "321"
            user_info += '321'
            user_info += ';'

            permission = xml.SubElement(user, 'permission')
            permission.text = foreign_permission
            user_info += foreign_permission
            user_info += ';'

            domain = xml.SubElement(user, 'domain')
            domain.text = foreign_domain
            user_info += foreign_domain

            doc.append(user)

            file = open("foreignuserdatabase.xml", 'w')
            xml.ElementTree(doc).write(file)

            print(user_info)
            return user_info

        except:
            user_info = ''

            users = xml.Element('users')
            user = xml.SubElement(users, 'user')

            username = xml.SubElement(user, 'username')
            username.text = foreign_username
            user_info += foreign_username
            user_info += ';'

            password = xml.SubElement(user, 'password')
            password.text = '321'
            user_info += '321'
            user_info += ';'

            permission = xml.SubElement(user, 'permission')
            permission.text = foreign_permission
            user_info += foreign_permission
            user_info += ';'

            domain = xml.SubElement(user, 'domain')
            domain.text = foreign_domain
            user_info += foreign_domain

            file = open("foreignuserdatabase.xml", 'w')
            xml.ElementTree(users).write(file)

            print(user_info)
            return user_info

        else:
            return 'not created'


HOST = socket.gethostname()  # The host name
DOMAIN = 'foreign.virtual.vm'  # The domain name
IP = socket.gethostbyname(HOST)  # The IP address

MIDDLE_HOST = socket.gethostname()  # Get middleware Server Hostname
MIDDLE_PORT = 1234  # Port to simuate middleware server

KRB_HOST = socket.gethostname()  # Get Kerberos key Distribution Centre Hostname
KRB_PORT = 50001  # The KDC simulation's port number


def saml_aai_kerberos_sim():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", MIDDLE_PORT))
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


if __name__ == '__main__':
    saml_aai_kerberos_sim()
    sys.exit(0)
