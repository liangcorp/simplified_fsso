#!/usr/bin/python
# Name: Chen Liang
# College: Dublin Institute of Technology
# Date: 06 Apr 2012
# Description: Kerberos Key Distribution Centre Simuluation

import socket
import sys
import threading
import xml.etree.ElementTree as xml
import datetime
import hashlib

class ClientThread (threading.Thread):
    def __init__(self, channel, details):
        self.conn = channel
        self.addr = details
        threading.Thread.__init__ ( self )

    def run(self):
        print 'Received connection from ', self.addr[0]
        message = self.conn.recv(1024)
        data_list = message.split(';', 1)
        
        if data_list[0] == 'req_tgt':
            print 'Recieved TGT requst.'
            print data_list[1]
            username, password = data_list[1].split(';', 1)
            # Check the username and password
            auth_successful = self.auth_user(username, password)            
            
            if auth_successful:
                tgt_message = self.create_tgt() # Create ticket granting ticket
                self.conn.send (tgt_message) # Send ticket granting ticket
                print 'Ticket Granting Ticket sent.'
            else:
                self.conn.send('fail')
                print 'Failed to authenticate.'
            
            print 'Request answered.'
            self.conn.close() # Close connection
        
        elif data_list[0] == 'req_sk':
            print 'Recieved shared key request.'
            
            service_info = data_list[1].split(';', 2)
            auth_successful = self.auth_service(service_info[0], 
                                                service_info[1])
            
            if auth_successful:
                sk_message = self.create_share_key()
                self.conn.send (sk_message)
                print 'Shared Key sent.'
            else:
                self.conn.send('fail')
                print 'Service does not exist in database'
            
            print 'Request answered.'
            self.conn.close() # Close connection
        
        elif data_list[0] == 'req_st':
            print 'Recieved service ticket request.'
            tgt_info = data_list[1].split(';', 6)
            
            auth_successful = self.auth_tgt(tgt_info)
            
            if auth_successful:
                self.conn.send('ok')
                service_name = self.conn.recv(1024)
                st_info = self.create_st(service_name)
                self.conn.send(tgt_info[0] + ';' +st_info)
                print 'Service Ticket sent'
            else:
                print 'User does not seems to be authenticated'
                self.conn.send('fail')
            
            print 'Request answered.'
            self.conn.close() # Close connection
        
        else:
            print 'Recieved unknown request.'
            self.conn.send('unknown request')
            print 'Request answered.'
            self.conn.close() # Close connection

    # Authenticate the user
    def auth_user(self, username, password):
        tree = xml.parse("foreignuserdatabase.xml") # Parse the user database
        doc = tree.getroot() # Get the root node
        print username
        print password
        # Check the username and password
        for user in doc:
            if user[0].text == username and user[1].text == password:
                self.user = user
                print user[0].text
                print user[1].text
                return True
        return False

    # Create Ticket Granting Ticket
    def create_tgt(self):
        ticket_info = ''
        issue_time = datetime.datetime.now()
        expire_time = datetime.datetime.now() + datetime.timedelta(days=1)
        
        for elements in self.user:
            ticket_info += elements.text
            ticket_info += ';'
        
        ticket_info += issue_time.strftime("%Y-%m-%d %H:%M")
        ticket_info += ';'
        ticket_info += expire_time.strftime("%Y-%m-%d %H:%M")
        ticket_info += ';'
        
        hash = hashlib.md5(ticket_info) # Hash the shared key informations
        hash_hex = hash.hexdigest()
        
        ticket_info += str(hash_hex)
        
        f = open(self.user[0].text, 'w') # Keep recodes of authenticated users
        f.write(ticket_info)
        f.close
        
        return ticket_info
  
    # Authenticate the service
    def auth_service(self, service_name, service_domain_name):
        tree = xml.parse("servicedatabase.xml") # Parse the service database
        doc = tree.getroot() # Get the root node
        
        # Compare the service name and domain name against the database
        for service in doc:
            if service[0].text == service_name and \
               service[1].text == service_domain_name:
                self.service = service
                return True
        return False

    # Create Share Key
    def create_share_key(self):
        share_key = ''
        
        for elements in self.service:
            share_key += elements.text
            share_key += ';'
        
        hash = hashlib.md5(share_key) # Hash the shared key informations
        hash_hex = hash.hexdigest()
        
        share_key += str(hash_hex)
        return share_key

    def auth_tgt(self, tgt_info):
        print str(tgt_info[0])

        f = open(str(tgt_info[0]), 'r')
        
        if f == None:
                print 'User not found'
                return False
        else:
            key_info = f.readline()
            f.close()
            
            key_info_list = key_info.split(';', 6)
            
            if tgt_info[0] == key_info_list[0] and \
                tgt_info[3] == key_info_list[3] and \
                tgt_info[4] < key_info_list[5] and \
                tgt_info[6] == key_info_list[6]:
                return True
            else:
                return False

    def create_st(self, service_name):
        tree = xml.parse("servicedatabase.xml") # Parse the service database
        doc = tree.getroot() # Get the root node
        st_info = ''
        
        # Compare the service name and domain name against the database
        for service in doc:
            if service[0].text == service_name:
                self.service = service
                break
        
        for elements in self.service:
            st_info += elements.text
            st_info += ';'
        
        hash = hashlib.md5(st_info) # Hash the shared key informations
        hash_hex = hash.hexdigest()
        
        return str(hash_hex)

#############################################################
#   Followings are outside of the ClientThread class
#############################################################

HOST = socket.gethostname() # Get the hostname
LOCAL_PORT = 50001 # Define port number
IP = socket.gethostbyname(HOST) # get IP address of the KSIM Server

if __name__ == '__main__':
    try:
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM) # create socket
        s.bind(("127.0.0.1", LOCAL_PORT))
        s.listen(1)
        print 'KDC Simulation Server started at: 127.0.0.1'

        # create a thread for every connection
        while True:
            channel, details = s.accept()
            c_th = ClientThread(channel, details)
            c_th.start()
        s.close()

    except (KeyboardInterrupt, SystemExit):
        s.close()
        print "\nKeyboard interrupted, existing..."
        sys.exit(1)

    else:
        s.close()
        sys.exit(1) 
