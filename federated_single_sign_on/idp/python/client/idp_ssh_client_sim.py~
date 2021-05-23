#!/usr/bin/python
# Name: Chen Liang
# College: Dublin Institute of Technology
# Date: 06 Apr 2012
# Description: SSH client program simulation

import socket
import os
import sys
import getpass

from Ticket import TicketGrantingTicket
from Ticket import ServiceTicket

HOST = socket.gethostname() # The host name
IP = "127.0.0.1" # The IP address

KRB_HOST = "127.0.0.1" # Kerberos key Distribution Centre Hostname
KRB_PORT = 50002 # The KDC simulation's port number

SSHD_HOST = "127.0.0.1" # SSH Server Hostname
SSHD_PORT = 2224 # The SSH server simulation's port number

FOREIGN_SSHD_HOST = socket.gethostname() # SSH Server Hostname
FOREIGN_SSHD_PORT = 2222 # The SSH server simulation's port number

SAML_AAI_KERBEROS_HOST = "127.0.0.1" # SSH Server Hostname
SAML_AAI_KERBEROS_PORT = 1235 # The SSH server simulation's port number

# Make sure the end-user has registered in KDC
def authentication():
    try:
        krb_sok = socket.socket (socket.AF_INET, socket.SOCK_STREAM) # KRB socket
        krb_sok.connect(("127.0.0.1", KRB_PORT))
        print 'Connecting to', HOST, '...'
        
        name = raw_input('Username: ')
        password = getpass.getpass('Password: ') 
        
        krb_sok.send('req_tgt;' + name + ';' + password)
        # Recieve returned ticket information
        ticket = krb_sok.recv(1024)
        
        if ticket != 'fail':
            # Convert into ticket
            save_tgt(ticket)
            krb_sok.close()
            return True
        else:
            krb_sok.close()
            return False
    except (KeyboardInterrupt, SystemExit):
        print "existing..."
        krb_sok.close
    else:
        pass

# Save ticket granting ticket from KDC
def save_tgt(tgt_info):
    # Set ticket granting ticket content in memory
    tgt.set_ticket_info(tgt_info)
    print 'Recieved and saved Ticket Granting Ticket.'

    # Save ticket granting ticket content in file
    f = open('tgt.key', 'w')
    f.write(tgt_info)
    f.close()

def get_tgt_info():
    print '\nTicket Granting Ticket:'
    print 'Username:', tgt.get_username()
    print 'Password:', tgt.get_password()
    print 'Role:', tgt.get_role()
    print 'Domain:', tgt.get_domain()
    print 'Ticket Create Date:', tgt.get_create_date()
    print 'Ticket Expire Date:', tgt.get_expire_date()
    print 'Key:', tgt.get_md5sum()
    print '\n'

# Get service ticket from KDC to access services
def request_service_ticket():
    krb_sok = socket.socket (socket.AF_INET, socket.SOCK_STREAM) # KRB socket
    f = open('tgt.key', 'r')
    tgt_info = f.readline()
    f.close()
    tgt_info_list = tgt_info.split(';', 7)

    krb_sok.connect((KRB_HOST, KRB_PORT))
    print 'Connecting to', HOST, '...'
    krb_sok.send('req_st;' + tgt_info)

    answer = krb_sok.recv(1024)

    if answer == 'fail':
        return 'fail'
    else:
        krb_sok.send('ssh')
        st_info = krb_sok.recv(1024)
        return tgt_info_list[0] + ';' + st_info

# Get service ticket from KDC for SAML-AAI/Kerberos middleware
def request_st_sak():
    krb_sok = socket.socket (socket.AF_INET, socket.SOCK_STREAM) # KRB socket
    f = open('tgt.key', 'r')
    tgt_info = f.readline()
    f.close()
    tgt_info_list = tgt_info.split(';', 7)

    krb_sok.connect((KRB_HOST, KRB_PORT))
    print 'Connecting to', HOST, '...'
    krb_sok.send('req_st_sak;' + tgt_info)

    answer = krb_sok.recv(1024)

    if answer == 'fail':
        return 'fail'
    else:
        krb_sok.send('saml-aai-kerberos')
        st_info = krb_sok.recv(1024)
        print tgt_info_list[0] + ';' + st_info
        return tgt_info_list[0] + ';' + st_info


# Simple simulation of ls
def ls_sim():
    for dirname, dirnames, filenames in os.walk('.'):
        for subdirname in dirnames:
            print os.path.join(dirname, subdirname)
        for filename in filenames:
            print os.path.join(dirname, filename)

# Simluation of a local Unix/Linux shell
def shell_sim():
    while True:
        command = raw_input('local shell~>')
        if command == 'ls':
            ls_sim()
        
        elif command == 'exit':
            sys.exit(0)
        
        elif command == 'hostname':
            print HOST
        
        elif command == 'ifconfig':
            print IP
        
        elif command == 'ssh remote.home.virtual.vm':
            st_info = request_service_ticket() # Request Service Ticket
            print st_info
            if st_info != 'fail':
                ssh_local(st_info) # Simulation of SSH
            else:
                print 'Fail to request service ticket'
        
        elif command == 'ssh foreign.virtual.vm':
            st_sak_info = request_st_sak() # Request Service Ticket
            if st_sak_info != 'fail':
                st_info = request_foreign_st(st_sak_info) # Simulation of SSH
                ssh_foreign(st_info)
            else:
                print 'Fail to request service ticket'
        
        elif command == 'klist':
            get_tgt_info()
        
        else:
            print 'ls\tifconfig\thostname\texit\tklist\tssh remote.home.virtual.vm\tssh foreign.virtual.vm'

def request_foreign_st(st_sak_info):
    # authenticate the service ticket of SAML-AAI/Kerberos Proxy first
    saml_aai_kerberos_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM) # SSH socket
    saml_aai_kerberos_socket.connect((SAML_AAI_KERBEROS_HOST, SAML_AAI_KERBEROS_PORT))
    # Send service ticket to ssh server
    saml_aai_kerberos_socket.send(st_sak_info)
    
    # Recieve single sign-on reply
    result = saml_aai_kerberos_socket.recv(1024)
    
    if result == 'ok':
        f = open('tgt.key', 'r')
        tgt_info = f.readline()
        f.close()
        tgt_info_list = tgt_info.split(';', 7)
        
        assertion = tgt_info_list[0] + ';' # Username
        assertion += tgt_info_list[2] + ';' # Role
        assertion += tgt_info_list[4] # Domain name
        saml_aai_kerberos_socket.send(assertion)

        st_info = saml_aai_kerberos_socket.recv(1024)
        saml_aai_kerberos_socket.close()
        return st_info
    
    else:
        saml_aai_kerberos_socket.close()

def ssh_local(st_info):
    ssh = socket.socket (socket.AF_INET, socket.SOCK_STREAM) # SSH socket
    ssh.connect((SSHD_HOST, SSHD_PORT))
    # Send service ticket to ssh server
    ssh.send(st_info)
    
    # Recieve single sign-on reply
    shell_name = ssh.recv(1024)

    if shell_name != 'fail':
        results = ''
        
        while results != 'exit_confirm':
            command = raw_input(shell_name)
            ssh.send(command)
            results = ssh.recv(1024)
            if results != 'exit_confirm':
                print results
            else:
                pass
    else:
        print 'Service ticket failed to authenticate'

    ssh.close()
    print 'exiting...'

def ssh_foreign(st_info):
    ssh_foreign_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM) # SSH socket
    ssh_foreign_socket.connect((FOREIGN_SSHD_HOST, FOREIGN_SSHD_PORT))
    # Send service ticket to ssh server
    ssh_foreign_socket.send(st_info)
    
    # Recieve single sign-on reply
    shell_name = ssh_foreign_socket.recv(1024)
    
    if shell_name != 'fail':
        results = ''
        
        while results != 'exit_confirm':
            command = raw_input(shell_name)
            ssh_foreign_socket.send(command)
            results = ssh_foreign_socket.recv(1024)
            if results != 'exit_confirm':
                print results
            
            else:
                pass
    
    else:
        print 'Service ticket failed to authenticate'
    
    ssh_foreign_socket.close()
    print 'exiting...'

if __name__ == '__main__':
    tgt = TicketGrantingTicket() # Ticket granting ticket
    st = ServiceTicket() # Service Ticket

    try:
        if authentication():
            shell_sim() # Start shell simulation
        else:
            print 'Unsuccessful authentication.'
    except (KeyboardInterrupt, SystemExit):
        print "\nexisting..."
        sys.exit(1) 
    else:
        sys.exit(1)
