class Ticket:
    pass

class TicketGrantingTicket(Ticket):
    def __Init__(self):
        self.username = ''
        self.password = ''
        self.role = ''
        self.authenticated = ''
        self.domain = ''
        self.ticket_create_date = ''
        self.ticket_expire_date = ''
        self.key = ''

    def set_ticket_info(self, ticket):
        ticket_info = ticket.split(';', 6)
        
        self.username = ticket_info[0]
        self.password = ticket_info[1]
        self.role = ticket_info[2]
        self.domain = ticket_info[3]
        self.create_date = ticket_info[4]
        self.expire_date = ticket_info[5]
        self.key = ticket_info[6]

    def get_username(self):
        return self.username
    
    def get_password(self):
        return self.password
    
    def get_role(self):
        return self.role
    
    def get_authenticated(self):
        return self.authenticated
    
    def get_domain(self):
        return self.domain
    
    def get_create_date(self):
        return self.create_date
    
    def get_expire_date(self):
        return self.expire_date
    
    def get_md5sum(self):
        return self.key

class ServiceTicket(Ticket):
    def __Init__(self):
        self.username = ''
        self.role = ''
        self.authenticated = ''
        self.domain = ''
        self.ticket_create_date = ''
        self.ticket_expire_date = ''
        self.key = ''

    def set_ticket_info(self, ticket):
        ticket_info = ticket.split(';', 6)
        
        self.username = ticket_info[0]
        self.password = ticket_info[1]
        self.role = ticket_info[2]
        self.domain = ticket_info[3]
        self.create_date = ticket_info[4]
        self.expire_date = ticket_info[5]
        self.key = ticket_info[6]

    def get_username(self):
        return self.username

    def get_role(self):
        return self.role
    
    def get_authenticated(self):
        return self.authenticated
    
    def get_domain(self):
        return self.domain
    
    def get_create_date(self):
        return self.create_date
    
    def get_expire_date(self):
        return self.expire_date
    
    def get_md5sum(self):
        return self.key
