import socket
import re
import whois
import sys

#Recon 1st step
print("\nStep 1: Collecting intial information\n")

#Reading domain from a text file
DomainList=open('domain.txt','r')
ipAdd = ""

for D in DomainList:
    ipAdd = D
    print("Domain IP Address: ")
    print(D.strip())
    WhoisData=whois.whois(D.strip())
    print("Expiration Date: ")
    print(WhoisData.expiration_date)
    print("Creation Date: ")
    print(WhoisData.creation_date)
    print("Updated Date: ")
    print(WhoisData.updated_date)
    print("Domain Name: ")
    print(WhoisData.domain)

print("\n\n")

#Recon 2nd step
print("Step 2: Finding active addresses\n")

net1 = ipAdd
net2 = net1.split('.')
a = '.'
net3 = net2[0] + a + net2[1] + a + net2[2] + a
stn1 = int(input("Enter the starting number of the IP range: "))
edn1 = int(input("Enter the ending number of the IP range: "))

#To ensure that the last address is included
edn1 = edn1 + 1

#Establishing connection with the defined IP addresses to check if it is alive
def scan(addr):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((addr,135))
    if result == 0 :
        return 1
    else :
        return 0

#Printing live addresses
def run1():
    ctr = 0
    for ip in range(stn1,edn1):
        addr = net3+str(ip)
        if (scan(addr)):
            ctr=ctr+1
            print (addr, "this address is live")
    return ctr

counter=run1()

#If there are no live addresses, exit system
if(counter==0):
    sys.exit("There are no live addresses")

#Recon 3rd and 4th step
print("\n\nStep 3: Finding open ports and services running on them")

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

port_min = 0

port_max = 65535

open_ports = []

ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")

while True:
    #Specifying the range of ports
    print("Please enter the range of ports you want to scan")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))

    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

#Trying to connect to the specified range of ports to check if it is opened
for port in range(port_min, port_max + 1):

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((ip_add_entered, port))
            open_ports.append(port)

    except Exception as ex:

        pass

#Finding services that are running on opened ports
def find_service_name(open_ports):

    open_ports=list(open_ports)

    for port in open_ports:

        print("Port: %s => service name: %s" % (port, socket.getservbyport(port)))

find_service_name(open_ports)