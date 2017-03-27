# VIKRAM MANJA
# LINUX FILTER
# vmanja
# 3-28-2017

# Flush rules
iptables -F
# Port-forwarding from 2222 -> 22
iptables -t nat -A PREROUTING -p tcp --dport 2222 -j REDIRECT --to-ports 22
# Accept all outbound packets
iptables -A OUTPUT -j ACCEPT
# Block computer from being pinged by all other hosts
iptables -A INPUT  -p icmp --icmp-type echo-request -j DROP
# Block a list of specific IP addresses for all incoming connections
iptables -A INPUT -p tcp -s 221.0.0.0/8 -j REJECT
# Allow Port 22 access (SSH) only from ecn.purdue.edu domain
iptables -A INPUT -p tcp --destination-port 22 -s 172.31.5.3 -j ACCEPT
iptables -A INPUT -p tcp --destination-port 22 -j DROP
# Permit Auth/Ident (port 113) 
iptables -A INPUT -p tcp --destination-port 113 -j ACCEPT
# Allow a random single IP address to access our HTTD server (port 80)
iptables -A INPUT -p tcp -s 172.31.5.4 --destination-port 80 -j ACCEPT
iptables -A INPUT -p tcp --destination-port 80 -j DROP


