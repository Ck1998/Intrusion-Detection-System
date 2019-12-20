import socket
import datetime
import struct
import textwrap
import os 
import time

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

# Global Variable
currentdt = datetime.datetime.now() 
current_dt = currentdt.strftime("%Y-%m-%d")
hp_ip = '192.168.43.7'
hp_port = 0
ids_ip = '192.168.43.6'
ids_port = 0
broadcast_ip = '192.168.43.255'
SYN_PACKET_DICT = {}
PING_FLOOD_DICT = {}
# Special IPs

# hp_ip = ''          # Honeypot IP 
# hp_port =           # Honeypot Port
# ids_ip = ''         # IDS IP
# ids_port =          # IDS Port

# Log Files
ids_log_files = open('/var/log/ids_log/ids-'+current_dt+'.log', "a+")

# Counters
ping_flood_counter = 0
udp_flood_counter = 0
syn_flag_counter = 0

class Ethernet:

    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]

class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    # Returns properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))

class ICMP:

    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]

class TCP:

    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]

class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data

class UDP:

    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]

class Pcap:

    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'a+b')
        self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)
        #pyAesCrypt.encryptFile('/var/log/rh_log/capture-'+current_dt+'.pcap', '/var/log/rh_log/encrypted-capture-'+current_dt+'.pcap.aes', password, buffersize)

    def close(self):
        self.pcap_file.close()

# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# /*******************************************/
# /          REDIRECT FUNCTION                /
# /*******************************************/

def redirect_traffic_to_rh(ip):
    
    # HTTP Traffic
    os.system('sudo ufw route allow in on enp0s8 to 192.168.43.7 port 80 proto tcp from '+ip)

    # HTTPS Traffic
    os.system('sudo ufw route allow in on enp0s8 to 192.168.43.7 port 443 proto tcp from '+ip)

    # ICMP Traffic
    os.system('sudo ufw route allow in on enp0s8 to 192.168.43.7 from '+ip)

    os.system("sudo ufw disable")

    os.system("sudo ufw enable")
    
# /*******************************************/
# /         REDIRECT FUNCTION ENDS            /
# /*******************************************/

# /*******************************************/
# /          ICMP ANALYSIS STARTS             /
# /*******************************************/
def PingFloodCheck(ip, data):
    if ip in PING_FLOOD_DICT:
        if PING_FLOOD_DICT[ip] > 5:
            return True
        else:
            PING_FLOOD_DICT[ip] = PING_FLOOD_DICT[ip] + 1 
            return False
    else:
        PING_FLOOD_DICT[ip] = 1
        return False
          
def IcmpSmurfAttack(src_ip, target_ip):
    
    if target_ip == broadcast_ip:
        if src_ip == hp_ip or src_ip == ids_ip:
            return True
        else:
            return False
    else:
        return False

def IcmpRedirect(code):
    if code == 0 :
        return True
    elif code == 1 :
        return True
    elif code == 2 :
        return True
    elif code == 3 :
        return True
    else:
        return False

# /*******************************************/
# /          ICMP ANALYSIS STOPS              /
# /*******************************************/

# /*******************************************/
# /            UDP ANALYSIS STARTS            /
# /*******************************************/

def UdpFloodCheck(ip, data):
    global ping_flood_counter
    if ping_flood_counter > 5:
        ping_flood_counter = 0
        return True
    else:
        ping_flood_counter +=1
        return False
          
# /*******************************************/
# /            UDP ANALYSIS STOPS             /
# /*******************************************/

# /*******************************************/
# /            TCP ANALYSIS STARTS            /
# /*******************************************/

def SynFloodCheck(ip):
    if ip in SYN_PACKET_DICT:
        if SYN_PACKET_DICT[ip] > 5:
            return True
        else:
            SYN_PACKET_DICT[ip] = SYN_PACKET_DICT[ip] + 1 
            return False
    else:
        SYN_PACKET_DICT[ip] = 1
        return False

def TcpSpoofedAttack(ip):
    if ip == hp_ip or ip == ids_ip:
        return True
    else:
        return False

def TcpBounceAttack(ip):
    if ip == hp_ip or ip == ids_ip:
        return True
    else:
        return False
          
# /*******************************************/
# /            TCP ANALYSIS STOPS             /
# /*******************************************/


# /*******************************************/
# /                 MAIN STARTS               /
# /*******************************************/

def main():
    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth = Ethernet(raw_data)

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                
                if icmp.type == 5:
                    if(IcmpRedirect(icmp.code)):
                        redirect_traffic_to_rh(ipv4.src)
                        ids_log_files.write('Timestamp: {}\n'.format(currentdt.strftime("%Y-%m-%d %H:%M:%S")))
                        ids_log_files.write(TAB_1+'IP: {}\n'.format(ipv4.src))
                        ids_log_files.write(TAB_2+'Reason: Possible ICMP Redirect Attack, Redirected!!\n\n\n')
                
                elif icmp.type == 0:
                    if PingFloodCheck():
                        redirect_traffic_to_rh(ipv4.src)
                        ids_log_files.write('Timestamp: {}\n'.format(currentdt.strftime("%Y-%m-%d %H:%M:%S")))
                        ids_log_files.write(TAB_1+'IP: {}\n'.format(ipv4.src))
                        ids_log_files.write(TAB_2+'Reason: Possible Ping Flood Attack, Redirected!!\n\n\n')
                
                elif icmp.type == 8:
                    if IcmpSmurfAttack(ipv4.src, ipv4.target):
                        redirect_traffic_to_rh(ipv4.src)
                        ids_log_files.write('Timestamp: {}\n'.format(currentdt.strftime("%Y-%m-%d %H:%M:%S")))
                        ids_log_files.write(TAB_1+'IP: {}\n'.format(ipv4.src))
                        ids_log_files.write(TAB_2+'Reason: Possible ICMP Smurf Attack, Redirected!!\n\n\n')
            
            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                                   
                if TcpSpoofedAttack(ipv4.src):
                    redirect_traffic_to_rh(ipv4.src)
                    ids_log_files.write('Timestamp: {}\n'.format(currentdt.strftime("%Y-%m-%d %H:%M:%S")))
                    ids_log_files.write(TAB_1+'IP: {}\n'.format(ipv4.src))
                    ids_log_files.write(TAB_2+'Reason: Possible TCP Spoof Attack, Redirected!!\n\n\n')
                    

                if tcp.flag_syn == 1:
                    if SynFloodCheck(ipv4.src):
                        redirect_traffic_to_rh(ipv4.src)
                        ids_log_files.write('Timestamp: {}\n'.format(currentdt.strftime("%Y-%m-%d %H:%M:%S")))
                        ids_log_files.write(TAB_1+'IP: {}\n'.format(ipv4.src))
                        ids_log_files.write(TAB_2+'Reason: Possible SYN Flood Attack, Redirected!!\n\n\n')

                    if TcpBounceAttack(ipv4.src):
                        redirect_traffic_to_rh(ipv4.src)
                        ids_log_files.write('Timestamp: {}\n'.format(currentdt.strftime("%Y-%m-%d %H:%M:%S")))
                        ids_log_files.write(TAB_1+'IP: {}\n'.format(ipv4.src))
                        ids_log_files.write(TAB_2+'Reason: Possible TCP Bounce Attack, Redirected!!\n\n\n')
        ids_log_files.close()

            # UDP
            """elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))"""


# /*******************************************/
# /                 MAIN ENDS                 /
# /*******************************************/

main()