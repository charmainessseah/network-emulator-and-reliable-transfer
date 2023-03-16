from enum import Enum
from locale import atoi
import socket
import string
import struct
import ipaddress

class Packet_Type(Enum):
    REQUEST = 'R'
    DATA = 'D'
    END = 'E'
    ACK = 'A'
    
def send_packet_2(sender_host_name, sender_port_number, priority, src_ip_address, src_port, dest_ip_address, dest_port, length):
    data = 'hello world'.encode()

    # assemble udp header
    packet_type = (Packet_Type.REQUEST.value).encode('ascii')
    sequence_number = 0
    data_length = 0
    header = struct.pack('!cII', packet_type, sequence_number, data_length)

    packet_with_header = header + data

    # add encapsulation header

    # convert 
    a, b, c, d = map(atoi, src_ip_address.split('.'))
    encapsulation_header = struct.pack('!BBBBBhBBBBhI', priority, a, b, c, d, src_port, a, b, c, d, dest_port, length)

    packet_with_header = encapsulation_header + packet_with_header

    sock.sendto(packet_with_header, (sender_host_name, sender_port_number))

def send_packet(sender_host_name, emulator_port_number, priority, src_ip_address, src_port, dest_ip_address, dest_port, length):
    data = 'hello world'.encode()

    # assemble udp header
    packet_type = (Packet_Type.REQUEST.value).encode('ascii')
    sequence_number = 0
    data_length = 0
    header = struct.pack('!cII', packet_type, sequence_number, data_length)

    packet_with_header = header + data

    # add encapsulation header

    # convert 
    source_ip_a, source_ip_b, source_ip_c, source_ip_d = map(atoi, src_ip_address.split('.'))
    dest_ip_a, dest_ip_b, dest_ip_c, dest_ip_d = map(atoi, dest_ip_address.split('.'))

    encapsulation_header = struct.pack('!BBBBBhBBBBhI', 
        priority, 
        source_ip_a, source_ip_b, source_ip_c, source_ip_d, 
        src_port, 
        dest_ip_a, dest_ip_b, dest_ip_c, dest_ip_d, 
        dest_port, 
        length)

    packet_with_header = encapsulation_header + packet_with_header
    
    sock.sendto(packet_with_header, (sender_host_name, emulator_port_number))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_host = socket.gethostname()
sock.bind((udp_host, 12344))

size = struct.calcsize('!BBBBBhBBBBhI')
print(size)

send_packet(udp_host, 12345, 1, '123.45.67.89', 123, '255.45.67.98', 321, 40)