import argparse
from enum import Enum
from queue import PriorityQueue
import select
import socket
import struct
import sys

class Packet_Type(Enum):
    REQUEST = 'R'
    DATA = 'D'
    END = 'E'
    ACK = 'A'

# init the three priority queues
highest_priority_queue = PriorityQueue()
medium_priority_queue = PriorityQueue()
lowest_priority_queue = PriorityQueue()

def parse_command_line_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port', help='the port of the emulator', required=True, type=int)
    parser.add_argument('-q', '--queue_size', help='the size of each of the three queues', required=True, type=int)
    parser.add_argument('-f', '--filename', help='the name of the file containing the static forwarding table', required=True, type=str)
    parser.add_argument('-l', '--log', help='the name of the log file', required=True, type=str)

    args = parser.parse_args()
    return args

# returns a dictionary containing info from the forwarding table file 
# that only concerns this particular emulator_host_name + emulator_port_number
# format of returned dictionary is denoted with the ! sign in the format comment below
def parse_forwarding_table(file_name, emulator_host_name, emulator_port_number):
    try:
        file = open(file_name, 'r')
    except:
        print('parse_forwading_table: error reading ', file_name, '.')
        return

    file_lines = file.readlines()

    # remove newline character at the end of lines
    for i in range(0, len(file_lines)):
        file_lines[i] = file_lines[i].replace('\n', '')

    # construct a dictionary - format below
    # emulator_host_name: {
    #   emulator_port_number: {
    #!       dest_host_name: {
    #!           dest_port_number: {
    #!               next_hop_host_name: host2,
    #!               next_hop_port_number: 4321,
    # !              delay_in_milliseconds: 5,
    # !              loss_probability_percentage: 2
    # !          }
    # !      }
    #   }
    # }
    forwarding_table_info = {}
    for i in range(0, len(file_lines)):
        words_in_line = file_lines[i].split()

        emulator_host_name = words_in_line[0]
        emulator_port_number = int(words_in_line[1])
        dest_host_name = words_in_line[2]
        dest_port_number = words_in_line[3]

        if emulator_host_name not in forwarding_table_info:
            forwarding_table_info[emulator_host_name] = {}

        if emulator_port_number not in forwarding_table_info[emulator_host_name]:
            forwarding_table_info[emulator_host_name][emulator_port_number] = {}

        if dest_host_name not in forwarding_table_info[emulator_host_name][emulator_port_number]:
            forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name] = {}
        
        if dest_port_number not in forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name]:
            forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number] = {}

        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['next_hop_host_name'] = words_in_line[4]
        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['next_hop_port_number'] = words_in_line[5]
        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['delay_in_milliseconds'] = words_in_line[6]
        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['loss_probability_percentage'] = words_in_line[7]

        # leave this for testing
        # emulator_host_name = 'mumble-03'
        # emulator_port_number = 5000
        
    return forwarding_table_info[emulator_host_name][emulator_port_number]

def send_packet(sender_host_name, sender_port_number, priority, src_ip_address, src_port, dest_ip_address, dest_port, length):
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
    
# insert (priority, object) pairs into priority queues, with priority in each queue begininng at 1
def queue_packet(packet_with_header):
    return

# parse command line args
args = parse_command_line_args()
forwarding_table_filename = args.filename
emulator_port_number = args.port
queue_size = args.queue_size

# create socket object and bind to host and port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
emulator_host_name = socket.gethostname()
print(emulator_host_name)
sock.bind((emulator_host_name, emulator_port_number))
sock.setblocking(0) # receive packets in a non-blocking way

# parse the file containing the static forwarding table
forwarding_table_info = parse_forwarding_table(forwarding_table_filename, emulator_host_name, emulator_port_number)
print(forwarding_table_info)

while True:
    try:
        message, sender_address = sock.recvfrom(8192) # Buffer size is 8192. Change as needed
        if message:

            encapsulation_header = struct.unpack('!BBBBBhBBBBhI', message[:17]) # first unpack and get encapsulation header
            inner_header_and_payload = message[17:] # get the rest of the message excluding the encapsulation header

            inner_header = struct.unpack("!cII", inner_header_and_payload[:9]) # unpack the inner header
            data = inner_header_and_payload[9:] # get the actual payload excluding the inner header
            print(data.decode("utf-8")) # print decoded data
    except:
        pass