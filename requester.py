import argparse
from collections import OrderedDict
from datetime import datetime
from enum import Enum
import socket
import struct 

class Packet_Type(Enum):
    REQUEST = 'R'
    DATA = 'D'
    END = 'E'
    ACK = 'A'

def parse_command_line_args():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-p', '--requester_port', help='port on which the requester waits for packets', required=True, type=int)
    parser.add_argument('-o', '--file_name', help='the name of the file that is being requested', required=True, type=str)
    parser.add_argument('-f', '--f_hostname', help='the hostname of the emulator', required=True, type=str)
    parser.add_argument('-e', '--f_port', help='the port of the emulator', required=True, type=int)
    parser.add_argument('-w', '--window', help="the requester's window size", required=True, type=int)

    args = parser.parse_args()
    return args

# printing information for each packet that arrives
def print_receipt_information(header, data, sender_address):
    packet_type = header[0].decode('ascii')
    if (packet_type == 'D'):
        print('DATA Packet')
    elif (packet_type == 'E'):
        print('END Packet')

    sender_address = str(sender_address[0]) + ':' + str(sender_address[1])

    print('recv time:        ', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
    print('sender addr:      ', sender_address)
    print('sequence num:     ', header[1])
    print('length:           ', header[2])
    print('payload:          ', data.decode("utf-8"))
    print()

def print_summary(sender_stats, sender_full_address, sender_host_name_and_port, start_time, end_time):
    total_data_packets = sender_stats[sender_host_name_and_port]['data_packets_received']
    total_data_bytes = sender_stats[sender_host_name_and_port]['data_bytes_received']

    time_elapsed = end_time - start_time
    time_elapsed_in_miliseconds = time_elapsed.total_seconds() * 1000.0
    rate = total_data_packets / time_elapsed.total_seconds()

    print('Summary')
    print('sender addr:              ', sender_full_address)
    print('Total Data packets:       ', total_data_packets)
    print('Total Data bytes:         ', total_data_bytes)
    print('Average packets/ second:  ', rate)
    print('Duration of the test:     ', time_elapsed_in_miliseconds, ' ms')
    print()

# reads and parses tracker.txt into a nested dictionary
# details of nested dictionary are outlined below
def read_and_parse_tracker_file(file_name):
    try:
        file = open(file_name, 'r')
    except:
        print('Please enter the correct file name!')
        return
    
    file_lines = file.readlines()

    # below is the structure of the nested dictionary
    # filename: {
    #          id: {
    #              sender_host_name: "some_host_name",
    #              sender_port_number: 12345
    #          }
    # }
    tracker_dict =  {}

    for file_line in file_lines:
        words_in_line = file_line.split()
        curr_file_name = words_in_line[0]
        id = int(words_in_line[1])
        sender_host_name = words_in_line[2]
        sender_port_number = words_in_line[3]

        if curr_file_name not in tracker_dict:
            tracker_dict[curr_file_name] = {}
        if id not in tracker_dict[curr_file_name]:
            tracker_dict[curr_file_name][id] = {}

        tracker_dict[curr_file_name][id]['sender_host_name'] = sender_host_name
        tracker_dict[curr_file_name][id]['sender_port_number'] = int(sender_port_number)

    return tracker_dict

# send request packed with file name to the sender
def send_request_packet_to_sender(tracker_dict, file_name, id):
    data = file_name.encode()
    file_id_dict = tracker_dict[file_name]
    
    sender_host_name = file_id_dict[id]['sender_host_name']
    sender_port_number = file_id_dict[id]['sender_port_number']

    # assemble udp header
    packet_type = (Packet_Type.REQUEST.value).encode('ascii')
    sequence_number = 0
    data_length = 0
    header = struct.pack('!cII', packet_type, sequence_number, data_length)

    packet_with_header = header + data

    sock.sendto(packet_with_header, (sender_host_name, sender_port_number))

# file_storage_dict = {
#   sender_full_address: ''
# }
def create_file_data_storage_dict(file_id_dict):
    num_senders = len(file_id_dict)
    file_storage_dict = OrderedDict()
    
    for sender in range(0, num_senders):
        sender_id = sender + 1
        sender_details = file_id_dict[sender_id]
        sender_host_name = sender_details['sender_host_name']
        sender_port_number = sender_details['sender_port_number']
        sender_full_address = str(sender_host_name) + ':' + str(sender_port_number)
        file_storage_dict[sender_full_address] = ''

    return file_storage_dict

# pass in file_data_storage_dict to have easy access to all sender's full address
# create a dict to store a sender's stats
# sender_stats = {
#       sender_full_address = {
#           data_packets_received: int,
#           data_bytes_received: int
#       }
# }
def create_sender_stats_dict(file_data_storage_dict):
    sender_stats = {}
    
    for sender_address, file_data in file_data_storage_dict.items():
        sender_stats[sender_address] = {}
        sender_stats[sender_address]['data_packets_received'] = 0
        sender_stats[sender_address]['data_bytes_received'] = 0
    
    return sender_stats

# set global variables from command line args
args = parse_command_line_args()
requester_port = args.requester_port
requested_file_name = args.file_name
tracker_dict = read_and_parse_tracker_file('tracker.txt') 

# create socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
requester_host_name = socket.gethostname()
sock.bind((requester_host_name, requester_port))

# request the senders for packets
if requested_file_name not in tracker_dict:
    print('error: no information on requested file')
    print('exiting program...')
    exit()

file_id_dict = tracker_dict[requested_file_name]
number_of_chunks_to_request = len(file_id_dict)
start_time = datetime.now()

file_data_storage_dict = create_file_data_storage_dict(file_id_dict)

for id in range(0, number_of_chunks_to_request):
    send_request_packet_to_sender(tracker_dict, requested_file_name, id + 1)

# wait for requested packets from sender while the END packet has not been sent

sender_stats = create_sender_stats_dict(file_data_storage_dict)

end_packets_received = 0

while end_packets_received != number_of_chunks_to_request:
    packet_with_header, sender_address = sock.recvfrom(1024)
    sender_full_address = str(sender_address[0]) + ':' + str(sender_address[1])
    sender_ip_address = sender_address[0]
    sender_port_number = sender_address[1]
    sender_host_name = socket.gethostbyaddr(sender_ip_address)[0].replace('.cs.wisc.edu', '')
    sender_host_name_and_port = sender_host_name + ':' + str(sender_port_number)

    header = struct.unpack("!cII", packet_with_header[:9])
    data = packet_with_header[9:]

    packet_type = header[0].decode('ascii')

    if (packet_type == 'D'):
        sender_stats[sender_host_name_and_port]['data_packets_received'] += 1
        payload_length = header[2]
        sender_stats[sender_host_name_and_port]['data_bytes_received'] += payload_length

        file_data_storage_dict[sender_host_name_and_port] += data.decode("utf-8")
        
    print_receipt_information(header, data, sender_address)

    if (packet_type == 'E'):
        end_packets_received += 1
        end_time = datetime.now()
        print_summary(sender_stats, sender_full_address, sender_host_name_and_port, start_time, end_time)

results_file = open(requested_file_name, 'a')
for sender_address, file_data in file_data_storage_dict.items():
    results_file.write(file_data)

results_file.close()


