import argparse
from collections import OrderedDict
from datetime import datetime
from enum import Enum
from locale import atoi
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
def send_request_packet_to_sender(tracker_dict, file_name, id, emulator_host_name, emulator_port, window_size, source_host_name, source_port):
    data = file_name.encode()
    file_id_dict = tracker_dict[file_name]
    
    sender_host_name = file_id_dict[id]['sender_host_name']
    sender_port_number = file_id_dict[id]['sender_port_number']

    source_ip_address = socket.gethostbyname(source_host_name)
    dest_ip_address = socket.gethostbyname(sender_host_name)
    dest_port = sender_port_number # the final dest of this packet is the targeted sender

    # assemble udp header
    packet_type = (Packet_Type.REQUEST.value).encode('ascii')
    sequence_number = 0
    header = struct.pack('!cII', packet_type, sequence_number, window_size)

    packet_with_header = header + data

    # add encapsulation header

    # convert 
    source_ip_a, source_ip_b, source_ip_c, source_ip_d = map(atoi, source_ip_address.split('.'))
    dest_ip_a, dest_ip_b, dest_ip_c, dest_ip_d = map(atoi, dest_ip_address.split('.'))
    priority = 1 # all request packets have priority 1

    encapsulation_header = struct.pack('!BBBBBhBBBBhI', 
        priority, 
        source_ip_a, source_ip_b, source_ip_c, source_ip_d, 
        source_port, 
        dest_ip_a, dest_ip_b, dest_ip_c, dest_ip_d, 
        dest_port, 
        window_size)

    packet_with_header = encapsulation_header + packet_with_header

    sock.sendto(packet_with_header, (emulator_host_name, emulator_port))


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
# sender's full address: "host_name:port_number"
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

def parse_packet(packet):
    encapsulation_header = struct.unpack('!BBBBBhBBBBhI', packet[:17]) # first unpack and get encapsulation header

    # header 
    priority = encapsulation_header[0]
    src_ip_address = '.'.join(str(addr) for addr in encapsulation_header[1:5])
    src_port = encapsulation_header[5]
    dest_ip_address = '.'.join(str(addr) for addr in encapsulation_header[6:10])
    dest_port = encapsulation_header[10]
    length = encapsulation_header[11]
    
    # inner header
    inner_header_and_payload = packet[17:] # get the rest of the message excluding the encapsulation heade
    inner_header = struct.unpack("!cII", inner_header_and_payload[:9]) # unpack the inner header
    packet_type = inner_header[0].decode('ascii')
    sequence_number = inner_header[1]
    inner_header_length = inner_header[2]
    data = inner_header_and_payload[9:].decode('utf-8') # get the actual payload excluding the inner header
    
    # if is_incoming_packet:
    #     print('------------------------------------------------')
    #     print('INCOMING PACKET DETAILS:')
    #     print('priority: ', priority)
    #     print('src ip: ', src_ip_address)
    #     print('src port: ', src_port)
    #     print('dest ip: ', dest_ip_address)
    #     print('dest port: ', dest_port)
    #     print('length: ', length)
    #     print('data: ', data.decode("utf-8")) # print decoded data
    #     # print('seq number: ', sequence_number)
    #     print('------------------------------------------------')

    return (priority, src_ip_address, src_port, dest_ip_address, dest_port, length, packet_type, sequence_number, inner_header_length, data)

def send_ack_receipt(emulator_host_name, emulator_port, source_host_name, source_port, dest_host_name, dest_port, sequence_number):
    source_ip_address = socket.gethostbyname(source_host_name)
    dest_ip_address = socket.gethostbyname(dest_host_name)

    # assemble inner header
    packet_type = (Packet_Type.ACK.value).encode('ascii')
    header = struct.pack('!cII', packet_type, sequence_number, 0)

    packet_with_header = header + ''.encode() # empty data for ack packet

    # add encapsulation header

    # convert 
    source_ip_a, source_ip_b, source_ip_c, source_ip_d = map(atoi, source_ip_address.split('.'))
    dest_ip_a, dest_ip_b, dest_ip_c, dest_ip_d = map(atoi, dest_ip_address.split('.'))
    priority = 1 # all request packets have priority 1

    encapsulation_header = struct.pack('!BBBBBhBBBBhI', 
        priority, 
        source_ip_a, source_ip_b, source_ip_c, source_ip_d, 
        source_port, 
        dest_ip_a, dest_ip_b, dest_ip_c, dest_ip_d, 
        dest_port, 
        0)

    packet_with_header = encapsulation_header + packet_with_header
    print('sending ack packet to port: ', dest_port, ', seq num: ', sequence_number)
    sock.sendto(packet_with_header, (emulator_host_name, emulator_port))

# set global variables from command line args
args = parse_command_line_args()
requester_port = args.requester_port
requested_file_name = args.file_name
tracker_dict = read_and_parse_tracker_file('tracker.txt')
window_size = args.window
emulator_host_name = args.f_hostname
emulator_port = args.f_port

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

# 1) send out request packets to the respective senders (given in tracker.txt) through the emulator

# args: (tracker_dict, file_name, id, emulator_host_name, emulator_port, window_size, source_host_name, source_port)
for id in range(0, number_of_chunks_to_request):
    send_request_packet_to_sender(tracker_dict, requested_file_name, id + 1, emulator_host_name, emulator_port, window_size, requester_host_name, requester_port)

# wait for requested packets from sender while the END packet has not been sent

sender_stats = create_sender_stats_dict(file_data_storage_dict)

end_packets_received = 0

# { sequence_number: data_packet }
data_packets_received = {}

#while end_packets_received != number_of_chunks_to_request:
while True: 
    packet, sender_address = sock.recvfrom(1024)
    sender_full_address = str(sender_address[0]) + ':' + str(sender_address[1])
    sender_ip_address = sender_address[0]
    sender_port_number = sender_address[1]
    sender_host_name = socket.gethostbyaddr(sender_ip_address)[0].replace('.cs.wisc.edu', '')
    sender_host_name_and_port = sender_host_name + ':' + str(sender_port_number)

    priority, src_ip_address, src_port, dest_ip_address, dest_port, length, packet_type, sequence_number, inner_header_length, data = parse_packet(packet)

    if packet_type == 'D':
        data_packets_received[sequence_number] = data
        print('received data packet - seq num: ', sequence_number)
        send_ack_receipt(emulator_host_name, emulator_port, requester_host_name, requester_port, src_ip_address, src_port, sequence_number)
    
    #if packet_type == 'E':
    #    end_packets_received += 1
    #    print('received end packet')
    #    break
    if len(data_packets_received) == 517:
        break
    print('curr dict state: ', data_packets_received)

print('broke out of loop bec end packet received or while loop cond fulfilled')
print(data_packets_received)
print('gonna start writing results to file')

# write to file according to sequence number
# results_file = open(requested_file_name, 'a')
results_file = open('result.txt', 'a')
for sequence_number in sorted(data_packets_received.keys()):
    file_data = data_packets_received[sequence_number]
    results_file.write(file_data)

print('finished writing result to file')
