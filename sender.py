import argparse
from datetime import datetime
from enum import Enum
from locale import atoi
import math
import socket
import struct
import time

total_number_of_transmissions = 0
total_number_of_retransmissions = 0

class Packet_Type(Enum):
    REQUEST = 'R'
    DATA = 'D'
    END = 'E'

def command_line_args_range_checker(input):
    if (not input.isnumeric()):
        raise argparse.ArgumentTypeError('invalid arg type: must be an int')
    input = int(input)

    if input < 2050 or input > 65536:
        raise argparse.ArgumentTypeError('port number out of accepted range')
    return input

def parse_command_line_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--sender_port', help='port on which the sender waits for requests', required=True, type=command_line_args_range_checker, metavar="[2050,65536]")
    parser.add_argument('-g', '--requester_port', help='port on which the requester is waiting', required=True, type=command_line_args_range_checker, metavar="[2050,65536]")
    parser.add_argument('-r', '--rate', help='the number of packets to be sent per second', required=True, type=int)
    parser.add_argument('-q', '--seq_no', help='the initial sequence of the packet exchange', required=True, type=int)
    parser.add_argument('-l', '--length', help='length of the payload (in bytes) in the packets', required=True, type=int)
    parser.add_argument('-f', '--f_hostname', help='the hostname of the emulator', required=True, type=str)
    parser.add_argument('-e', '--f_port', help='the port of the emulator', required=True, type=int)
    parser.add_argument('-i', '--priority', help='the priority of the sent packets', required=True, type=int)
    parser.add_argument('-t', '--timeout', help='the timeout for retransmission for lost packets in the unit of milliseconds', required=True, type=int)

    args = parser.parse_args()

    # disregard command line args; always start at sequence number 1
    args.seq_no = 1 

    return args

# print packet information before each packet is sent to the requester
def print_packet_information(requester_ip_address, requester_port_number, requester_host_name, sequence_number, data, packet_type):
    if (packet_type == 'D'):
        print('DATA Packet')
    elif (packet_type == 'E'):
        print('END Packet')

    requester_full_address = str(requester_ip_address) + ':' + str(requester_port_number)
    print('send time:       ', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
    print('requester addr:  ', requester_full_address)
    print('Sequence num:    ', sequence_number)
    print('length:          ', len(data))
    print('payload:         ', data.decode('utf-8'))
    print()

# if file exists, read the file and return the file data
# if file does not exist, return -1
def read_file(file_name):
    try:
        with open(file_name, 'r') as reader:
            data = reader.read()
            return data
    except:
        return -1

def send_packet(emulator_host_name, emulator_port_number, priority, src_ip_address, src_port, dest_ip_address, dest_port, length, data, packet_type, sequence_number):
    data = data.encode()
    packet_type = packet_type.encode('ascii')

    # assemble udp header
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
    print('sending packet now, src port: ', src_port, ' , dest port: ', dest_port)
    packet_with_header = encapsulation_header + packet_with_header
    sock.sendto(packet_with_header, (emulator_host_name, emulator_port_number))

    global total_number_of_transmissions
    total_number_of_transmissions += 1
    
    return packet_with_header

def epoch_time_in_milliseconds_now():
    time_now_in_milliseconds = round(time.time() * 1000)
    return time_now_in_milliseconds

def parse_packet(packet, is_incoming_packet=True):
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
    window_size = inner_header[2]
    data = inner_header_and_payload[9:].decode("utf-8") # get the actual payload excluding the inner header
    
    if is_incoming_packet:
        print('------------------------------------------------')
        print('INCOMING PACKET DETAILS:')
        print('priority: ', priority)
        print('src ip: ', src_ip_address)
        print('src port: ', src_port)
        print('dest ip: ', dest_ip_address)
        print('dest port: ', dest_port)
        print('length: ', length)
        print('packet type: ', packet_type)
        print('seq number: ', sequence_number)
        print('window size: ', window_size)
        print('data: ', data) # print decoded data
        print('------------------------------------------------')

    return (priority, src_ip_address, src_port, dest_ip_address, dest_port, length, packet_type, sequence_number, window_size, data)

def create_curr_window_packets_info(starting_sequence_number, window_size):
    curr_window_packets_info = {}
    #print('creating new window table for starting sequence number: ', starting_sequence_number, ', window size: ', window_size)
    for sequence_number in range(starting_sequence_number, starting_sequence_number + window_size):
     #   print('curr seq number to create an entry for: ', sequence_number)
        curr_window_packets_info[sequence_number] = {}
        curr_window_packets_info[sequence_number]['packet'] = None
        curr_window_packets_info[sequence_number]['received_ack'] = False
        curr_window_packets_info[sequence_number]['number_of_retransmissions'] = 0
        curr_window_packets_info[sequence_number]['deadline'] = None
    
    #print('returning newly created window dict: ', curr_window_packets_info)    
    return curr_window_packets_info

def all_acks_received(curr_window_packets_info):
    for sequence_number, details in curr_window_packets_info.items():
        packet = curr_window_packets_info[sequence_number]['packet']
        if packet is None:
            continue
        received_ack = details['received_ack']
        number_of_retransmissions = details['number_of_retransmissions']
        deadline = details['deadline']

        if not received_ack:
     #       print('not all acks received')
            return False
    
    #print('all acks received')
    return True

# when the sender has not received an ack for all packets 
# and has reached timeout on the last transmission and is
# going to giev up on this window of packets
def reached_max_transmissions(curr_window_packets_info):
    max_transmissions_count = 0
    num_packets = 0
    time_now = epoch_time_in_milliseconds_now()

    for sequence_number, details in curr_window_packets_info.items():
        packet = curr_window_packets_info[sequence_number]['packet']
        if packet is None:
            continue

        num_packets += 1
        received_ack = details['received_ack']
        number_of_retransmissions = details['number_of_retransmissions']
        deadline = details['deadline']

        if (number_of_retransmissions == 5 and time_now > deadline) or received_ack == True:
            max_transmissions_count += 1
    
    reached_max = max_transmissions_count == num_packets
   # print('num packets in this window: ', num_packets, ', max transmission count: ', max_transmissions_count)
   # print('reached max transmissions for this window: ', reached_max) 
    return reached_max
    
def retransmit_packets(curr_window_packets_info, timeout, emulator_host_name, emulator_port_number):
    time_now = epoch_time_in_milliseconds_now()
  #  print('inside retransmit packets')
 #   print(curr_window_packets_info)
    for sequence_number, details in curr_window_packets_info.items():
        packet = curr_window_packets_info[sequence_number]['packet']
        if packet is None:
            continue
   #     print('checking if we need to retransmit seq number: ', sequence_number)
        received_ack = details['received_ack']
        number_of_retransmissions = details['number_of_retransmissions']
        deadline = details['deadline']

        if not received_ack and number_of_retransmissions < 5 and time_now > timeout:
    #        print('retransmitting seq number: ', sequence_number)
            packet = curr_window_packets_info[sequence_number]['packet']
            sock.sendto(packet, (emulator_host_name, emulator_port_number))
            curr_window_packets_info[sequence_number]['deadline'] = epoch_time_in_milliseconds_now() + timeout
            curr_window_packets_info[sequence_number]['number_of_retransmissions'] += 1
            
            total_number_of_retransmissions += 1
            total_number_of_transmissions += 1            

def observed_percentage_packets_lost():
    global total_number_of_transmissions
    global total_number_of_retransmissions
    print('---------------------------------------------------')
    print('total number of transmissions: ', total_number_of_transmissions)
    print('total number of retransmissions: ', total_number_of_retransmissions)
    print('observed percentage of packets lost: ', total_number_of_retransmissions/ total_number_of_transmissions)
    print('---------------------------------------------------')

# set command line args as global variables
args = parse_command_line_args()
requester_port_number = args.requester_port # for testing it is 12345
sender_port_number = args.sender_port # for testing it is 12344
rate = args.rate
max_size_payload_in_bytes = args.length
timeout = args.timeout
emulator_host_name = args.f_hostname
emulator_port = args.f_port
sender_priority = args.priority

# create socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender_host_name = socket.gethostname()
sender_ip_address = socket.gethostbyname(sender_host_name)
sock.bind((sender_host_name, sender_port_number))

# 1) wait for request packet
print('gonna wait for the req packet now')
packet, sender_address = sock.recvfrom(1024)
priority, src_ip_address, src_port, dest_ip_address, dest_port, length, packet_type, sequence_number, packet_window_size, file_name = parse_packet(packet)
print('received the request for file: ', file_name)
print('req received from port: ', src_port)
print('it has a dest of port: ', dest_port)
requester_ip_address = src_ip_address
requester_port = src_port


window_sequence_number = 1

# 2) read requested file data
data = read_file(file_name)
#print('read file data')
# file does not exist
if data == -1:
    #print('here 1')
    # send END packet
    sequence_number = 0
    length = 0
    # the source and dest are the same because we are sending this back to the requester
    send_packet(emulator_host_name, emulator_port, sender_priority, src_ip_address, src_port, src_ip_address, src_port, length, '', Packet_Type.END.value, sequence_number)
else:     
    #print('here 2')
    sock.setblocking(0) # receive packets in a non-blocking way

    remaining_bytes_to_send = len(data)
    num_packets = math.ceil(remaining_bytes_to_send / max_size_payload_in_bytes)
    sending_interval_in_seconds = (1000 / rate) / 1000
    #print('num packets to send: ', num_packets)
    starting_index = 0
    curr_window_starting_sequence_number = 1
    while remaining_bytes_to_send > 0:
    #    print('creating new window table, starting seq num: ', curr_window_starting_sequence_number)
        # 3) send window of packets

        # sequence_number: {
        #   packet: packet,
        #   received_ack: True/ False,
        #   number_of_retransmissions: 0
        #   deadline: epoch time in milliseconds
        # }
        curr_window_packets_info = create_curr_window_packets_info(curr_window_starting_sequence_number, packet_window_size)

        num_packets_sent = 0
        print('remaining bytes to send: ', remaining_bytes_to_send, 'curr seq num: ', window_sequence_number)
        print(curr_window_packets_info)
        print('num packets sent: ', num_packets_sent)
        while remaining_bytes_to_send > 0 and num_packets_sent < packet_window_size:
            print('remaining bytes to send: ', remaining_bytes_to_send)
            sliced_data = data[starting_index:starting_index + max_size_payload_in_bytes]
            print('sending a packet - curr seq number: ', sequence_number)
            time.sleep(sending_interval_in_seconds)
            sent_packet =  send_packet(emulator_host_name, emulator_port, sender_priority, sender_ip_address, sender_port_number, requester_ip_address, requester_port, length, sliced_data, Packet_Type.DATA.value, window_sequence_number)

            num_packets_sent += 1
  #          print('num packets sent: ', num_packets_sent)
            remaining_bytes_to_send -= max_size_payload_in_bytes
            starting_index += max_size_payload_in_bytes
   #         print('trying to store packet for seq num: ', window_sequence_number)
            curr_window_packets_info[window_sequence_number]['packet'] = sent_packet
            curr_window_packets_info[window_sequence_number]['deadline'] = epoch_time_in_milliseconds_now() + timeout
            window_sequence_number += 1
            print(curr_window_packets_info)

        curr_window_starting_sequence_number += packet_window_size
#        print('finished sending window of packets, gonna wait for acks now')
        while True:
            try:
 #               print('waiting for acks')
                print(curr_window_packets_info)
                if all_acks_received(curr_window_packets_info):
 #                   print('all acks have been received: breaking out of waiting for acks loop')
                    break
                
                if reached_max_transmissions(curr_window_packets_info):
 #                   print('reached max transmissions: breaking out of waiting for acks loop')
                    break
                
                retransmit_packets(curr_window_packets_info, timeout, emulator_host_name, emulator_port) 

                packet, sender_address = sock.recvfrom(8192) # Buffer size is 8192. Change as needed
                if packet:
                    priority, src_ip_address, src_port, dest_ip_address, dest_port, length, packet_type, sequence_number, window_size, file_name = parse_packet(packet)
                    curr_window_packets_info[sequence_number]['received_ack'] = True
                    print('ACK RECEIVED for seq number: ', sequence_number)
            except:
                pass

        print('moving onto the next window of packets')

print('done and going to send end packet now')

# 5) send end packet when done with data packets
time.sleep(sending_interval_in_seconds)

sequence_number = 0
length = 0
send_packet(emulator_host_name, emulator_port, sender_priority, sender_ip_address, sender_port_number, requester_ip_address, requester_port, length, sliced_data, Packet_Type.END.value, sequence_number)
print('sent to port: ', requester_port)
print(curr_window_packets_info)

observed_percentage_packets_lost()
