import argparse
from enum import Enum
from locale import atoi
import logging
import random
import socket
import struct
import time

class Packet_Type(Enum):
    REQUEST = 'R'
    DATA = 'D'
    END = 'E'
    ACK = 'A'

# init the three priority queues
highest_priority_queue = []
medium_priority_queue = []
lowest_priority_queue = []

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
        dest_port_number = int(words_in_line[3])

        if emulator_host_name not in forwarding_table_info:
            forwarding_table_info[emulator_host_name] = {}

        if emulator_port_number not in forwarding_table_info[emulator_host_name]:
            forwarding_table_info[emulator_host_name][emulator_port_number] = {}

        if dest_host_name not in forwarding_table_info[emulator_host_name][emulator_port_number]:
            forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name] = {}
        
        if dest_port_number not in forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name]:
            forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number] = {}

        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['next_hop_host_name'] = words_in_line[4]
        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['next_hop_port_number'] = int(words_in_line[5])
        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['delay_in_milliseconds'] = int(words_in_line[6])
        forwarding_table_info[emulator_host_name][emulator_port_number][dest_host_name][dest_port_number]['packet_loss_percentage'] = float(words_in_line[7])
        
    return forwarding_table_info

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
    
    sock.sendto(packet_with_header, (sender_host_name, sender_port_number))
    
def queue_packet(packet, priority, queue_max_size):
    print('inside queueing func')
    if priority == 1 and len(highest_priority_queue) < queue_max_size:
        highest_priority_queue.append(packet)
    elif priority == 2 and len(medium_priority_queue) < queue_max_size:
        medium_priority_queue.append(packet)
    elif priority == 3 and len(lowest_priority_queue) < queue_max_size:
        lowest_priority_queue.append(packet)
    else:
        error_message = 'priority queue ' + str(priority) + ' is full'
        log_error_message(packet, error_message)

    return

def randomly_drop_packet(loss_percentage):
    no_drop_percentage = 100 - loss_percentage
    return random.randrange(100) < no_drop_percentage

def epoch_time_in_milliseconds_now():
    time_now_in_milliseconds = round(time.time() * 1000)
    # print("Milliseconds since epoch:", time_now_in_milliseconds)
    return time_now_in_milliseconds

# returns a tuple (priority, src_ip_address, src_port, dest_ip_address, dest_port, length, data)
def parse_packet(message, is_incoming_packet=True):
    encapsulation_header = struct.unpack('!BBBBBhBBBBhI', message[:17]) # first unpack and get encapsulation header

    # header 
    priority = encapsulation_header[0]
    src_ip_address = '.'.join(str(addr) for addr in encapsulation_header[1:5])
    src_port = encapsulation_header[5]
    dest_ip_address = '.'.join(str(addr) for addr in encapsulation_header[6:10])
    dest_port = encapsulation_header[10]
    length = encapsulation_header[11]
    
    # inner header
    inner_header_and_payload = message[17:] # get the rest of the message excluding the encapsulation heade
    inner_header = struct.unpack("!cII", inner_header_and_payload[:9]) # unpack the inner header
    data = inner_header_and_payload[9:] # get the actual payload excluding the inner header
    
    if is_incoming_packet:
        print('------------------------------------------------')
        print('INCOMING PACKET DETAILS:')
        print('priority: ', priority)
        print('src ip: ', src_ip_address)
        print('src port: ', src_port)
        print('dest ip: ', dest_ip_address)
        print('dest port: ', dest_port)
        print('length: ', length)
        print('data: ', data.decode("utf-8")) # print decoded data
        print('------------------------------------------------')

    return (priority, src_ip_address, src_port, dest_ip_address, dest_port, length, data)

def dequeue_and_delay_packet():
    packet_to_delay = None
    if len(highest_priority_queue) > 0:
        print('dequeing from highest priority')
        packet_to_delay = highest_priority_queue.pop()
    elif len(medium_priority_queue) > 0:
        packet_to_delay = medium_priority_queue.pop()
    elif len(lowest_priority_queue) > 0:
        packet_to_delay = lowest_priority_queue.pop()

    return packet_to_delay

# ensure to log this into a file
def log_error_message(packet, error_message):
    priority, src_ip_address, src_port, dest_ip_address, dest_port, length, data = parse_packet(packet, is_incoming_packet=False)
    logging.basicConfig(filename='warning.log', encoding='utf-8', level=logging.DEBUG)
    logging.warning(
        '\n-----------------------------------------------------------------------\nPACKET DROPPED: ' + error_message + 
        '\nsource hostname: ' + src_ip_address + ', source port: ' + str(src_port) + 
        '\ndest hostname: ' + str(dest_ip_address) + ', dest port: ' + str(dest_port) + 
        '\ntime of loss: ' + str(epoch_time_in_milliseconds_now()) + 
        '\npacket priority level: ' + str(priority) + 
        '\nsize of payload: ' + str(length) + 
        '\n-----------------------------------------------------------------------')
    
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

delay_expiry_time = 0
delayed_packet = None

while True:
    # epoch_time_in_milliseconds_now()
    try:
        # step 1) receive packet in a non-blocking way
        message, sender_address = sock.recvfrom(8192) # Buffer size is 8192. Change as needed
        if message:
            # step 2) decide if this packet is to be forwarded by consulting the forwarding table
            print('here')
            priority, src_ip_address, src_port, dest_ip_address, dest_port, length, data = parse_packet(message)

            try:
                print('emulator host name: ', emulator_host_name, ', emulator port: ', emulator_port_number, ', dest ip', dest_ip_address, ', dest port: ', dest_port)

                dict = forwarding_table_info[emulator_host_name][emulator_port_number][dest_ip_address][dest_port]

                # step 3) queue packet
                print('queueing packet')
                queue_packet(message, priority, queue_size)
            except KeyError:
                print('here 2')
                log_error_message(message, 'no forwarding entry found')
                pass
    except:
        pass

    # step 4) 
    if delayed_packet is not None and epoch_time_in_milliseconds_now() == delay_expiry_time:
        print('epoch time now: ', epoch_time_in_milliseconds_now(), ', delay expiry time: ', delay_expiry_time)
        print('delay has expired, now either send or drop packet')
        packet_loss_percentage = forwarding_table_info[emulator_host_name][emulator_port_number][dest_ip_address][dest_port]['packet_loss_percentage'] 
        if not randomly_drop_packet(packet_loss_percentage):
            print('sending packet')
            # send_packet()
        else:
            print('here 2')
            log_error_message(message, 'loss event occurred')
        delay_expiry_time = 0
        delayed_packet = None
    elif delayed_packet is None:
        delayed_packet = dequeue_and_delay_packet()
        if delayed_packet is not None:
            print('here 3')
            priority, src_ip_address, src_port, dest_ip_address, dest_port, length, data = parse_packet(delayed_packet, is_incoming_packet=False)
            delay_time = forwarding_table_info[emulator_host_name][emulator_port_number][dest_ip_address][dest_port]['delay_in_milliseconds']
            delay_expiry_time = epoch_time_in_milliseconds_now() + delay_time
            print('setting delay timer now to: ', epoch_time_in_milliseconds_now())