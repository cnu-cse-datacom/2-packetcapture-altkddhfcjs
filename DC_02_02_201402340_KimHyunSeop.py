import socket
import struct 


def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("==================ethernet haeder================")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr


def parsing_ip_header(data):
    ip_data = data[0][14:34]
    ip_header = struct.unpack("!1c1c1h2c2c1B1B2c4B4B", ip_data)
    ip_version = ip_header[0].hex()[0]          # 4bit \ 
    ip_header_length = ip_header[0].hex()[1]    # 4bit / 1byte 1c
    ip_DSC = ip_header[1].hex()[0]              # 4bit \
    ip_ECN = ip_header[1].hex()[1]              # 4bit / 1byte 1c
    ip_total_length = ip_header[2]              # 2byte -> int 1h
    ip_identification = "0x"+ip_header[3].hex() + ip_header[4].hex()    # 2byte 2c
    ip_flags = "0x" + ip_header[5].hex() + ip_header[6].hex()           # 2byte 2c 
    #------- datas in flags ----
    
    dec = int(ip_flags, 16) 
    flags = ByteToBinaryString(dec) #change Binary String ip_frags

    ip_reserved_bit = flags[0]   #ip_frags 1bit 
    ip_not_flagments = flags[1]  
    ip_flagments = flags[2]
    ip_flagments_offset = flags[3] #3, 4~16bit
    #------- end --------

    ip_time_to_live = ip_header[7]  # 1byte 1B
    ip_protocol = ip_header[8]      # 1byte -> deciede TCP/UDP 1B
    ip_header_checksum = "0x"+ip_header[9].hex()+ip_header[10].hex()    # 2byte 2c
    ip_source_ip_address = convert_ip_address(ip_header[11:15])        # 4byte 4B
    dest_ip_address = convert_ip_address(ip_header[15:20])              # 4byte 4B
    print("===================ip header=====================")
    print("ip_header:", ip_version)
    print("ip_version:", ip_header_length)
    print("Different Services Codepoint:", ip_DSC)
    print("Explicit Congestion Notification", ip_ECN)
    print("ip_total_length:", ip_total_length)
    print("ip_identification:", ip_identification)
    print("ip_flags:", ip_flags)
    print(">>>>ip_reserved_bit:", ip_reserved_bit)
    print(">>>>ip_not_flagments:", ip_not_flagments)
    print(">>>>ip_flagments:", ip_flagments)
    print(">>>>ip_flagments_offset:", ip_flagments_offset)
    print("ip_time_to_live:", ip_time_to_live)
    print("ip_protocol:", ip_protocol)
    print("ip_header_checksum:", ip_header_checksum)
    print("ip_source_ip_address:",ip_source_ip_address)
    
    if ip_protocol == 6:    #tcp call
        tcp_data = data[0][34:54]
        parsing_tcp_header(tcp_data)
    
    if ip_protocol == 17:   #udp call
        udp_data = data[0][34:42]
        parsing_udp_header(udp_data)

def convert_ip_address(data):
    ip_addr = ""
    number = 0
    for i in data:
        if number >= len(data)-1:
            ip_addr += str(i)
        else:
            ip_addr += str(i) + "."
            number = number + 1
    #ip_addr = ".".join(ip_addr)
    return ip_addr


def ByteToBinaryString(data):
    result = ""
    mask = 1<<15
    while True:
        c="1"if(data&mask)!=0else"0"
        result+=c
        mask >>=1
        if mask <= 0: break

    return result


def parsing_tcp_header(data):
    tcp_header = struct.unpack("!HHIIBBHHH" ,data)
        
    tcp_source_port = tcp_header[0]                 #2byte
    tcp_destination_port = tcp_header[1]            #2byte
    tcp_sequence_number = tcp_header[2]             #4byte
    tcp_acknowledgment_number = tcp_header[3]       #4byte
    
    
    
    tcp_binary_header_flags = bin(tcp_header[4])    #to binary header[4]
    tcp_len = int(tcp_binary_header_flags[:-4], 2)  #input 4bit -> integer
    tcp_len *= 4                                    #shift calcuration - 4bit turn to header[5]

    tcp_header_length = tcp_header[4]   #4bit \ 
    tcp_flags = tcp_header[5]           #8bit /2byte    
    #----------tcp flags----------------
    tcp_flags_infor = ByteToBinaryStringinTCP(tcp_flags)
    tcp_reserved = tcp_flags_infor[2]
    tcp_nonce = tcp_flags_infor[3]
    tcp_cwr = tcp_flags_infor[4]
    tcp_ecn_echo = tcp_flags_infor[5]
    tcp_urgent = tcp_flags_infor[6]
    tcp_ack = tcp_flags_infor[7]
    tcp_push = tcp_flags_infor[8]
    tcp_reset = tcp_flags_infor[9]
    tcp_stn = tcp_flags_infor[10]
    tcp_fin = tcp_flags_infor[11]
    #------------end------------------
    tcp_window_size_value = tcp_header[6]   #2byte
    tcp_checksum = tcp_header[7]            #2byte
    tcp_urgent_pointer = tcp_header[8]      #2byte
    
    print("===================tcp header=====================")
    print("tcp_source_port:", tcp_source_port)
    print("tcp_destination_port:", tcp_destination_port)
    print("tcp_sequence_number:", tcp_sequence_number)
    print("tcp_acknowledgment_number:", tcp_acknowledgment_number)
    print("tcp_header_length:", tcp_header_length)
    #print flags
    print("tcp_flags:", tcp_flags)
    print(">>>>reserved:", tcp_reserved)
    print(">>>>nonce:", tcp_nonce)
    print(">>>>cwr:", tcp_cwr)
    print(">>>>ecn_echo:", tcp_ecn_echo)
    print(">>>>urgent:", tcp_urgent)
    print(">>>>ack:", tcp_ack)
    print(">>>>push:", tcp_push)
    print(">>>>reset:", tcp_reset)
    print(">>>>stn:", tcp_stn)
    print(">>>>fin:", tcp_fin)
    # end
    print("tcp_window_size_value:", tcp_window_size_value)
    print("tcp_checksum:", tcp_checksum)
    print("tcp_urgent_pointer:", tcp_urgent_pointer)
    
def ByteToBinaryStringinTCP(data):
    result = list()
    mask = 1<<11
    while True:
        c='1'if(data&mask)!=0else'0'
        result.append(c)
        mask>>=1
        if mask<=0: break

    return result


def parsing_udp_header(data):
    udp_header = struct.unpack('!HHH2c', data)
    udp_source_port = udp_header[0]
    udp_destination_port = udp_header[1]
    udp_length = udp_header[2]
    udp_header_checksum = "0x" + udp_header[3].hex() + udp_header[4].hex()

    print("==================udp header=================")
    print("udp_source_port:", udp_source_port)
    print("udp_destination_port:", udp_destination_port)
    print("udp_length:", udp_length)
    print("udp_header_checksum:", udp_header_checksum)


recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))


while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    parsing_ip_header(data)
    print("\n")