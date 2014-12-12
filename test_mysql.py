from struct import unpack, pack
import socket

CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_SECURE_CONNECTION = 0x00008000


def parse_header(packet):
    header = packet[:4]
    # mysql protocol's byte order between server and client are little endian
    # first 3 bytes in header reprent payload_length, we padding an '\0' to
    # make it 4 bytes
    payload_length, seq_id = unpack('<IB', header[:3] + b'\0' + header[-1])
    return payload_length, seq_id


def parse_initial_hand_shake(payload):
    global CLIENT_PLUGIN_AUTH

    i = 0
    version = unpack('<B', payload[0])[i]
    i += 1
    # server_verion and the rest are splited by 0
    server_version_index = payload.find(pack('<B', 0))
    server_version = payload[i:server_version_index]
    i += server_version_index
    connection_id = unpack('<I', payload[i:i+4])
    i += 4
    auth_plugin_data_part_1 = payload[i:i+8]  # salt
    i += 9 # 8 + 1, 1 is the filter 0x00
    capability_flags_1 = unpack('<H', payload[i:i+2])[0] # lower 2 bytes
    i += 2
    # character_set is a id, name can be mapped from:
    # select id, collation_name from  information_schema.collations order by id;
    character_set, status_flags, capability_flags_2 = unpack('<BHH', payload[i:i+5])
    # combine lower 8 bit and upper 8 bit
    capability_flags = capability_flags_1 | (capability_flags_2 >> 16)
    i += 5

    if capability_flags & CLIENT_PLUGIN_AUTH:
        auth_plugin_data_length = unpack('<B', payload[i:1])
    else:
        auth_plugin_data_length = 0
    # TODO decode other capability_flags
    i += 11 # 1 for auth_plugin_data_length, 10 for reverse

    if capability_flags & CLIENT_SECURE_CONNECTION:
        auth_plugin_data_part_2 = max(13, auth_plugin_data_length - 8)
    # if capability_flags & CLIENT_PLUGIN_AUTH:
    #     auth_plugin_name = None


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.4.10", 3306))
resp = s.recv(1024)
payload_length, _ =parse_header(resp[:4])
parse_initial_hand_shake(resp[4:payload_length])
