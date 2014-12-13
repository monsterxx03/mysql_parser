import hashlib
from struct import unpack, pack
import socket

import capability_flags
import charset_const
import status_flags

CAP_FLAGS = {k: v for k, v in capability_flags.__dict__.iteritems() if k.startswith('CLIENT_')}
SERVER_STATUS_FLAGS = {k: v for k, v in status_flags.__dict__.iteritems() if k.startswith('SERVER_')}
CLIENT_CAP = (CAP_FLAGS["CLIENT_LONG_PASSWORD"] |
              CAP_FLAGS["CLIENT_LONG_FLAG"] |
              CAP_FLAGS["CLIENT_CONNECT_WITH_DB"] |
              CAP_FLAGS["CLIENT_LOCAL_FILES"] |
              CAP_FLAGS["CLIENT_PROTOCOL_41"] |
              CAP_FLAGS["CLIENT_INTERACTIVE"] |
              CAP_FLAGS["CLIENT_TRANSACTIONS"] |
              CAP_FLAGS["CLIENT_SECURE_CONNECTION"] |
              CAP_FLAGS["CLIENT_MULTI_STATEMENTS"] |
              CAP_FLAGS["CLIENT_MULTI_RESULTS"] |
              CAP_FLAGS["CLIENT_PS_MULTI_RESULTS"] |
              CAP_FLAGS["CLIENT_PLUGIN_AUTH"])

bin_zero = pack('<B', 0)


class Connection(object):

    def __init__(self, user=None, passwd=None, db=None, host='127.0.0.1', port=3306):
        self.user = user
        self.passwd = passwd
        self.db = db
        self.host = host
        self.port = 3306

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self._stage_handshake()
        self._print_shake_info()
        self._stage_handshake_response()

    def _print_shake_info(self):
        print "prototol_version:", self.protocol_version
        print "server_version:", self.server_version
        print "connection_id:", self.connection_id
        print "charset:", self.charset
        print "### client capibility ###"
        for k, v in self.capabilities:
            print k, ':', v

        print "### server status ###"
        for k, v in self.server_status:
            print k, ':', v
        print self.auth_plugin_name

    def _stage_handshake(self):
        payload = self._get_packet()

        i = 0
        self.protocol_version = unpack('<B', payload[0])[i]
        i += 1
        # server_verion and the rest are splited by 0
        server_version_index = payload.find(bin_zero)
        # human readable server_version string
        self.server_version = payload[i:server_version_index]
        i += server_version_index
        self.connection_id = unpack('<I', payload[i:i + 4])
        i += 4
        auth_plugin_data_part_1 = payload[i:i + 8]
        i += 9  # 8 + 1, 1 is the filter 0x00
        capability_flags_1 = unpack('<H', payload[i:i + 2])[0]  # lower 2 bytes
        i += 2
        # character_set is a id, name can be mapped from:
        # select id, collation_name from  information_schema.collations order by id;
        charset_id, self.status_flags, capability_flags_2 = unpack('<BHH', payload[i:i + 5])
        # combine lower 8 bit and upper 8 bit
        self.capability_flags = capability_flags_1 | (capability_flags_2 << 16)
        i += 5

        if self.capability_flags & CAP_FLAGS['CLIENT_PLUGIN_AUTH']:
            auth_plugin_data_length = unpack('<B', payload[i:i + 1])[0]
        else:
            auth_plugin_data_length = 0
        i += 11  # 1 for auth_plugin_data_length, 10 for reverse

        if self.capability_flags & CAP_FLAGS['CLIENT_SECURE_CONNECTION']:
            _length = max(13, auth_plugin_data_length - 8) - 1  # remote the \x00
            auth_plugin_data_part_2 = payload[i:i + _length]
            i += _length + 1
            self.auth_plugin_data = auth_plugin_data_part_1 + auth_plugin_data_part_2  # this is the salt
        else:
            self.auth_plugin_data = auth_plugin_data_part_1

        if self.capability_flags & CAP_FLAGS['CLIENT_PLUGIN_AUTH']:
            auth_plugin_name_index = payload.find(pack('<B', 0), i)
            self.auth_plugin_name = payload[i:auth_plugin_name_index]
        else:
            self.auth_plugin_name = None

        self._parse_status_flags(self.status_flags)
        self._parse_charset(charset_id)
        self._parse_capability_flags(self.capability_flags)

    def _stage_handshake_response(self):
        if self.capability_flags & CAP_FLAGS['CLIENT_PROTOCOL_41']:
            self._send_handshake41()
        else:
            self._send_handshake320()

    def _send_handshake41(self):
        data = pack("<i", CLIENT_CAP)
        data += pack("<I", 2 ** 24)  # max packet size
        data += pack("<B", 224)  # charset id
        data += b'\0' * 23  # reserved
        data += self.user + b'\0'  # user name
        data += self._crypt_passwd()
        data += self.db + b'\0'
        data += self.auth_plugin_name + b'\0'
        # add header, seq_id is 1, because it's the second packet
        data = pack('<I', len(data))[:3] + pack('<B', 1) + data
        self.socket.sendall(data)
        resp = self.socket.recv(1024)
        print resp

    def _send_handshake320(self):
        pass

    def _crypt_passwd(self):
        return getattr(self, self.auth_plugin_name)()

    def mysql_native_password(self):
        # sha1(password) xor sha1(salt_from_server + sha1(sha1(password)))
        passwd_sha = hashlib.sha1(self.passwd).digest()
        remain = hashlib.sha1(self.auth_plugin_data + hashlib.sha1(passwd_sha).digest()).digest()
        length = len(passwd_sha)
        result = pack('B', length)  # got it from wireshark :(
        for i in range(length):
            tmp = (unpack('B', passwd_sha[i:i + 1])[0] ^
                   unpack('B', remain[i:i + 1])[0])
            result += pack('B', tmp)
        return result

    def _get_packet(self):
        """
        1 packet = 4 bytes header + payload
        header = 3 bytes payload length + 1 seq_id
        """
        header = self.socket.recv(4)
        # mysql packet use little-endian to for bytes order
        payload_length, seq_id = unpack('<IB', header[:3] + b'\0' + header[-1])
        # TODO handle packge length > 0xffffff
        payload = self.socket.recv(payload_length)
        return payload

    def _parse_charset(self, charset_id):
        self.charset = charset_const.CHARSET_MAP.get(charset_id)

    def _parse_status_flags(self, status_flags):
        self.server_status = []
        flags = SERVER_STATUS_FLAGS.items()
        flags.sort(key=lambda x: x[1])
        for k, v in flags:
            self.server_status.append((k, True if v & status_flags else False))

    def _parse_capability_flags(self, cap_flags):
        self.capabilities = []
        caps = CAP_FLAGS.items()
        caps.sort(key=lambda x: x[1])
        for k, v in caps:
            self.capabilities.append((k, True if v & cap_flags else False))

if __name__ == '__main__':
    conn = Connection(user='emma', host='192.168.4.10', db='emma0', passwd='emma')
    conn.connect()
