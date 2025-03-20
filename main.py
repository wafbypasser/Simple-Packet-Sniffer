import socket
import struct
import time
import select
import argparse
from datetime import datetime
import logging

class PacketSniffer:
    def __init__(self, log_file=None, filter_ip=None, filter_port=None, filter_proto=None):
        self.filter_ip = filter_ip
        self.filter_port = filter_port
        self.filter_proto = filter_proto
        
        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format='%(asctime)s - %(message)s'
            )
        self.logger = logging.getLogger('packet_sniffer')
        
        self.sockets = []
        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.tcp_sock.setblocking(False)
            self.sockets.append(self.tcp_sock)
        except (socket.error, PermissionError) as e:
            print(f"Error creating TCP socket: {e}")
        
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            self.udp_sock.setblocking(False)
            self.sockets.append(self.udp_sock)
        except (socket.error, PermissionError) as e:
            print(f"Error creating UDP socket: {e}")
            
        try:
            self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.icmp_sock.setblocking(False)
            self.sockets.append(self.icmp_sock)
        except (socket.error, PermissionError) as e:
            print(f"Error creating ICMP socket: {e}")
            
        if not self.sockets:
            raise RuntimeError("No sockets could be created. Are you running with sufficient privileges?")
    
    def decode_ip(self, data):
        try:
            ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            header_length = ihl * 4
            ttl = ip_header[5]
            total_length = ip_header[2]
            protocol = ip_header[6]
            source_ip = socket.inet_ntoa(ip_header[8])
            destination_ip = socket.inet_ntoa(ip_header[9])
            
            output = [
                f"IP Header Version: {version}, IHL: {ihl}, Total Length: {total_length}",
                f"TTL: {ttl}, Protocol: {protocol} (6=TCP, 17=UDP, 1=ICMP)",
                f"Source IP: {source_ip}, Destination IP: {destination_ip}"
            ]
            self.log_info("\n".join(output))
            
            return data[header_length:], protocol, source_ip, destination_ip
        except Exception as e:
            self.log_error(f"Error decoding IP header: {e}")
            return data[20:], None, None, None
    
    def decode_tcp(self, data):
        try:
            tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            seq_num = tcp_header[2]
            ack_num = tcp_header[3]
            data_offset_reserved_flags = tcp_header[4]
            data_offset = (data_offset_reserved_flags >> 4) * 4
            
            # TCP Flags
            flags = tcp_header[5]
            fin = (flags & 1) != 0
            syn = (flags & 2) != 0
            rst = (flags & 4) != 0
            psh = (flags & 8) != 0
            ack = (flags & 16) != 0
            urg = (flags & 32) != 0
            
            window = tcp_header[6]
            
            flag_str = ''.join([
                'F' if fin else '',
                'S' if syn else '',
                'R' if rst else '',
                'P' if psh else '',
                'A' if ack else '',
                'U' if urg else ''
            ])
            
            output = [
                f"TCP Header: Src port: {source_port}, Dest port: {dest_port}",
                f"Seq number: {seq_num}, Ack num: {ack_num}",
                f"Data offset: {data_offset//4}, Flags: {flag_str}, Window: {window}"
            ]
            self.log_info("\n".join(output))
            
            service = self.identify_service(source_port, dest_port)
            if service:
                self.log_info(f"Service: {service}")
            
            return data[data_offset:], source_port, dest_port
        except Exception as e:
            self.log_error(f"Error decoding TCP header: {e}")
            return data[20:], None, None
    
    def decode_udp(self, data):
        try:
            udp_header = struct.unpack("!HHHH", data[:8])
            source_port = udp_header[0]
            dest_port = udp_header[1]
            length = udp_header[2]
            checksum = udp_header[3]
            
            output = [
                f"UDP Header: Src port: {source_port}, Dest port: {dest_port}",
                f"Length: {length}, Checksum: {checksum}"
            ]
            self.log_info("\n".join(output))
            
            service = self.identify_service(source_port, dest_port)
            if service:
                self.log_info(f"Service: {service}")
                
            if source_port == 53 or dest_port == 53:
                self.decode_dns(data[8:])
                
            return data[8:], source_port, dest_port
        except Exception as e:
            self.log_error(f"Error decoding UDP header: {e}")
            return data[8:], None, None
            
    def decode_icmp(self, data):
        try:
            icmp_header = struct.unpack("!BBHHH", data[:8])
            icmp_type = icmp_header[0]
            code = icmp_header[1]
            checksum = icmp_header[2]
            identifier = icmp_header[3]
            sequence = icmp_header[4]
            
            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded"
            }
            
            type_str = icmp_types.get(icmp_type, f"Unknown ({icmp_type})")
            
            output = [
                f"ICMP Header: Type: {type_str}, Code: {code}",
                f"Checksum: {checksum}, Identifier: {identifier}, Sequence: {sequence}"
            ]
            self.log_info("\n".join(output))
            
            return data[8:], None, None
        except Exception as e:
            self.log_error(f"Error decoding ICMP header: {e}")
            return data[8:], None, None
    
    def decode_dns(self, data):
        try:
            if len(data) < 12:
                return
                
            dns_header = struct.unpack("!HHHHHH", data[:12])
            transaction_id = dns_header[0]
            flags = dns_header[1]
            questions = dns_header[2]
            answers = dns_header[3]
            authority = dns_header[4]
            additional = dns_header[5]
            
            qr = (flags >> 15) & 0x1  # Query (0) or Response (1)
            opcode = (flags >> 11) & 0xF
            
            message_type = "Response" if qr else "Query"
            
            self.log_info(f"DNS {message_type}: ID={transaction_id}, Questions={questions}, Answers={answers}")
        except Exception as e:
            self.log_error(f"Error decoding DNS data: {e}")
    
    def identify_service(self, sport, dport):
        ports = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP Alt'
        }
        
        if sport in ports:
            return f"{ports[sport]} (source)"
        if dport in ports:
            return f"{ports[dport]} (destination)"
        return None
    
    def should_process_packet(self, proto, src_ip, dst_ip, src_port, dst_port):
        if self.filter_proto and proto != self.filter_proto:
            return False
        if self.filter_ip and (src_ip != self.filter_ip and dst_ip != self.filter_ip):
            return False
        if self.filter_port and (src_port != self.filter_port and dst_port != self.filter_port):
            return False
        return True
    
    def analyze_payload(self, data, protocol, sport, dport):
        if not data:
            return
            
        if len(data) > 0:
            # Show first 32 bytes as hex
            max_len = min(32, len(data))
            hex_data = ' '.join(f'{byte:02x}' for byte in data[:max_len])
            ascii_data = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data[:max_len])
            
            self.log_info(f"Payload: {hex_data}")
            self.log_info(f"ASCII: {ascii_data}")
            
            if protocol == 6 and (sport == 80 or dport == 80 or sport == 443 or dport == 443):
                if data.startswith(b'GET ') or data.startswith(b'POST ') or data.startswith(b'HTTP/'):
                    try:
                        http_header = data.split(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')
                        self.log_info("HTTP Header detected:")
                        for line in http_header.split('\r\n'):
                            self.log_info(f"  {line}")
                    except Exception as e:
                        self.log_error(f"Error parsing HTTP header: {e}")
    
    def log_info(self, message):
        print(message)
        self.logger.info(message)
    
    def log_error(self, message):
        print(f"ERROR: {message}")
        self.logger.error(message)
    
    def sniff(self):
        print("Packet sniffer started...")
        print("Press Ctrl+C to exit.")
        
        try:
            while True:
                readable, _, _ = select.select(self.sockets, [], [], 0.1)
                
                for sock in readable:
                    try:
                        packet, address = sock.recvfrom(65565)
                        ip, _ = address
                        
                        # Get current timestamp
                        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                        
                        # Start packet analysis
                        self.log_info("\n" + "="*60)
                        self.log_info(f"Packet received from {ip} at {timestamp}")
                        
                        data, protocol, src_ip, dst_ip = self.decode_ip(packet)
                        
                        # Skip if no protocol detected
                        if protocol is None:
                            continue
                            
                        src_port = None
                        dst_port = None
                        
                        if protocol == 6:  # TCP
                            self.log_info("Protocol: TCP")
                            data, src_port, dst_port = self.decode_tcp(data)
                        elif protocol == 17:  # UDP
                            self.log_info("Protocol: UDP")
                            data, src_port, dst_port = self.decode_udp(data)
                        elif protocol == 1:  # ICMP
                            self.log_info("Protocol: ICMP")
                            data, src_port, dst_port = self.decode_icmp(data)
                        
                        if not self.should_process_packet(protocol, src_ip, dst_ip, src_port, dst_port):
                            continue
                            
                        self.analyze_payload(data, protocol, src_port, dst_port)
                        
                    except Exception as e:
                        self.log_error(f"Error processing packet: {e}")
                
        except KeyboardInterrupt:
            print("\nSniffer stopped by user.")
        finally:
            for sock in self.sockets:
                sock.close()


def main():
    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('-l', '--log', help='Log file to save packet data')
    parser.add_argument('-i', '--ip', help='Filter by IP address')
    parser.add_argument('-p', '--port', type=int, help='Filter by port number')
    parser.add_argument('-t', '--proto', type=int, help='Filter by protocol (6=TCP, 17=UDP, 1=ICMP)')
    
    args = parser.parse_args()
    
    try:
        sniffer = PacketSniffer(
            log_file=args.log,
            filter_ip=args.ip,
            filter_port=args.port,
            filter_proto=args.proto
        )
        sniffer.sniff()
    except PermissionError:
        print("Error: This program requires root/administrator privileges to run.")
        print("Try running with 'sudo' on Linux/macOS or as Administrator on Windows.")
    except Exception as e:
        print(f"Error starting sniffer: {e}")


if __name__ == "__main__":
    main()