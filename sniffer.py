import sys
from formatter import print_alert, print_error, print_info
from detector_wrapper import process_payload
try:
    from scapy.all import sniff, TCP, IP, Raw
except ImportError:
    print_error("Scapy module not found. Run: pip install scapy")
    sys.exit(1)

def packet_handler(pkt):
    """
    Called asynchronously by scapy for each processed packet matching the BPF filter.
    Extracts raw payload of TCP packets, routes it to detector.
    """
    try:
        # Strict layer confirmation
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            
            raw_data = bytes(pkt[Raw].payload)
            if not raw_data:
                return
                
            # Process payload through wrapper logic
            result = process_payload(raw_data)
            
            # Formatter triggering for confident matches
            if result:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                print_alert(src_ip, dst_ip, result)
                
    except Exception:
        # Never crash sniffing loop on malformed individual packets
        pass

def start_sniffing(iface: str | None = None):
    """
    Starts real-time live packet capture.
    """
    try:
        iface_name = iface if iface else "auto-selected"
        print_info(f"Starting NetSpecter capture on interface: {iface_name}")
            
        print_info("Waiting for HTTP credentials...")
        
        # Start scapy live sniffing loop
        # filter catches cleartext HTTP and Telnet defaults
        sniff(
            iface=iface,
            filter="tcp port 80 or tcp port 23", 
            prn=packet_handler, 
            store=False
        )
        
    except OSError as e:
        if "No such device" in str(e):
            print_error(f"Network interface not found: {iface}")
        else:
            print_error(f"OS/Driver error initializing sniffer: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print_error(f"Fatal error in sniffing engine: {e}")
        sys.exit(1)
