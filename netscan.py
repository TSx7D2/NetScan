import argparse, logging, time, socket, multiprocessing

#Remove warnings other than errors, reference:
#https://stackoverflow.com/questions/13249341/suppress-scapy-warning-message-when-importing-the-module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Global Const Variables
VERBOSITY_LEVEL = 0

def host_scan(net_address, m):
    #Log formatting functions
    arp_response_format = lambda s,r: r.sprintf("%ARP.psrc% %Ether.src%")
    icmp_response_format = lambda s,r: r.sprintf("%IP.src%")

    if m == "arp":
        print("Discovering, this may take a while...")
        
        start_time = time.time()
        #ARP request each IP on network
        ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = net_address), timeout=2, verbose=VERBOSITY_LEVEL)
        end_time = time.time()

        if len(ans) > 0:
            print("Found Hosts:")
            ans.summary(arp_response_format)
            print("Time Taken: %.2fs" % (end_time-start_time))
        else:
            print("No hosts found.")
            print("Time Taken: %.2fs" % (end_time-start_time))

    if m == "icmp":
        print("Discovering, this may take a while...")

        #ICMP each IP on network
        start_time = time.time()
        ans, unans = sr(IP(dst=net_address)/ICMP(), timeout=2, verbose=VERBOSITY_LEVEL)
        end_time = time.time()

        if len(ans) > 0:
            print("Found Hosts:")
            ans.summary(icmp_response_format)
            print("Time Taken: %.2fs" % (end_time-start_time))
        else:
            print("No hosts found.")
            print("Time Taken: %.2fs" % (end_time-start_time))

def scan_port(target_ip, port):
    #Attempt to establish TCP connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    conn = s.connect_ex((target_ip, port))
    if conn == 0:
        s.close()
        return port
    return 0

#Used as refrence for multiprocessing:
#https://machinelearningmastery.com/multiprocessing-in-python/
def port_scan(target_ip, sport, eport):
    start_time = time.time()
    #Workers set to none = default os.cpu_count()
    pool = multiprocessing.Pool()
    processes = [pool.apply_async(scan_port, args=(target_ip, port)) for port in range(sport, eport+1)]

    #Return port scan results into list
    ports = [port for p in processes if (port := p.get()) > 0]

    end_time = time.time()

    for port in ports:
       print("Open: %d" % port)
    print("Time Taken: %.2fs" % (end_time-start_time))

def parse_args():
    #If not arguments then exit
    if not len(sys.argv) > 1:
        print("usage: netscan.py (hscan|pscan) [-h]")
        return sys.exit(2)

    parser = argparse.ArgumentParser(prog="netscan.py")
    subparser = parser.add_subparsers(dest="command")

    #Host scanning arugment parsing
    hs_parser = subparser.add_parser("hscan", help="Host Scan", usage="netscan.py hscan [-h] <ip> [-m {icmp, arp}]")
    hs_parser.add_argument("net_address", help="Network Address in Format X.X.X.X/X")
    hs_parser.add_argument("-m", help="Scanning Protocol", choices=["icmp", "arp"], default="arp")

    #Port scanning argument parsing
    ps_parser = subparser.add_parser("pscan", help="Port Scan", usage="netscan.py pcan [-h] <target_ip> [-s] [-e]")
    ps_parser.add_argument("target_ip", help="Target IP")
    ps_parser.add_argument("-sport", help="Start Port (Default=1)", type=int, default=1)
    ps_parser.add_argument("-eport", help="End Port (Default=1000)", type=int, default=1000)

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()

    #args.command defined by Line 82 dest="command"
    if args.command == 'hscan':
        host_scan(args.net_address, args.m)
    if args.command == 'pscan':
        port_scan(socket.gethostbyname(args.target_ip), args.sport, args.eport)

