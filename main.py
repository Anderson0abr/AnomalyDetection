
#!/usr/bin/env python
# coding: utf-8

"""
Analisador e monitorador de tráfego de rede para detecção de ataques
Trabalho de Conclusão de Curso (TCC)
Ciência da Computação - Universidade Estadual do Ceará (UECE)

Desenvolvido por: Anderson Bezerra Ribeiro
Data: 30/10/2017
"""

from Classes.myThread import MyThread
from scapy.all import rdpcap, conf
from time import sleep

import subprocess

def monitor(name):
  print(name + " running...")
  subprocess.run(["sudo", "tcpdump", "ip", "-Uni", "ens33", "-w", "./capture.pcap"])
  #pkts = sniff(iface=conf.iface, count=50, store=1, filter="ip")

if __name__ == "__main__":
  ipHeader = []
  ipTable = []

  thread_monitor = MyThread(monitor, ("Monitor",))
  thread_monitor.start()

  while True:
    try:
      pkts = rdpcap("./capture.pcap")

      if pkts:
        for pkt in pkts:
          ipPkt = pkt.payload
          if ipPkt.src not in ipHeader:
            ipHeader.append(ipPkt.src)
            ipTable.append([])
            ipTable[-1].append(pkt)
          else:
            ipTable[ipHeader.index(ipPkt.src)].append(pkt)

        for i in range(len(ipHeader)):
          print(ipHeader[i])
          for j in range(len(ipTable[i])):
            print(ipTable[i][j].summary())
          print(" ")
          
    except IOError as err:
      print(err)
      sleep(5)
      continue

    