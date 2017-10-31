
#!usr/bin/env python
# coding: utf-8

"""
Analisador e monitorador de tráfego de rede para detecção de ataques
Trabalho de Conclusão de Curso (TCC)
Ciência da Computação - Universidade Estadual do Ceará (UECE)

Desenvolvido por: Anderson Bezerra Ribeiro
Data: 30/10/2017
"""

from scapy.all import *
#import threading

if __name__ == "__main__":
 ipHeader = []
 ipTable = []

 pkts = sniff(iface=conf.iface, count=50, store=1, filter="ip")

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