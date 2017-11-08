
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
from scapy.all import sniff, conf
from time import time, sleep

import threading

def timer():
  sleep(5*60)
  tableMutex.acquire()
  for i in range(len(ipTimer)):
    lastReference = time()-ipTimer[i]
    if lastReference > tempoLimite:
      print("removed"+ipHeader[i]) # TESTE
      ipTimer.pop(i)
      ipHeader.pop(i)
      ipTable.pop(i)
  tableMutex.release()

def monitorCallback(pkt):
  ipPkt = pkt.payload
  tableMutex.acquire()
  if ipPkt.src not in ipHeader:
    ipHeader.append(ipPkt.src)
    ipTimer.append(time()-initialTime)
    ipTable.append([])
    ipTable[-1].append(pkt)
  else:
    ipTable[ipHeader.index(ipPkt.src)].append(pkt)
  tableMutex.release()

if __name__ == "__main__":
  initialTime = time()
  tempoLimite = 5*60 # 5 minutos
  tableMutex = threading.Semaphore(1)

  ipHeader = []
  ipTimer = []
  ipTable = []

  thread_timer = MyThread(timer, ())
  thread_timer.start()

  sniff(iface=conf.iface, count=50, filter="ip", prn=monitorCallback)

  for i in range(len(ipHeader)):
    print(ipHeader[i])
    for j in range(len(ipTable[i])):
      print(ipTable[i][j].summary())
    print(" ")