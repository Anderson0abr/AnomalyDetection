
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
from scapy.all import *
from time import time, sleep

import threading

def test():
    print("Sending packages...")
    #srcs=["www.github.com", "www.facebook.com", "www.google.com", "www.gmail.com", "www.9gag.com"]
    srcs=["192.30.253.112", "157.24.12.35", "172.217.29.164", "216.58.202.229", "151.101.66.133"]
    dest="10.10.10.10"

    for i in range(5):
      send(IP(src=srcs[0], dst=dest)/TCP(), verbose=0)
    send(IP(src=srcs[4], dst=dest)/TCP(), verbose=0)
    sleep(10)
    for i in range(4):
      send(IP(src=srcs[1], dst=dest)/TCP(), verbose=0)
      send(IP(src=srcs[2], dst=dest)/TCP(), verbose=0)
      send(IP(src=srcs[3], dst=dest)/TCP(), verbose=0)
    send(IP(src=srcs[0], dst=dest)/TCP(), verbose=0)
    sleep(10)
    send(IP(src=srcs[0], dst=dest)/TCP(), verbose=0)

def timer():
  print("Starting...")
  while True:
    sleep(checkTime)
    tableMutex.acquire()
    for i in reversed(range(len(ipHeader))): # Começa a checar do último para evitar erro de indexação
      lastReference = time() - ipTimer[i]
      if lastReference > tempoLimite:
        print("Removed package... IP:", ipHeader[i], "Last reference:", lastReference, "seconds ago")
        ipTimer.pop(i)
        ipHeader.pop(i)
        ipTable.pop(i)
    tableMutex.release()

def monitorCallback(pkt):
  ipPkt = pkt.payload
  print("Package captured... IP:", ipPkt.src)
  tableMutex.acquire()
  if ipPkt.src not in ipHeader:
    ipHeader.append(ipPkt.src)
    ipTimer.append(time())
    ipTable.append([])
    ipTable[-1].append(pkt)
  else:
    ipTimer[ipHeader.index(ipPkt.src)] = time()
    ipTable[ipHeader.index(ipPkt.src)].append(pkt)
  tableMutex.release()

if __name__ == "__main__":
  initialTime = time()
  checkTime = 5
  tempoLimite = 20 # 5 minutos
  tableMutex = threading.Semaphore(1)

  ipHeader = []
  ipTimer = []
  ipTable = []

  thread_timer = MyThread(timer, ())
  test_thread = MyThread(test, ())
  thread_timer.start()
  test_thread.start()

  sniff(iface="root-eth0", count=20, filter="ip and tcp", prn=monitorCallback)
  #root --> 10.10.10.254
  #eth0 --> 10.10.10.10

  print("-"*20)
  for i in range(len(ipHeader)):
    print(ipHeader[i])
    for j in range(len(ipTable[i])):
      print(ipTable[i][j].summary())
    print(" ")