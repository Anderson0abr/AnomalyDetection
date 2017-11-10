
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
from random import randrange

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

def stressTest():
  print("Starting stress test...")
  dest="10.10.10.10"
  while True:
    send(IP(src="192.30.253."+str(randrange(100)), dst=dest)/TCP(), verbose=0)
    sleep(1)

def printToFile(file):
  for i in range(len(ipHeader)):
    file.write(ipHeader[i] + "\n")
    for j in range(len(ipTable[i])):
      file.write(ipTable[i][j].summary() + "\n")
    file.write("\n")

def timer():
  print("Starting...")
  while True:
    sleep(checkTime)
    rewrite = False
    tableMutex.acquire()
    for i in reversed(range(len(ipHeader))): # Começa a checar do último para evitar erro de indexação
      lastReference = time() - ipTimer[i]
      if lastReference > tempoLimite:
        print("- Removed package... IP:", ipHeader[i], "Last reference:", lastReference, "seconds ago")
        ipTimer.pop(i)
        ipHeader.pop(i)
        ipTable.pop(i)
        rewrite = True
    if rewrite:
      with open("IP_Log.txt", "w") as file:
        printToFile(file)
    tableMutex.release()

def monitorCallback(pkt):
  ipPkt = pkt.payload
  print("+ Package captured... IP:", ipPkt.src)
  tableMutex.acquire()
  if ipPkt.src not in ipHeader:
    ipHeader.append(ipPkt.src)
    ipTimer.append(time())
    ipTable.append([])
    ipTable[-1].append(pkt)
  else:
    ipTimer[ipHeader.index(ipPkt.src)] = time()
    ipTable[ipHeader.index(ipPkt.src)].append(pkt)
  with open("IP_Log.txt", "w") as file:
    printToFile(file)
  tableMutex.release()

if __name__ == "__main__":
  initialTime = time()
  checkTime = 10
  tempoLimite = 5*60 # 5 minutos
  tableMutex = threading.Semaphore(1)

  ipHeader = []
  ipTimer = []
  ipTable = []

  thread_timer = MyThread(timer, ())
  test_thread = MyThread(stressTest, ())
  thread_timer.start()
  test_thread.start()

  sniff(iface="root-eth0", filter="ip and tcp", prn=monitorCallback)
  #root --> 10.10.10.254
  #eth0 --> 10.10.10.10

  with open("IP_Log.txt") as file:
    for line in file:
      print(line.rstrip())