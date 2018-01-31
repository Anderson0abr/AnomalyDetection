
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
from random import randrange, choice

import threading
import pandas

def test():
  #checktime 5s limite 20s
  print("Sending packages...")
  #srcs=["www.github.com", "www.facebook.com", "www.google.com", "www.gmail.com", "www.9gag.com"]
  srcs=["192.30.253.112", "157.24.12.35", "172.217.29.164", "216.58.202.229", "151.101.66.133"]
  dest="10.10.10.10"

  for i in range(5):
    send(Ether()/IP(src=srcs[0], dst=dest)/TCP(), verbose=0)
  send(Ether()/IP(src=srcs[4], dst=dest)/TCP(), verbose=0)
  sleep(10)
  for i in range(4):
    send(Ether()/IP(src=srcs[1], dst=dest)/TCP(), verbose=0)
    send(Ether()/IP(src=srcs[2], dst=dest)/UDP(), verbose=0)
    send(Ether()/IP(src=srcs[3], dst=dest)/TCP(), verbose=0)
  send(Ether()/IP(src=srcs[0], dst=dest)/TCP(), verbose=0)
  sleep(10)
  send(Ether()/IP(src=srcs[0], dst=dest)/TCP(), verbose=0)

def stressTest():
  print("Starting stress test...")
  dest="10.10.10.10"
  while True:
    send(Ether()/IP(src="192.30.253."+str(randrange(100)), dst=dest)/choice([TCP(),UDP()]), verbose=0)
    sleep(1)

def printToFile(file):
  for i in range(len(ipHeader)):
    file.write("IpSource: " + str(ipHeader[i][0]) + " IpDest: " + str(ipHeader[i][1]) + " L2Protocol: " + str(ipHeader[i][2]) + " SourcePort: " + str(ipHeader[i][3]) + " DestPort: " + str(ipHeader[i][4]) + "\n")
    for j in range(len(ipTable[i])):
      file.write(ipTable[i][j].summary() + "\n")
    file.write("\n")

def listToDF(row):
  return pandas.DataFrame(data=[row], columns=columns)

def isRowInDF(row):
  return ipDf[(ipDf[columns[0]] == row[0]) & (ipDf[columns[1]] == row[1]) & (ipDf[columns[2]] == row[2]) & (ipDf[columns[3]] == row[3]) & (ipDf[columns[4]] == row[4])].empty

def appendRowInDF(row):
  ipDf = ipDf.append(data=listToDF(row), ignore_index=True)

def updateRowInDF(row):
  index = ipDf[(ipDf[columns[0]] == row[0]) & (ipDf[columns[1]] == row[1]) & (ipDf[columns[2]] == row[2]) & (ipDf[columns[3]] == row[3]) & (ipDf[columns[4]] == row[4])].index
  ipDf.loc[index, columns[6]] += 1
  ipDf.loc[index, columns[7]] = pandas.Timestamp('now')

def deleteExpiredRowsInDF():
  df = ipDf[(pandas.Timestamp('now') - ipDf["Last reference"]) < tempoLimite]
  if df.equals(ipDf):
    for index, row in ipDf[(pandas.Timestamp('now') - ipDf["Last reference"]) > tempoLimite]:
      print("- Removed package... Index:", index, "IpSource:", row[columns[0]], "IpDest:", row[columns[1]], "L2Protocol:", row[columns[2]], "SourcePort:", row[columns[3]], "DestPort:", row[columns[4]], "Package size:", row[columns[5]], "References:", row[columns[6]])
    return False
  else:
    ipDf = df
    return True

def timer():
  print("Starting...")
  while True:
    sleep(checkTime)
    tableMutex.acquire()
    deleted = deleteExpiredRowsInDF()
    if deleted:
      pandas.DataFrame.to_csv(file)
    tableMutex.release()

def monitorCallback(pkt):
  ipPkt = pkt.payload
  l2Pkt = ipPkt.payload
  if ipPkt.proto == 1:
    l2Protocol = "icmp"
  elif ipPkt.proto == 6:
    l2Protocol = "tcp"
  elif ipPkt.proto == 17:
    l2Protocol = "udp"

  rowPkt = [ipPkt.src, ipPkt.dst, l2Protocol, l2Pkt.sport, l2Pkt.dport, len(pkt), 1, pandas.to_datetime("now")]
  print("+ Package captured... IpSource:", rowPkt[0], "IpDest:", rowPkt[1], "L2Protocol:", rowPkt[2], "SourcePort:", rowPkt[3], "DestPort:", rowPkt[4])
  tableMutex.acquire()
  if isRowInDF(rowPkt):
    updateRowInDF(rowPkt)
  else:
    appendRowInDF(rowPkt)
  pandas.DataFrame.to_csv(file)
  tableMutex.release()

if __name__ == "__main__":
  file = "IP_DataFrame.csv"
  checkTime = 30 # 30 segundos
  tempoLimite = pandas.Timedelta('15m') # 15 minutos
  tableMutex = threading.Semaphore(1)

  #Criando DataFrame e definindo tipos
  columns = ["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size", "References", "Last reference"]
  ipDf = pandas.DataFrame(columns = columns)
  ipDf["L2 protocol"] = ipDf["L2 protocol"].astype("category")
  ipDf[columns[3:7]] = ipDf[columns[3:7]].astype("int")
  ipDf["Last reference"] = pandas.to_datetime(ipDf["Last reference"])

  thread_timer = MyThread(timer, ())
  test_thread = MyThread(test, ())
  thread_timer.start()
  test_thread.start()

  sniff(iface="root-eth0", filter="ip", prn=monitorCallback)
  #root --> 10.10.10.254
  #eth0 --> 10.10.10.10

  for index, row in ipDf.iterrows():
    print("Index:", index, "IpSource:", row[columns[0]], "IpDest:", row[columns[1]], "L2Protocol:", row[columns[2]], "SourcePort:", row[columns[3]], "DestPort:", row[columns[4]], "Package size:", row[columns[5]], "References:", row[columns[6]])
