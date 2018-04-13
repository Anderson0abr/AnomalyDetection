
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
from sklearn import preprocessing 
from sklearn_pandas import DataFrameMapper
from sklearn.covariance import EllipticEnvelope

import threading
import pandas as pd
import warnings

def test():
  #checktime 5s limite 20s
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
    send(IP(src=srcs[2], dst=dest)/UDP(), verbose=0)
    send(IP(src=srcs[3], dst=dest)/TCP(), verbose=0)
  send(IP(src=srcs[0], dst=dest)/TCP(), verbose=0)
  sleep(10)
  send(IP(src=srcs[0], dst=dest)/TCP(), verbose=0)

def stressTest():
  print("Starting stress test...")
  dest="10.10.10.10"
  for i in range(3000):
    send(IP(src=str(randrange(255))+"."+str(randrange(255))+"."+str(randrange(255))+"."+str(randrange(255)), dst=dest)/choice([TCP(),UDP()]), verbose=0)
  print("Stopping stress test...")

def ipInt(ip):
  ipInt = ''
  for i in ip.split('.'):
    ipInt += i
  return int(ipInt)

def listToDF(row):
  return pd.DataFrame(data=[row], columns=columns)

def isRowInDF(row):
  global ipDf
  return not ipDf[(ipDf[columns[0]] == row[0]) & (ipDf[columns[1]] == row[1]) & (ipDf[columns[2]] == row[2]) & (ipDf[columns[3]] == row[3]) & (ipDf[columns[4]] == row[4])].empty

def appendRowInDF(row):
  global ipDf
  ipDf = ipDf.append(listToDF(row), ignore_index=True)

def updateRowInDF(row):
  global ipDf
  index = ipDf[(ipDf[columns[0]] == row[0]) & (ipDf[columns[1]] == row[1]) & (ipDf[columns[2]] == row[2]) & (ipDf[columns[3]] == row[3]) & (ipDf[columns[4]] == row[4])].index
  ipDf.loc[index, columns[6]] = pd.Timestamp('now')

def deleteExpiredRowsInDF():
  global ipDf
  df = ipDf[(pd.Timestamp('now') - ipDf["Last reference"]) <= tempoLimite]
  if df.equals(ipDf):
    return False
  else:
    ipDf = df
    return True

def timer():
  print("Starting timer thread...")
  global ipDf, keep_timer, tableMutex
  while keep_timer:
    sleep(checkTime)
    tableMutex.acquire()
    deleted = deleteExpiredRowsInDF()
    if deleted:
      ipDf[["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size"]].to_csv(file)
    tableMutex.release()
  print("Stopping timer thread...")

def l2Proto(pkt):
  if pkt.proto == 6:
    l2Protocol = "tcp"
  elif pkt.proto == 17:
    l2Protocol = "udp"
  return l2Protocol

def monitorCallback(pkt):
  global ipDf, tableMutex
  ipPkt = pkt.payload
  l2Pkt = ipPkt.payload
  l2Protocol = l2Proto(pkt)

  rowPkt = [ipInt(ipPkt.src), ipInt(ipPkt.dst), l2Protocol, l2Pkt.sport, l2Pkt.dport, len(pkt), pd.to_datetime("now")]
  tableMutex.acquire()
  if isRowInDF(rowPkt):
    updateRowInDF(rowPkt)
  else:
    appendRowInDF(rowPkt)
  ipDf[["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size"]].to_csv(file)
  tableMutex.release()

def predict(pkt):
  ###
  global ipDf
  ###
  global clf, mapper, tableMutex
  ipPkt = pkt.payload
  l2Pkt = ipPkt.payload
  l2Protocol = l2Proto(ipPkt)

  rowPkt = [ipInt(ipPkt.src), ipInt(ipPkt.dst), l2Protocol, l2Pkt.sport, l2Pkt.dport, len(pkt)]
  X = mapper.transform(listToDF(rowPkt))
  y_pred = clf.predict(X)

  ###
  tableMutex.acquire()
  appendRowInDF(rowPkt)
  ipDf[["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size"]].to_csv("TestSet.csv")
  tableMutex.release()
  ###

  if(not bool(y_pred)): # Anomalia detectada
    sendToSolver(pkt)

def sendToSolver(pkt):
  print("Sending package to solver...")
  # send(pkt)
  pass

if __name__ == "__main__":
  warnings.filterwarnings(action='ignore')
  file = "Profile.csv"
  checkTime = 30 # 30 segundos
  tempoLimite = pd.Timedelta('15m') # 15 minutos
  tableMutex = threading.Semaphore(1)
  keep_timer = True

  #Criando DataFrame e definindo tipos
  columns = ["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size", "Last reference"]
  ipDf = pd.DataFrame(columns = columns)
  ipDf[columns[:2]] = ipDf[columns[:2]].astype("int")
  ipDf[columns[3:-1]] = ipDf[columns[3:-1]].astype("int")
  ipDf["Last reference"] = pd.to_datetime(ipDf["Last reference"])

  thread_timer = MyThread(timer, ())
  test_thread = MyThread(stressTest, ())
  thread_timer.start()
  test_thread.start()
  

  sniff(iface="root-eth0", filter="ip", prn=monitorCallback, count=1000)
  #root --> 10.10.10.254
  #eth0 --> 10.10.10.10

  profile = pd.read_csv(file, index_col = 0)
  profile["L2 protocol"] = profile["L2 protocol"].astype("category")

  mapper = DataFrameMapper([(["IP source", "IP destiny"], preprocessing.StandardScaler()),
                            ("L2 protocol", preprocessing.LabelBinarizer()),
                            (["Source port", "Destiny port", "Package size"], preprocessing.StandardScaler())
                          ])
  mapper.fit(profile)

  clf = EllipticEnvelope()
  clf.fit(mapper.transform(profile))

  ###
  columns = columns[:-1]
  ipDf = pd.DataFrame(columns = columns)
  ipDf[columns[:2]] = ipDf[columns[:2]].astype("int")
  ipDf[columns[3:-1]] = ipDf[columns[3:-1]].astype("int")
  ###

  sniff(iface="root-eth0", filter="ip", prn=predict, count=2000)