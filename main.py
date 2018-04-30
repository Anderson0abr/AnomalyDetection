
#!/usr/bin/env python
# coding: utf-8

"""
Analisador e monitorador de tráfego de rede para detecção de ataques
Trabalho de Conclusão de Curso (TCC)
Ciência da Computação - Universidade Estadual do Ceará (UECE)

Desenvolvido por: Anderson Bezerra Ribeiro
Data: 30/10/2017
"""

import threading
import pandas as pd
import warnings
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from Classes.myThread import MyThread
from scapy.all import *
from time import time, sleep
from random import randrange, choice
from sklearn import preprocessing 
from sklearn_pandas import DataFrameMapper
from sklearn.covariance import EllipticEnvelope


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
  global keep_test
  dest="10.10.10.10"
  while keep_test:
    send(IP(src=str(randrange(256))+"."+str(randrange(256))+"."+str(randrange(256))+"."+str(randrange(256)), dst=dest)/choice([TCP(),UDP()]), verbose=0)
  print("Stopping stress test...")

def ipInt(ip):
  ipInt = ''
  for i in ip.split('.'):
    ipInt += '0' * (3-len(i)) + i
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
  sleep(checkTime)
  while keep_timer:
    tableMutex.acquire()
    deleted = deleteExpiredRowsInDF()
    if deleted:
      ipDf[["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size"]].to_csv(file)
    tableMutex.release()
    sleep(checkTime)
  print("Stopping timer thread...")

def l2Proto(pkt):
  if pkt.proto == 6:
    l2Protocol = "tcp"
  elif pkt.proto == 17:
    l2Protocol = "udp"
  return l2Protocol

def monitorCallback(pkt):
  global ipDf, tableMutex, bandwidth

  if bandwidth == 0:
    bandwidth = len(pkt)
  else:
    bandwidth = (bandwidth+len(pkt))/2

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

def bandwidthMonitor():
  print("Starting bandwidth monitor...")
  global bandwidth, tempoLimite, bandwidthTolerance
  sleep(10)
  initialBandwidth = bandwidth
  start = pd.Timestamp.now()

  while True:
    tempoDecorrido = pd.Timestamp.now()-start
    if tempoDecorrido >= tempoLimite:
      percentual = initialBandwidth*bandwidthTolerance
      if initialBandwidth - percentual < bandwidth < initialBandwidth + percentual:
        initialBandwidth = bandwidth
        start = pd.Timestamp.now()
      else:
        callSolver("Bandwidth = {}. Expected {} < bandwidth < {}".format(bandwidth, initialBandwidth - percentual, initialBandwidth + percentual))
        start = pd.Timestamp.now()

def predict(pkt):
  global clf, mapper
  ###
  global testSet
  ###
  ipPkt = pkt.payload
  l2Pkt = ipPkt.payload
  l2Protocol = l2Proto(ipPkt)

  rowPkt = [ipInt(ipPkt.src), ipInt(ipPkt.dst), l2Protocol, l2Pkt.sport, l2Pkt.dport, len(pkt)]
  ###
  testSet = testSet.append(pd.DataFrame([rowPkt], columns = columns[:-1]), ignore_index = True)
  testSet.to_csv("TestSet.csv")
  ###
  X = mapper.transform(pd.DataFrame([rowPkt], columns=columns[:-1]))
  y_pred = clf.predict(X)

  if(not bool(y_pred)): # Anomalia detectada
    callSolver("Anomaly detected")

def callSolver(msg):
  print("{}. Calling solver...".format(msg))
  pass

if __name__ == "__main__":
  warnings.filterwarnings(action='ignore')
  file = "Profile.csv"

  bandwidth = 0.0
  bandwidthTolerance = 0.25 # 25%

  checkTime = 30 # 30 segundos
  tempoLimite = pd.Timedelta('10s') # 15 minutos
  keep_timer = True
  keep_test = True

  tableMutex = threading.Semaphore(1)

  #Criando DataFrame e definindo tipos
  columns = ["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size", "Last reference"]
  ipDf = pd.DataFrame(columns = columns)
  ipDf[columns[:2]] = ipDf[columns[:2]].astype("int")
  ipDf[columns[3:-1]] = ipDf[columns[3:-1]].astype("int")
  ipDf["Last reference"] = pd.to_datetime(ipDf["Last reference"])

  thread_timer = MyThread(timer, ())
  test_thread = MyThread(stressTest, ())
  bandwidth_thread = MyThread(bandwidthMonitor, ())
  thread_timer.start()
  test_thread.start()
  bandwidth_thread.start()
  

  sniff(iface="root-eth0", filter="ip", prn=monitorCallback, count=1000)
  #root --> 10.10.10.254
  #eth0 --> 10.10.10.10

  keep_timer=False
  print("Profile defined")
  profile = pd.read_csv(file, index_col = 0)
  profile["L2 protocol"] = profile["L2 protocol"].astype("category")

  mapper = DataFrameMapper([(["IP source", "IP destiny"], preprocessing.StandardScaler()),
                            ("L2 protocol", preprocessing.LabelBinarizer()),
                            (["Source port", "Destiny port", "Package size"], preprocessing.StandardScaler())
                          ])
  mapper.fit(profile)

  clf = EllipticEnvelope()
  clf.fit(mapper.transform(profile))

  ### Salva dados para teste
  testSet = pd.DataFrame(columns = columns[:-1])
  testSet[columns[:2]] = testSet[columns[:2]].astype("int")
  testSet[columns[3:-1]] = testSet[columns[3:-1]].astype("int")
  ###

  print("Initializing monitor")

  sniff(iface="root-eth0", filter="ip", prn=predict, count=1000)
  keep_test=False