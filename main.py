
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
import numpy as np
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
  df = ipDf[(pd.Timestamp('now') - ipDf["Last reference"]) <= tempo_limite]
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
  global ipDf, tableMutex, bandwidth, parcialPackages

  bandwidth += len(pkt)

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

def throughputMonitor():
  print("Starting throughput monitor...")
  global bandwidth, bandwidth_Checktime, throughput_tolerance, bandwidth_errors, throughput, profile_time
  if profile_time < bandwidth_Checktime:
    sleep((bandwidth_Checktime - profile_time).total_seconds())
    initial_throughput = bandwidth/bandwidth_Checktime.total_seconds()
  else:
    initial_throughput = bandwidth/profile_time.total_seconds()
  bandwidth = 0.0
  start = pd.Timestamp.now()

  while True:
    tempoDecorrido = pd.Timestamp.now()-start
    if tempoDecorrido >= bandwidth_Checktime:
      throughput = bandwidth/tempoDecorrido.total_seconds()
      percentual = initial_throughput*throughput_tolerance
      if initial_throughput - percentual < throughput < initial_throughput + percentual:
        initial_throughput = throughput
        start = pd.Timestamp.now()
        print("bandwidth:", bandwidth)
      else:
        bandwidth_errors += 1
        callSolver("Throughput = {} bps. Expected {} < throughput < {}".format(str(np.round(throughput, 2))[:4], str(np.round(initial_throughput - percentual, 2))[:4], str(np.round(initial_throughput + percentual, 2))[:4]))
        start = pd.Timestamp.now()
      bandwidth = 0.0

def predict(pkt):
  global clf, mapper, bandwidth, total_packages, anomaly_errors, test_set

  total_packages += 1
  bandwidth += len(pkt)

  ipPkt = pkt.payload
  l2Pkt = ipPkt.payload
  l2Protocol = l2Proto(ipPkt)

  rowPkt = [ipInt(ipPkt.src), ipInt(ipPkt.dst), l2Protocol, l2Pkt.sport, l2Pkt.dport, len(pkt)]

  test_set = test_set.append(pd.DataFrame([rowPkt], columns = columns[:-1]), ignore_index = True)
  test_set.to_csv("TestSet.csv")

  X = mapper.transform(pd.DataFrame([rowPkt], columns=columns[:-1]))
  y_pred = clf.predict(X)

  if(y_pred == -1): # Anomalia detectada
    anomaly_errors += 1
    callSolver("Anomaly {} detected".format(anomaly_errors))

def callSolver(msg):
  print("{}. Calling solver...".format(msg))
  pass

if __name__ == "__main__":
  start_time = pd.Timestamp.now()
  warnings.filterwarnings(action='ignore')
  file = "Profile.csv"

  total_packages = 0
  anomaly_errors = 0

  bandwidth = 0.0
  throughput_tolerance = 0.10 # 10%
  bandwidth_errors = 0
  bandwidth_Checktime = pd.Timedelta('1m') # 1 minuto
  throughput = 0.0 # taxa em bytes por segundo

  checkTime = 30 # 30 segundos
  tempo_limite = pd.Timedelta('15m') # 15 minutos
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
  throughput_thread = MyThread(throughputMonitor, ())
  #thread_timer.start()
  test_thread.start()
  

  #sniff(iface="root-eth0", filter="ip", prn=monitorCallback, count=1000)
  #root --> 10.10.10.254
  #eth0 --> 10.10.10.10

  keep_timer=False
  profile_time = pd.Timestamp.now() - start_time
  print("Profile defined")

  throughput_thread.start()

  profile = pd.read_csv(file, index_col = 0)
  profile["L2 protocol"] = profile["L2 protocol"].astype("category")

  mapper = DataFrameMapper([(["IP source", "IP destiny"], preprocessing.StandardScaler()),
                            ("L2 protocol", preprocessing.LabelBinarizer()),
                            (["Source port", "Destiny port", "Package size"], preprocessing.StandardScaler())
                          ])
  mapper.fit(profile)

  clf = EllipticEnvelope()
  clf.fit(mapper.transform(profile))

  test_set = pd.DataFrame(columns = columns[:-1])
  test_set[columns[:2]] = test_set[columns[:2]].astype("int")
  test_set[columns[3:-1]] = test_set[columns[3:-1]].astype("int")

  print("Initializing monitor")

  sniff(iface="root-eth0", filter="ip", prn=predict)
  keep_test=False

  print("Anomaly errors: {}/{}".format(anomaly_errors, total_packages))
  print("Bandwidth errors:", bandwidth_errors)
  print("Profile time:", profile_time)
  print("Program duration:", pd.Timestamp.now() - start_time)