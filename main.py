
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
from Classes.dfModel import DfModel
from scapy.all import *
from time import sleep
from random import choice
from sklearn import preprocessing 
from sklearn_pandas import DataFrameMapper
from sklearn.covariance import EllipticEnvelope

def stressTest():
    print("Starting stress test...")
    global keep_test
    dest="10.10.10.10"
    while keep_test:
      ip_bin = format(int(np.round((2**32-1)*np.random.random())),'b')
      ip_bin = '0'*(32-len(ip_bin)) + ip_bin
      ip = [ip_bin[:-24], ip_bin[-24:-16], ip_bin[-16:-8], ip_bin[-8:]]
      origin = '.'.join([str(int(x,2)) for x in ip])
      send(IP(src=origin, dst=dest)/choice([TCP(),UDP()]), verbose=0)
    print("Stopping stress test...")

def ipInt(ip):
  ipInt = ''
  for i in ip.split('.'):
    ipInt += '0' * (3-len(i)) + i
  return int(ipInt)

def timer():
  print("Starting timer thread...")
  global ipDf, profile_phase, tableMutex
  sleep(checkTime)
  while profile_phase:
    tableMutex.acquire()
    deleted = dfModel.deleteExpiredRowsInDF(ipDf)
    if deleted:
      ipDf[["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size"]].to_csv(profile_file)
    tableMutex.release()
    sleep(checkTime)
  print("Stopping timer thread...")

def l2Proto(pkt):
  if pkt.proto == 6:
    l2Protocol = "tcp"
  elif pkt.proto == 17:
    l2Protocol = "udp"
  return l2Protocol

def throughputMonitor():
  print("Starting throughput monitor...")
  global bandwidth, throughput_errors, throughput, throughput_check, profile_phase, throughput_list
  
  start_time = pd.Timestamp.now()
  while profile_phase:
    time_running = pd.Timestamp.now() - start_time
    if time_running >= bandwidth_checktime:
      throughput_list.append(bandwidth/time_running.total_seconds())
      start_time = pd.Timestamp.now()
      bandwidth = 0.0

  start_time = pd.Timestamp.now()
  while True:
    time_running = pd.Timestamp.now() - start_time
    if time_running >= bandwidth_checktime:
      throughput_check += 1
      throughput = bandwidth/time_running.total_seconds()
      if not (throughput_mean - throughput_deviation < throughput < throughput_mean + throughput_deviation):
        throughput_errors += 1
        callSolver("Throughput = {} bps. Expected {} < throughput < {}".format(str(np.round(throughput, 2))[:4], str(np.round(throughput_mean - throughput_deviation, 2))[:4], str(np.round(throughput_mean + throughput_deviation, 2))[:4]))
      start_time = pd.Timestamp.now()
      bandwidth = 0.0

def createProfile(pkt):
  global ipDf, tableMutex, bandwidth, profile_packages

  profile_packages += 1
  bandwidth += len(pkt)

  ipPkt = pkt.payload
  l2Pkt = ipPkt.payload
  l2Protocol = l2Proto(pkt)

  rowPkt = [ipInt(ipPkt.src), ipInt(ipPkt.dst), l2Protocol, l2Pkt.sport, l2Pkt.dport, len(pkt), pd.to_datetime("now")]
  tableMutex.acquire()
  if dfModel.isRowInDF(rowPkt, ipDf):
    ipDf = dfModel.updateRowInDF(rowPkt, ipDf)
  else:
    ipDf = dfModel.appendRowInDF(rowPkt, ipDf)
  ipDf[["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size"]].to_csv(profile_file)
  tableMutex.release()

def predict(pkt):
  global clf, mapper, bandwidth, predicted_packages , anomaly_errors, test_set

  predicted_packages += 1
  bandwidth += len(pkt)

  ipPkt = pkt.payload
  l2Pkt = ipPkt.payload
  l2Protocol = l2Proto(ipPkt)

  rowPkt = [ipInt(ipPkt.src), ipInt(ipPkt.dst), l2Protocol, l2Pkt.sport, l2Pkt.dport, len(pkt)]

  test_set = test_set.append(pd.DataFrame([rowPkt], columns = columns[:-1]), ignore_index = True)
  test_set.to_csv(test_file)

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
  profile_file = "Profile.csv"
  test_file = "Test.csv"

  profile_packages = 0
  predicted_packages = 0
  anomaly_errors = 0
  throughput_check = 0

  bandwidth = 0.0
  bandwidth_checktime = pd.Timedelta('1m') 
  throughput = 0.0 # taxa em bytes por segundo
  throughput_errors = 0
  throughput_list = []

  checkTime = pd.Timedelta('30s').total_seconds() # 30 segundos
  profile_phase = True
  keep_test = True

  tableMutex = threading.Semaphore(1)

  #Criando DataFrame e definindo tipos
  columns = ["IP source", "IP destiny", "L2 protocol", "Source port", "Destiny port", "Package size", "Last reference"]
  ipDf = pd.DataFrame(columns = columns)
  ipDf[columns[:2]] = ipDf[columns[:2]].astype("int")
  ipDf[columns[3:-1]] = ipDf[columns[3:-1]].astype("int")
  ipDf["Last reference"] = pd.to_datetime(ipDf["Last reference"])

  dfModel = DfModel(columns)
  thread_timer = MyThread(timer, ())
  test_thread = MyThread(stressTest, ())
  throughput_thread = MyThread(throughputMonitor, ())

  thread_timer.start()
  test_thread.start()
  throughput_thread.start()

  sniff(iface="root-eth0", filter="ip", prn=createProfile, timeout=pd.Timedelta('15m').total_seconds())
  #root --> 10.10.10.254
  #eth0 --> 10.10.10.10

  profile_phase=False
  print("Profile defined. {} packages captured.".format(profile_packages))

  throughput_mean = np.mean(throughput_list)
  throughput_deviation = np.std(throughput_list)

  profile = pd.read_csv(profile_file, index_col = 0)
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

  sniff(iface="root-eth0", filter="ip", prn=predict, timeout=pd.Timedelta('45m').total_seconds())
  keep_test=False

  print("Throughput mean: ", throughput_mean)
  print("Throughput standart deviation: ", throughput_deviation)
  print("Anomaly errors: {}/{}".format(anomaly_errors, predicted_packages))
  print("Throughput errors: {}/{}".format(throughput_errors, throughput_check))