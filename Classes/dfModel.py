import pandas as pd

class DfModel():
	def __init__(self, columns):
		self.columns = columns

	def listToDF(self, row):
	  return pd.DataFrame(data=[row], columns=self.columns)

	def isRowInDF(self, row, dataframe):
	  return not dataframe[(dataframe[self.columns[0]] == row[0]) & (dataframe[self.columns[1]] == row[1]) & (dataframe[self.columns[2]] == row[2]) & (dataframe[self.columns[3]] == row[3]) & (dataframe[self.columns[4]] == row[4])].empty

	def appendRowInDF(self, row, dataframe):
	  return dataframe.append(self.listToDF(row), ignore_index=True)

	def updateRowInDF(self, row, dataframe):
	  index = dataframe[(dataframe[self.columns[0]] == row[0]) & (dataframe[self.columns[1]] == row[1]) & (dataframe[self.columns[2]] == row[2]) & (dataframe[self.columns[3]] == row[3]) & (dataframe[self.columns[4]] == row[4])].index
	  dataframe.loc[index, self.columns[6]] = pd.Timestamp('now')
	  return dataframe

	def deleteExpiredRowsInDF(self, dataframe):
	  df = dataframe[(pd.Timestamp('now') - dataframe["Last reference"]) <= pd.Timedelta('5m')]
	  if df.equals(dataframe):
	    return False
	  else:
	    dataframe = df
	    return True