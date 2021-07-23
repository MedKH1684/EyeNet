from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QComboBox, QLineEdit, QFileDialog
from PyQt5 import uic
from PyQt5.QtCore import pyqtSignal
from scapy.all import get_if_list, compile_filter
from .FilterWindow import FilterWindow
from .FilterSupport import FilterSupport
import re
import os

class FirstWindow(QWidget):

	startedSig = pyqtSignal(str,str)
	dbSig = pyqtSignal()
	openSig = pyqtSignal(str)

	def __init__(self, currentMode):
		super().__init__()
		self.currentMode = currentMode

		#load template
		uic.loadUi("templates/FirstWindow.ui", self)

		#find childs
		self.iface = self.findChild(QComboBox, "iface")
		self.filterSyntaxHelp = self.findChild(QPushButton, "filterSyntaxHelp")
		self.clearFilterSearchBar = self.findChild(QPushButton, "clearFilterSearchBar")
		self.filter = self.findChild(QPushButton, "filter")
		self.filterSearchBar = self.findChild(QLineEdit, "filterSearchBar")
		self.start = self.findChild(QPushButton, "startCapturing")
		self.database = self.findChild(QPushButton, "database")
		self.open = self.findChild(QPushButton, "open")

		#connect children
		self.filterSyntaxHelp.clicked.connect(self.filterSyntaxHelpClicked)
		self.clearFilterSearchBar.clicked.connect(lambda: self.filterSearchBar.setText(""))
		self.filter.clicked.connect(self.filterWindowClicked)
		self.filterSearchBar.textChanged.connect(self.filterSearchBarChanged)
		self.start.clicked.connect(self.started)
		self.database.clicked.connect(self.dbClicked)
		self.open.clicked.connect(self.openClicked)

		#initialize
		self.iface.addItem("All")
		for iface in get_if_list():
			self.iface.addItem(iface)
		self.filterStr=""

		with open("stylesheets/darkmode.css", "r") as f: self.darkmode = f.read()
		with open("stylesheets/lightmode.css", "r") as f: self.lightmode = f.read()
		with open("stylesheets/filterWindowStyleD.css", "r") as f: self.filterWindowStyleD = f.read()

		if self.currentMode == self.darkmode:
			with open("stylesheets/filterSearchBarOriginalD.css", "r") as f: self.filterSearchBarOriginal = f.read()
			with open("stylesheets/filterSearchBarValidD.css", "r") as f: self.filterSearchBarValid = f.read()
			with open("stylesheets/filterSearchBarErrorD.css", "r") as f: self.filterSearchBarError = f.read()
		elif self.currentMode == self.lightmode:
			with open("stylesheets/filterSearchBarOriginalL.css", "r") as f: self.filterSearchBarOriginal = f.read()
			with open("stylesheets/filterSearchBarValidL.css", "r") as f: self.filterSearchBarValid = f.read()
			with open("stylesheets/filterSearchBarErrorL.css", "r") as f: self.filterSearchBarError = f.read()

	def started(self):
		self.startedSig.emit(self.iface.currentText(), self.filterSearchBar.text())
		self.close()

	def dbClicked(self):
		self.dbSig.emit()
		self.close()

	def openClicked(self):
		self.openedFileName = QFileDialog.getOpenFileName(self, 'Open Capture file', os.getcwd(), "Capture File (*.cap *.pcap *.pcapng)")[0]

		if self.openedFileName != "":
			self.openSig.emit(self.openedFileName)
			self.close()

	def filterSearchBarChanged(self):
		self.filterStr = self.filterSearchBar.text()
		if self.filterStr == "":
			self.filterSearchBar.setStyleSheet(self.filterSearchBarOriginal)
			if not self.start.isEnabled():
					self.start.setEnabled(True)
					self.database.setEnabled(True)
					self.open.setEnabled(True)
		else:
			#validate filter
			dateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d))(?: and)?")
			dateToDateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)) to (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)(?: and)?")

			dateAndList = re.findall(dateAndPattern, self.filterStr)
			dateToDateAndList = re.findall(dateToDateAndPattern, self.filterStr)

			self.filterStrParsed = self.filterStr

			if dateToDateAndList!=[]:
				if len(dateToDateAndList)==1:
					self.filterStrParsed=" and ".join(list(filter(None,self.filterStr.split(dateToDateAndList[0]))))
			elif dateAndList!=[]:
				if len(dateAndList)==1:
					self.filterStrParsed=" and ".join(list(filter(None,self.filterStr.split(dateAndList[0]))))
					
			try:
				compile_filter(self.filterStrParsed)
				self.filterSearchBar.setStyleSheet(self.filterSearchBarValid)
				if not self.start.isEnabled():
					self.start.setEnabled(True)
					self.database.setEnabled(True)
					self.open.setEnabled(True)
			except:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarError)
				if self.start.isEnabled():
					self.start.setEnabled(False)
					self.database.setEnabled(False)
					self.open.setEnabled(False)

	def filterWindowClicked(self):
		self.filterWindow = FilterWindow()
		if self.currentMode == self.darkmode:
			self.filterWindow.setStyleSheet(self.filterWindowStyleD)
		elif self.currentMode == self.lightmode:
			self.filterWindow.setStyleSheet(self.currentMode)
		self.filterWindow.apply_button.connect(self.getFilterStr)

	def getFilterStr(self, filterStr):
		self.filterStr = filterStr
		self.filterSearchBar.setText(filterStr)

	def filterSyntaxHelpClicked(self):
		self.filterSupport = FilterSupport()
		self.filterSupport.setStyleSheet(self.currentMode)


# if __name__ == "__main__":
# 	app = QApplication(sys.argv)
# 	mainWindow = IpsWindow("192.168.1.1",[])
# 	sys.exit(app.exec_())