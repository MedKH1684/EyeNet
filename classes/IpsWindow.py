from PyQt5.QtWidgets import QWidget, QTreeWidget, QLabel, QTreeWidgetItem
from PyQt5 import uic, QtCore

class IpsWindow(QWidget):
	def __init__(self, localip, ipsList):
		super().__init__()
		self.localip = localip
		self.ipsList = ipsList

		#load template
		uic.loadUi("templates/IpsWindow.ui", self)

		#finding children
		self.localIP = self.findChild(QLabel, "localIP")
		self.ipsTree = self.findChild(QTreeWidget, "ipsTree")
		self.localiptext = self.findChild(QLabel, "localiptext")
		self.localiptext.setAlignment(QtCore.Qt.AlignLeft)

		#local IP
		self.localIP.setText(self.localip)
		self.localIP.setAlignment(QtCore.Qt.AlignRight)

		#IPs Tree
		for ip in self.ipsList:
			self.ipsTree.addTopLevelItem(QTreeWidgetItem([ip]))

		self.show()

# if __name__ == "__main__":
# 	app = QApplication(sys.argv)
# 	mainWindow = IpsWindow("192.168.1.1",[])
# 	sys.exit(app.exec_())