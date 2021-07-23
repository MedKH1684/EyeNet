from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QLineEdit, QDateEdit, QCheckBox, QPushButton, QGroupBox, QComboBox
from PyQt5.QtCore import QSize, QRegExp, pyqtSignal
from PyQt5.QtGui import QRegExpValidator
from PyQt5 import uic
from scapy.all import compile_filter, conf
import sys
 
class FilterWindow(QDialog):
	
	#filter signal
	apply_button = pyqtSignal(str)

	def __init__(self):
		super().__init__()
		uic.loadUi("templates/FilterWindow.ui", self)

		self.show()

	#find children
		#basic filters
		self.macsrc = self.findChild(QLineEdit, "macsrc")
		self.macdst = self.findChild(QLineEdit, "macdst")
		self.ipsrc = self.findChild(QLineEdit, "ipsrc")
		self.ipdst = self.findChild(QLineEdit, "ipdst")
		self.datecap = self.findChild(QDateEdit, "datecap")
		self.datecap2 = self.findChild(QDateEdit, "datecap2")
		#network filters
		self.netip = self.findChild(QLineEdit, "netip")
		self.netmask = self.findChild(QLineEdit, "netmask")
		#icmp filters
		self.icmpfilter = self.findChild(QGroupBox, "icmpfilter")
		self.icmptype = self.findChild(QComboBox, "icmptype")
		#tcp filters
		self.tcpfilter = self.findChild(QGroupBox, "tcpfilter")
		self.tcpportsrc = self.findChild(QLineEdit, "tcpportsrc")
		self.tcpportdst = self.findChild(QLineEdit, "tcpportdst")
		self.uflag = self.findChild(QCheckBox, "uflag")
		self.aflag = self.findChild(QCheckBox, "aflag")
		self.pflag = self.findChild(QCheckBox, "pflag")
		self.rflag = self.findChild(QCheckBox, "rflag")
		self.sflag = self.findChild(QCheckBox, "sflag")
		self.fflag = self.findChild(QCheckBox, "fflag")
		#udp filters
		self.udpfilter = self.findChild(QGroupBox, "udpfilter")
		self.udpportsrc = self.findChild(QLineEdit, "udpportsrc")
		self.udpportdst = self.findChild(QLineEdit, "udpportdst")
		#ipv6 filters
		self.ipv6filter = self.findChild(QGroupBox, "ipv6filter")
		self.ipv6src = self.findChild(QLineEdit, "ipv6src")
		self.ipv6dst = self.findChild(QLineEdit, "ipv6dst")
		#arp checkbox
		self.arp = self.findChild(QCheckBox, "arpfilter")
		#apply button
		self.apply = self.findChild(QPushButton, "apply")

	#add icmp types to combobox
		self.icmptypes = ['0 ', '3 ', '5 ', '8 ', '9 ', '10 ', '11 ', '12 ', '13 ', '14 ', '19 ', '40 ', '41 ', '42 ', '43 ', '253 ', '254 ']
		self.icmptypenames = ['None', 'Echo Reply ', 'Destination Unreachable ', 'Redirect ', 'Echo Request ', 'Router Advertisement ', 'Router Solicitation ', 'Time Exceeded ', 'Parameter Problem ', 'Timestamp ', 'Timestamp Reply ', 'Reserved (for Security) ', 'Photuris ', 'ICMP messages utilized by experimental mobility protocols such as Seamoby ', 'Extended Echo Request ', 'Extended Echo Reply ', 'RFC3692-style Experiment 1 ', 'RFC3692-style Experiment 2 ']
		self.icmptype.addItems(self.icmptypenames)

	#textedit validation
		#validate ip addresses
		ipRange = "(?:[0-1]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])"
		ipRegex = QRegExp("^(!?" + ipRange + "\\." + ipRange + "\\." + ipRange + "\\." + ipRange + "\\,)+")
		ipValidator = QRegExpValidator(ipRegex, self)
		self.ipsrc.setValidator(ipValidator)
		self.ipdst.setValidator(ipValidator)
		#netmask validator
		netmaskRegex = QRegExp("^!?" + ipRange + "\\." + ipRange + "\\." + ipRange + "\\." + ipRange + "$")
		netmaskValidator = QRegExpValidator(netmaskRegex, self)
		self.netmask.setValidator(netmaskValidator)
		self.netip.setValidator(ipValidator)
		#validate mac addresses
		macRange = "(?:[0-9a-fA-F][0-9a-fA-F])"
		macRegex = QRegExp("^(!?" + macRange + "\\:" + macRange + "\\:" + macRange + "\\:" + macRange + "\\:" + macRange + "\\:" + macRange + "\\,)+")
		macValidator = QRegExpValidator(macRegex, self) 
		self.macsrc.setValidator(macValidator)
		self.macdst.setValidator(macValidator)
		#validate port number / port range
		PortRE = "(?:0|[1-5]?[0-9]?[0-9]?[0-9]?[0-9]|6[0-5][0-5][0-3][0-5])"
		PortRange = PortRE + "(\\-" + PortRE + ")?"
		PortRegex = QRegExp("^(!?" + PortRange + "\\,)+")
		PortValidator = QRegExpValidator(PortRegex, self) 
		self.tcpportsrc.setValidator(PortValidator)
		self.tcpportdst.setValidator(PortValidator)
		self.udpportsrc.setValidator(PortValidator)
		self.udpportdst.setValidator(PortValidator)
		#validate ipv6 addresses
		ipv6Range = "(?:[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])?"
		ipv6Regex = QRegExp("^(!?" + ipv6Range + "\\:" + ipv6Range + "\\:" + ipv6Range + "\\:" + ipv6Range + "\\:" + ipv6Range + "\\:" + ipv6Range + "\\:" + ipv6Range + "\\:" + ipv6Range + "\\,)+")
		ipv6Validator = QRegExpValidator(ipv6Regex, self)
		self.ipv6src.setValidator(ipv6Validator)
		self.ipv6dst.setValidator(ipv6Validator)
		#icmptype validator
		typeRange = "(?:[0-1][0-8])"
		typeRegex = QRegExp("^" + typeRange + "$")
		typeValidator = QRegExpValidator(typeRegex, self)
		self.icmptype.setValidator(typeValidator)

	#link button
		self.apply.clicked.connect(self.tanslateToBPF)

	#show window
		self.show()

	def tanslateToBPF(self):
		#translate basic filters
		mac_src=mac_dst=ip_src=ip_dst=date_cap=date_cap2=net_ip=net_mask=net=icmp=tcp=tcpsrcports=tcpdstports=udpsrcports=udpdstports=flag=udp=ipv6_src=ipv6_dst=ipv6=arp=""
		if self.macsrc.text() != "":
			mac_src = "".join([f"ether src {i} or " for i in self.macsrc.text().split(",")])[:-4]
			mac_src = "("+mac_src+")"
		if self.macdst.text() != "":
			mac_dst = "".join([f"ether dst {i} or " for i in self.macdst.text().split(",")])[:-4]
			mac_dst="("+mac_dst+")"
		if self.ipsrc.text() != "":
			ip_src = "".join([f"src host {i} or " for i in self.ipsrc.text().split(",")])[:-4]
			ip_src="("+ip_src+")"
		if self.ipdst.text() != "":
			ip_dst = "".join([f"dst host {i} or " for i in self.ipdst.text().split(",")])[:-4]
			ip_dst="("+ip_dst+")"
		#translate network filters
		if self.netip.text() != "":
			net_ip = f"net {self.netip.text()}"
			if self.netmask.text() != "":
				net_mask = f" mask {self.netmask.text()}"
			net = "("+net_ip+net_mask+")"
		#translate icmp
		if self.icmpfilter.isChecked():
			if self.icmptype.currentIndex()!=0:
				icmp = f"icmp[icmptype]=={self.icmptypes[self.icmptype.currentIndex()-1]}"
		else:
			icmp = "!icmp"
		#translate tcp
		if self.tcpfilter.isChecked():
			#translate ports
			if self.tcpportsrc.text()!="":
				tcpsrcports = "".join([f"tcp src portrange {i} or " if "-" in i else f"tcp src port {i} or " for i in self.tcpportsrc.text().split(",")])[:-4]
				tcpsrcports="("+tcpsrcports+")"
			if self.tcpportdst.text()!="":
				tcpdstports = "".join([f"tcp dst portrange {i} or " if "-" in i else f"tcp dst port {i} or " for i in self.tcpportdst.text().split(",")])[:-4]
				tcpdstports="("+tcpdstports+")"
			#translate flags
			if self.uflag.isChecked():
				flag+="tcp[13] & 32 != 0 or "
			if self.aflag.isChecked():
				flag+="tcp[13] & 16 != 0 or "
			if self.pflag.isChecked():
				flag+="tcp[13] & 8 != 0 or "
			if self.rflag.isChecked(): 
				flag+="tcp[13] & 4 != 0 or "
			if self.sflag.isChecked():
				flag+="tcp[13] & 2 != 0 or "
			if self.fflag.isChecked():
				flag+="tcp[13] & 1 != 0 or "
			tcp = " and ".join(list(filter(None, [tcpsrcports,tcpdstports,flag[:-4]])))
		else:
			tcp = "!tcp"
		#translate udp
		if self.udpfilter.isChecked():
			if self.udpportsrc.text()!="":
				udpsrcports = "".join([f"udp src portrange {i} or " if "-" in i else f"udp src port {i} or " for i in self.udpportsrc.text().split(",")])[:-4]
			if self.udpportdst.text()!="":
				udpdstports = "".join([f"udp dst portrange {i} or " if "-" in i else f"udp dst port {i} or " for i in self.udpportdst.text().split(",")])[:-4]
			udp = " and ".join(list(filter(None, [udpsrcports,udpdstports])))
		else:
			udp = "!udp"
		#translate ipv6
		if self.ipv6filter.isChecked():
			if self.ipv6src.text()!="":
				ipv6_src = "".join([f"ip6 src {i} or " for i in self.ipv6src.text().split(",")])[:-4]
				ipv6_src="("+ipv6_src+")"
			if self.ipv6dst.text()!="":
				ipv6_dst = "".join([f"ip6 dst {i} or " for i in self.ipv6dst.text().split(",")])[:-4]
				ipv6_dst="("+ipv6_dst+")"
			ipv6 = " and ".join(list(filter(None, [ipv6_src,ipv6_dst])))
		else:
			ipv6 = "!ip6"
		#translate arp
		if not self.arpfilter.isChecked():
			arp="!arp"

		#date get/set
		if (self.datecap.date().day() != 1 or self.datecap.date().month()!=1 or self.datecap.date().year()!=2000) and (self.datecap2.date().day() != 1 or self.datecap2.date().month()!=1 or self.datecap2.date().year()!=2000):
			date_cap=f"{str(self.datecap.date().day()).zfill(2)}-{str(self.datecap.date().month()).zfill(2)}-{str(self.datecap.date().year())}"
			date_cap2=f"{str(self.datecap2.date().day()).zfill(2)}-{str(self.datecap2.date().month()).zfill(2)}-{str(self.datecap2.date().year())}"
		if date_cap!="":
			fullDate = date_cap+" to "+date_cap2
			dateStr = "date " + fullDate
		else:
			fullDate = ""
			dateStr = ""

		self.filterStr=" and ".join(list(filter(None, [mac_src,mac_dst,ip_src,ip_dst,net,icmp,tcp,udp,ipv6,arp])))
		
		try:
			compile_filter(self.filterStr)
		except:
			self.filterStr = ""

		self.filterStr=" and ".join(list(filter(None, [dateStr,self.filterStr])))

		self.apply_button.emit(self.filterStr)
		self.close()

 
# if __name__ == "__main__":
# 	app = QApplication(sys.argv)
# 	filterWindow = FilterWindow()
# 	sys.exit(app.exec())