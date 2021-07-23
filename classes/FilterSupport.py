from PyQt5.QtWidgets import QDialog
from PyQt5 import uic

class FilterSupport(QDialog):
	def __init__(self):
		super().__init__()

		#load template
		uic.loadUi("templates/FilterSyntaxSupport.ui", self)

		self.show()

# if __name__ == "__main__":
# 	app = QApplication(sys.argv)
# 	mainWindow = IpsWindow("192.168.1.1",[])
# 	sys.exit(app.exec_())