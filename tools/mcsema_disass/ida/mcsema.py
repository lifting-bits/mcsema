from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets

import base64

class MainWindow(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        # contents
        layout = QtWidgets.QVBoxLayout()
        self.initializeWidgets(layout)
        self.parent.setLayout(layout)

        # controls
        temp_layout = QtWidgets.QHBoxLayout()
        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Expanding))
        temp_layout.addWidget(QtWidgets.QPushButton("Execute"))

        layout.addLayout(temp_layout)

    def initializeWidgets(self, layout):
        #
        # logo
        #

        logo_layout = QtWidgets.QHBoxLayout()

        logo_image = QtGui.QPixmap()
        logo_image.loadFromData(base64.b64decode(logo_image_base64))

        logo = QtWidgets.QLabel()
        logo.setPixmap(logo_image)
        logo.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(logo)

        layout.addLayout(logo_layout)

        #
        # tab widget
        #

        tab_widget = QtWidgets.QTabWidget()

        # settings
        self._settings_widget = SettingsPage()
        tab_widget.addTab(self._settings_widget, self._settings_widget.windowTitle())

        # entry point list
        self._entry_point_list_widget = EntryPointListPage()
        tab_widget.addTab(self._entry_point_list_widget, self._entry_point_list_widget.windowTitle())

        # exported function list
        self._exported_function_list_widget = ExportedFunctionListPage()
        tab_widget.addTab(self._exported_function_list_widget, self._exported_function_list_widget.windowTitle())

        # symbol definitions page
        self._symbol_definitions_widget = SymbolDefinitionsPage()
        tab_widget.addTab(self._symbol_definitions_widget, self._symbol_definitions_widget.windowTitle())

        # definitions and calling conventions for imported data and functions
        self._defs_and_call_conventions_widget = DefinitionsAndCallingConventionsPage()
        tab_widget.addTab(self._defs_and_call_conventions_widget, self._defs_and_call_conventions_widget.windowTitle())

        layout.addWidget(tab_widget)

    def OnClose(self, form):
        pass

class EntryPointListPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(EntryPointListPage, self).__init__(parent)

        self.setWindowTitle("Entry point list")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

    def initializeWidgets(self, layout):
        # ida functions
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel("Function list"))
        self._ida_function_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._ida_function_list)

        layout.addLayout(temp_layout)

        # arrow keys
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QPushButton("<="))
        temp_layout.addWidget(QtWidgets.QPushButton("=>"))

        layout.addLayout(temp_layout)

        # functions that will be used as entry points by mcsema
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel("McSema input"))
        self._mcsema_function_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._mcsema_function_list)

        layout.addLayout(temp_layout)

class ExportedFunctionListPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(ExportedFunctionListPage, self).__init__(parent)

        self.setWindowTitle("Exported function list")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

    def initializeWidgets(self, layout):
        # ida functions
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel("Exported function list"))
        self._ida_function_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._ida_function_list)

        layout.addLayout(temp_layout)

        # arrow keys
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QPushButton("<="))
        temp_layout.addWidget(QtWidgets.QPushButton("=>"))

        layout.addLayout(temp_layout)

        # functions that will be used as entry points by mcsema
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel("McSema input"))
        self._mcsema_function_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._mcsema_function_list)

        layout.addLayout(temp_layout)

class SymbolDefinitionsPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(SymbolDefinitionsPage, self).__init__(parent)

        self.setWindowTitle("Symbol definitions")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

    def initializeWidgets(self, layout):
        # text editor
        temp_layout = QtWidgets.QVBoxLayout()

        self._symbol_definitions = QtWidgets.QTextEdit()
        temp_layout.addWidget(self._symbol_definitions)

        layout.addLayout(temp_layout)

        # controls
        temp_layout = QtWidgets.QVBoxLayout()
        temp_layout.addWidget(QtWidgets.QPushButton("Load from file"))
        temp_layout.addWidget(QtWidgets.QPushButton("Clear"))
        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))

        layout.addLayout(temp_layout)

class DefinitionsAndCallingConventionsPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(DefinitionsAndCallingConventionsPage, self).__init__(parent)

        self.setWindowTitle("Definitions and calling conventions")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

    def initializeWidgets(self, layout):
        # text editor
        temp_layout = QtWidgets.QVBoxLayout()

        self._definitions = QtWidgets.QTextEdit()
        temp_layout.addWidget(self._definitions)

        layout.addLayout(temp_layout)

        # controls
        temp_layout = QtWidgets.QVBoxLayout()
        temp_layout.addWidget(QtWidgets.QPushButton("Load from file"))
        temp_layout.addWidget(QtWidgets.QPushButton("Clear"))
        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))

        layout.addLayout(temp_layout)

class SettingsPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(SettingsPage, self).__init__(parent)

        self.setWindowTitle("Settings")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

        self.detectSettings()

    def initializeWidgets(self, layout):
        #
        # settings
        #

        settings_layout = QtWidgets.QFormLayout()

        # architecture
        self._architecture = QtWidgets.QComboBox()
        self._architecture.addItem("amd64")
        self._architecture.addItem("x86")
        settings_layout.addRow("Architecture", self._architecture)

        # operating system
        self._operating_system = QtWidgets.QComboBox()
        self._operating_system.addItem("linux")
        self._operating_system.addItem("windows")
        settings_layout.addRow("Operating system", self._operating_system)

        layout.addLayout(settings_layout)

        #
        # options
        #

        options_layout = QtWidgets.QVBoxLayout()

        self._pie_mode = QtWidgets.QCheckBox("PIE mode")
        options_layout.addWidget(self._pie_mode)

        self._generate_export_stubs = QtWidgets.QCheckBox("Generate export stubs")
        options_layout.addWidget(self._generate_export_stubs)

        self._exports_are_apis = QtWidgets.QCheckBox("Exports are APIs")
        options_layout.addWidget(self._exports_are_apis)

        options_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding))
        layout.addLayout(options_layout)

    def detectSettings(self):
        pass

logo_image_base64 = """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"""

main_window = MainWindow()
main_window.Show("McSema")
