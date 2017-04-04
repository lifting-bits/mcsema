from idaapi import PluginForm
import idautils
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

        button = QtWidgets.QPushButton("Refresh")
        button.clicked.connect(self.onRefreshButtonClick)
        temp_layout.addWidget(button)

        button = QtWidgets.QPushButton("Execute")
        button.clicked.connect(self.onExecuteButtonClick)
        temp_layout.addWidget(button)

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

    def onRefreshButtonClick(self):
        self._settings_widget.refresh()
        self._entry_point_list_widget.refresh()
        self._exported_function_list_widget.refresh()
        self._symbol_definitions_widget.refresh()
        self._defs_and_call_conventions_widget.refresh()

    def onExecuteButtonClick(self):
        print "Not yet implemented!"

class EntryPointListPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(EntryPointListPage, self).__init__(parent)

        self.setWindowTitle("Entry point list")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

        self.refresh()

    def initializeWidgets(self, layout):
        # ida functions
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel("Function list"))
        self._ida_function_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._ida_function_list)

        layout.addLayout(temp_layout)

        # controls
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))

        add_function_button = QtWidgets.QPushButton(">")
        temp_layout.addWidget(add_function_button)

        remove_function_button = QtWidgets.QPushButton("<")
        temp_layout.addWidget(remove_function_button)

        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))

        add_all_functions_button = QtWidgets.QPushButton("Add all")
        temp_layout.addWidget(add_all_functions_button)

        clear_mcsema_function_list_button = QtWidgets.QPushButton("Clear")
        temp_layout.addWidget(clear_mcsema_function_list_button)

        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))

        layout.addLayout(temp_layout)

        # functions that will be used as entry points by mcsema
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel("McSema input"))
        self._mcsema_function_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._mcsema_function_list)

        # connections
        clear_mcsema_function_list_button.clicked.connect(self._mcsema_function_list.clear)
        add_function_button.clicked.connect(self.onAddFunctionButtonClick)
        remove_function_button.clicked.connect(self.onRemoveFunctionButtonClick)
        add_all_functions_button.clicked.connect(self.onAddAllFunctionsButtonClick)

        layout.addLayout(temp_layout)

    def refresh(self):
        # make a list of the exported functions so that we can filter them out
        exported_function_address_list = [ ]
        for exported_function_tuple in idautils.Entries():
            exported_function_address_list.append(exported_function_tuple[2])

        # refresh the ida function list
        function_address_list = Functions(SegStart(BeginEA()), SegEnd(BeginEA()))

        function_name_list = [ ]
        for function_address in function_address_list:
            if function_address in exported_function_address_list:
                continue

            function_name = GetFunctionName(function_address)
            function_flags = GetFunctionAttr(function_address, FUNCATTR_FLAGS)

            function_name_list.append(function_name)

        self._ida_function_list.clear()
        for function_name in function_name_list:
            self._ida_function_list.addItem(function_name)

        # update the selected function list
        selected_function_list = [ ]
        for i in range(0, self._mcsema_function_list.count()):
            selected_function_name = self._mcsema_function_list.item(i).text()
            if selected_function_name in function_name_list:
                selected_function_list.append(selected_function_name)

        self._mcsema_function_list.clear()
        for selected_function_name in selected_function_list:
            self._mcsema_function_list.addItem(selected_function_name)

    def onAddFunctionButtonClick(self):
        selected_item = self._ida_function_list.currentItem()
        if selected_item == None:
            return

        function_name = selected_item.text()

        search_result = self._mcsema_function_list.findItems(function_name, QtCore.Qt.MatchExactly)
        if len(search_result) != 0:
            return

        self._mcsema_function_list.addItem(function_name)

    def onRemoveFunctionButtonClick(self):
        selected_row_index = self._mcsema_function_list.currentRow()
        if selected_row_index == -1:
            return

        self._mcsema_function_list.takeItem(selected_row_index)

    def onAddAllFunctionsButtonClick(self):
        self._mcsema_function_list.clear()

        for i in range(0, self._ida_function_list.count()):
            function_name = self._ida_function_list.item(i).text()
            self._mcsema_function_list.addItem(function_name)

class ExportedFunctionListPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(ExportedFunctionListPage, self).__init__(parent)

        self.setWindowTitle("Exported function list")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

        self.refresh()

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

    def refresh(self):
        print "ExportedFunctionListPage refresh"

class SymbolDefinitionsPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(SymbolDefinitionsPage, self).__init__(parent)

        self.setWindowTitle("Symbol definitions")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

        self.refresh()

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

    def refresh(self):
        print "SymbolDefinitionsPage refresh"

class DefinitionsAndCallingConventionsPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(DefinitionsAndCallingConventionsPage, self).__init__(parent)

        self.setWindowTitle("Definitions and calling conventions")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

        self.refresh()

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

    def refresh(self):
        print "DefinitionsAndCallingConventionsPage refresh"

class SettingsPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(SettingsPage, self).__init__(parent)

        self.setWindowTitle("Settings")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

        self.refresh()

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

    def refresh(self):
        if idaapi.get_inf_structure().procName != 'metapc':
            PrintMessage("Unsupported architecture")
            return

        if idaapi.get_inf_structure().is_64bit():
            self._architecture.setCurrentIndex(0)
            PrintMessage("Architecture: AMD64")

        elif idaapi.get_inf_structure().is_32bit():
            self._architecture.setCurrentIndex(1)
            PrintMessage("Architecture: x86")

        else:
            PrintMessage("Unsupported architecture")
            return

        # attempt to guess the file format
        if "ELF" in idaapi.get_file_type_name():
            self._operating_system.setCurrentIndex(0)
            PrintMessage("Operating system: Linux")

        elif "Portable executable" in idaapi.get_file_type_name():
            self._operating_system.setCurrentIndex(1)
            PrintMessage("Operating system: Windows")

        else:
            PrintMessage("Unsupported image type! Only PE and ELF executables are supported!")

logo_image_base64 = """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
ICAQWNELQ0H4enIxyrAAAAAASUVORK5CYII="""

def PrintMessage(message):
    print 'McSema - ' + message

main_window = MainWindow()
main_window.Show("McSema")
