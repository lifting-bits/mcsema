from idaapi import PluginForm
import idautils

from PyQt5 import QtCore, QtGui, QtWidgets

import sip
import base64
import time
import datetime
import StringIO

from get_cfg import *

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

        button = QtWidgets.QPushButton("Export")
        button.clicked.connect(self.onExportButtonClick)
        temp_layout.addWidget(button)

        layout.addLayout(temp_layout)

        # attempt to dock us to the right side of the disassembly
        # todo: doesn't look like we can use self.windowTitle
        idaapi.set_dock_pos("McSema", "IDA View-A", idaapi.DP_RIGHT)

    def initializeWidgets(self, layout):
        #
        # logo
        #

        # automatically select the most suitable logo variation depending on the user theme
        background_color = QtWidgets.QWidget().palette().color(QtGui.QPalette.Background)

        gray = background_color.red() * 0.299 + background_color.green() * 0.587 + background_color.blue() * 0.114
        if gray <= 186:
            logo_image_base64 = dark_mode_logo_base64
            link_color = "white"
        else:
            logo_image_base64 = bright_mode_logo_base64
            link_color = "red"

        logo_layout = QtWidgets.QHBoxLayout()

        logo_image = QtGui.QPixmap()
        logo_image.loadFromData(base64.b64decode(logo_image_base64))

        logo = QtWidgets.QLabel()
        logo.setPixmap(logo_image)
        logo.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(logo)

        about_text = QtWidgets.QLabel()
        about_text.setTextFormat(QtCore.Qt.RichText)
        about_text.setText("<p>McSema<br/>x86 to machine code translation framework<br/><br/><a href=\"https://trailofbits.com\" style=\"color: {};\">https://trailofbits.com</a><br/><a href=\"https://github.com/trailofbits/mcsema\" style=\"color: {};\">https://github.com/trailofbits/mcsema</a></p>".format(link_color, link_color))
        logo_layout.addWidget(about_text)

        layout.addLayout(logo_layout)

        #
        # tab widget
        #

        tab_widget = QtWidgets.QTabWidget()

        # settings
        self._settings_page = SettingsPage()
        tab_widget.addTab(self._settings_page, self._settings_page.windowTitle())

        # function list
        self._function_list_page = FunctionListPage()
        tab_widget.addTab(self._function_list_page, self._function_list_page.windowTitle())

        # exported function list
        self._export_list_page = ExportListPage()
        tab_widget.addTab(self._export_list_page, self._export_list_page.windowTitle())

        # standard definitions page
        self._standard_definitions_page = StandardDefinitionsPage()
        tab_widget.addTab(self._standard_definitions_page, self._standard_definitions_page.windowTitle())

        # symbol definitions
        self._symbol_definitions_page = SymbolDefinitionsPage()
        tab_widget.addTab(self._symbol_definitions_page, self._symbol_definitions_page.windowTitle())

        layout.addWidget(tab_widget)

    def OnClose(self, form):
        pass

    def onRefreshButtonClick(self):
        self._settings_page.refresh()
        self._function_list_page.refresh()
        self._export_list_page.refresh()

    def onExportButtonClick(self):
        architecture = self._settings_page.architecture()
        operating_system = self._settings_page.operatingSystem()

        pie_mode = self._settings_page.pieModeEnabled()
        generate_export_stubs = self._settings_page.generateExportStubsEnabled()
        exports_are_apis = self._settings_page.exportsAreApisEnabled()

        function_list = self._function_list_page.getSelectedFunctionList()
        export_list = self._export_list_page.getSelectedFunctionList()

        symbol_definitions = self._symbol_definitions_page.getSymbolDefinitions()
        str_helper = StringIO.StringIO()
        str_helper.write(symbol_definitions)
        symbol_definition_lines = str_helper.readlines()

        standard_definition_file_list = self._standard_definitions_page.getStandardDefinitionFileList()

        output_file_path = idc.GetIdbPath();
        output_file_path += ".mcd"

        timestamp = datetime.datetime.now()
        PrintMessage("=> " + str(timestamp))
        PrintMessage("Architecture: " + architecture)
        PrintMessage("Operating_system: " + operating_system)
        PrintMessage("PIE mode: " + str(pie_mode))
        PrintMessage("Generate export stubs: " + str(generate_export_stubs))
        PrintMessage("Exports are APIs: " + str(exports_are_apis))
        PrintMessage("Selected functions: " + str(len(function_list)))
        PrintMessage("Selected exports: " + str(len(export_list)))

        try:
            output_file = open(output_file_path, "w")
            debug_stream = StringIO.StringIO()

            if not export_cfg(debug_stream, architecture, pie_mode, operating_system, standard_definition_file_list, export_list, function_list, symbol_definition_lines, output_file, generate_export_stubs, exports_are_apis):
                PrintMessage("Failed to generate the control flow graph information. Debug output follows")
                PrintMessage("===\n" + debug_stream.getvalue())
            else:
                PrintMessage("Control flow information saved to " + output_file_path)

            debug_stream.close()

        except:
            print "Failed to create the output file"

class GenericFunctionListPage(QtWidgets.QWidget):
    def __init__(self, title, get_function_list_callback, parent = None):
        super(GenericFunctionListPage, self).__init__(parent)

        self.setWindowTitle(title)
        self._get_function_list_callback = get_function_list_callback

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)
        
        self.refresh()

    def initializeWidgets(self, layout):
        # ida functions
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel(self.windowTitle()))
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

        clear_selected_function_list_button = QtWidgets.QPushButton("Clear")
        temp_layout.addWidget(clear_selected_function_list_button)

        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))

        layout.addLayout(temp_layout)

        # functions that will be used as entry points by mcsema
        temp_layout = QtWidgets.QVBoxLayout()

        temp_layout.addWidget(QtWidgets.QLabel("Selected functions"))
        self._selected_function_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._selected_function_list)

        # connections
        clear_selected_function_list_button.clicked.connect(self._selected_function_list.clear)
        add_function_button.clicked.connect(self.onAddFunctionButtonClick)
        remove_function_button.clicked.connect(self.onRemoveFunctionButtonClick)
        add_all_functions_button.clicked.connect(self.onAddAllFunctionsButtonClick)
        self._ida_function_list.itemDoubleClicked.connect(self.onAddFunctionButtonClick)
        self._selected_function_list.itemDoubleClicked.connect(self.onRemoveFunctionButtonClick)

        layout.addLayout(temp_layout)

    def refresh(self):
        function_name_list = self._get_function_list_callback()

        self._ida_function_list.clear()
        for function_name in function_name_list:
            self._ida_function_list.addItem(function_name)

        # update the selected function list, removing everything that has
        # vanished from the pool
        selected_function_list = [ ]
        for i in range(0, self._selected_function_list.count()):
            selected_function_name = self._selected_function_list.item(i).text()
            if selected_function_name in function_name_list:
                selected_function_list.append(selected_function_name)

        self._selected_function_list.clear()
        for selected_function_name in selected_function_list:
            self._selected_function_list.addItem(selected_function_name)

    def onAddFunctionButtonClick(self):
        selected_item = self._ida_function_list.currentItem()
        if selected_item == None:
            return

        function_name = selected_item.text()

        search_result = self._selected_function_list.findItems(function_name, QtCore.Qt.MatchExactly)
        if len(search_result) != 0:
            return

        self._selected_function_list.addItem(function_name)

    def onRemoveFunctionButtonClick(self):
        selected_row_index = self._selected_function_list.currentRow()
        if selected_row_index == -1:
            return

        self._selected_function_list.takeItem(selected_row_index)

    def onAddAllFunctionsButtonClick(self):
        self._selected_function_list.clear()

        for i in range(0, self._ida_function_list.count()):
            function_name = self._ida_function_list.item(i).text()
            self._selected_function_list.addItem(function_name)

    def getSelectedFunctionList(self):
        function_list = [ ]

        for i in range(0, self._selected_function_list.count()):
            function_name = self._selected_function_list.item(i).text()
            function_list.append(function_name)

        return function_list

class FunctionListPage(GenericFunctionListPage):
    def __init__(self, parent = None):
        super(FunctionListPage, self).__init__("Function list", FunctionListPage.GetFunctionListCallback, parent)

    @staticmethod
    def GetFunctionListCallback():
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

        return function_name_list

class ExportListPage(GenericFunctionListPage):
    def __init__(self, parent = None):
        super(ExportListPage, self).__init__("Export list", ExportListPage.GetFunctionListCallback, parent)

    @staticmethod
    def GetFunctionListCallback():
        function_name_list = [ ]
        for exported_function_tuple in idautils.Entries():
            virtual_address = exported_function_tuple[2]
            symbol_name = exported_function_tuple[3]

            memory_flags = idc.GetFlags(virtual_address)
            if not idc.isCode(memory_flags):
                continue

            if idc.isData(memory_flags):
                continue

            function_name_list.append(symbol_name)

        return function_name_list

class StandardDefinitionsPage(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(StandardDefinitionsPage, self).__init__(parent)

        self.setWindowTitle("Standard definitions")

        main_layout = QtWidgets.QHBoxLayout()
        self.initializeWidgets(main_layout)
        self.setLayout(main_layout)

    def initializeWidgets(self, layout):
        # text editor
        temp_layout = QtWidgets.QVBoxLayout()

        self._definition_file_list = QtWidgets.QListWidget()
        temp_layout.addWidget(self._definition_file_list)

        layout.addLayout(temp_layout)

        # controls
        temp_layout = QtWidgets.QVBoxLayout()

        add_file_button = QtWidgets.QPushButton("Add file")
        temp_layout.addWidget(add_file_button)

        remove_file_button = QtWidgets.QPushButton("Remove file")
        temp_layout.addWidget(remove_file_button)

        clear_button = QtWidgets.QPushButton("Clear")
        temp_layout.addWidget(clear_button)

        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))
        layout.addLayout(temp_layout)

        # connections
        add_file_button.clicked.connect(self.onAddFileButtonClick)
        remove_file_button.clicked.connect(self.onRemoveFileButtonClick)
        clear_button.clicked.connect(self._definition_file_list.clear)
        self._definition_file_list.itemDoubleClicked.connect(self.onRemoveFileButtonClick)

    def onAddFileButtonClick(self):
        file_path = QtWidgets.QFileDialog.getOpenFileName(self, "Symbol definitions file")[0]
        if len(file_path) == 0:
            return

        self._definition_file_list.addItem(file_path)

    def onRemoveFileButtonClick(self):
        current_row = self._definition_file_list.currentRow()
        if current_row == -1:
            return

        self._definition_file_list.takeItem(current_row)

    def getStandardDefinitionFileList(self):
        file_list = [ ]

        for i in range(0, self._definition_file_list.count()):
            file_name = self._definition_file_list.item(i).text()
            file_list.append(file_name)

        return file_list

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

        self._definitions = QtWidgets.QTextEdit()
        temp_layout.addWidget(self._definitions)

        layout.addLayout(temp_layout)

        # controls
        temp_layout = QtWidgets.QVBoxLayout()

        load_button = QtWidgets.QPushButton("Load from file")
        temp_layout.addWidget(load_button)
        load_button.clicked.connect(self.onLoadButtonClick)

        clear_button = QtWidgets.QPushButton("Clear")
        temp_layout.addWidget(clear_button)
        clear_button.clicked.connect(self._definitions.clear)

        temp_layout.addSpacerItem(QtWidgets.QSpacerItem(1, 1, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding))

        layout.addLayout(temp_layout)

    def onLoadButtonClick(self):
        input_file_path = QtWidgets.QFileDialog.getOpenFileName(self, "Symbol definitions file")[0]
        if len(input_file_path) == 0:
            return

        input_file = open(input_file_path, "r")
        input_file_content = input_file.read()
        self._definitions.setText(input_file_content)

        input_file.close()

    def getSymbolDefinitions(self):
        return self._definitions.toPlainText()

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
        elif idaapi.get_inf_structure().is_32bit():
            self._architecture.setCurrentIndex(1)
        else:
            PrintMessage("Unsupported architecture")
            return

        # attempt to guess the file format
        if "ELF" in idaapi.get_file_type_name():
            self._operating_system.setCurrentIndex(0)
        elif "Portable executable" in idaapi.get_file_type_name():
            self._operating_system.setCurrentIndex(1)
        else:
            PrintMessage("Unsupported image type! Only PE and ELF executables are supported!")

    def architecture(self):
        if self._architecture.currentIndex() == 0:
            return "amd64"
        else:
            return "x86"

    def operatingSystem(self):
        if self._operating_system.currentIndex() == 0:
            return "linux"
        else:
            return "windows"

    def pieModeEnabled(self):
        return self._pie_mode.checkState() == QtCore.Qt.Checked

    def generateExportStubsEnabled(self):
        return self._generate_export_stubs.checkState() == QtCore.Qt.Checked

    def exportsAreApisEnabled(self):
        return self._exports_are_apis.checkState() == QtCore.Qt.Checked

dark_mode_logo_base64 = """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"""

bright_mode_logo_base64 = """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
ICAQWNELQ0H4enIxyrAAAAAASUVORK5CYII="""

def PrintMessage(message):
    print 'McSema - ' + message

main_window = MainWindow()
main_window.Show("McSema")
