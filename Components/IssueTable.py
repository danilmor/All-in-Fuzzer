from threading import Lock

from javax.swing import JTable, ListSelectionModel
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.awt.event import MouseListener, KeyListener
import java.lang

from Components.Issue import Issue


class IssueTableModel(AbstractTableModel):
    columnNames = ["#", "Component", "Status code", "Response length", "Header length", "Header count"]
    columnClasses = [java.lang.Integer, java.lang.String, java.lang.Integer,
                     java.lang.Integer, java.lang.Integer, java.lang.Integer]

    def __init__(self):
        self.issues = list()

    def getColumnCount(self):
        # type: () -> int
        return len(self.columnNames)

    def getRowCount(self):
        # type: () -> int
        return len(self.issues)

    def getValueAt(self, row, column):
        # type: (int, int) -> object
        """Returns the value at the specified row and column."""
        if row < self.getRowCount() and column < self.getColumnCount():
            issue = self.issues[row]
            if column == 0:
                return issue.index
            if column == 1:
                return issue.component
            if column == 2:
                return issue.status_code
            if column == 3:
                return issue.response_length - issue.body_offset
            if column == 4:
                return issue.body_offset
            if column == 5:
                return issue.header_count
            return None


    def getColumnName(self, index):
        # type: (int) -> str
        """Returns the name of the table column."""
        if 0 <= index < self.getColumnCount():
            return self.columnNames[index]
        else:
            return "Invalid Column Index: " + str(index)

    def getColumnClass(self, index):
        # type: (int) -> object
        """Returns the class of the table column."""
        if 0 <= index < len(self.columnClasses):
            return self.columnClasses[index]
        return java.lang.Object

    def isCellEditable(self, row, column):
        # type: (int, int) -> bool
        """Returns True if cells are editable."""
        return False

    def getIssue(self, index):
        # type: (int) -> Issue
        """Returns the issue object at index."""
        if 0 <= index < len(self.issues):
            return self.issues[index]
        return self.issues[0]

    def addIssue(self, issue):
        # type: (Issue) -> ()
        """Adds the issue to the list of issues."""
        self.issues.append(issue)
        self.fireTableDataChanged()

    def removeIssue(self, index):
        # type: (int) -> ()
        """Removes the issue at index from the list of issues."""
        if 0 <= index < len(self.issues):
            del self.issues[index]
            self.fireTableDataChanged()


class IssueTableKeyListener(KeyListener):
    def keyPressed(self, event):
        IssueTableMouseListener().mouseClicked(event)

    def keyReleased(self, event):
        IssueTableMouseListener().mouseClicked(event)

    def keyTyped(self, event):
        pass


class IssueTableMouseListener(MouseListener):
    def getClickedIndex(self, event):
        """Returns the value of the first column of the table row that was
        clicked. This is not the same as the row index because the table
        can be sorted."""
        tbl = event.getSource()
        row = tbl.convertRowIndexToModel(tbl.getSelectedRow())
        return tbl.getValueAt(row, 0)

    def getClickedRow(self, event):
        """Returns the complete clicked row."""
        tbl = event.getSource()
        mdl = tbl.getModel()
        row = tbl.convertRowIndexToModel(tbl.getSelectedRow())
        assert isinstance(mdl, IssueTableModel)
        return mdl.getIssue(row)

    def mousePressed(self, event):
        # print "mouse pressed", event.getClickCount()
        pass

    def mouseReleased(self, event):
        # print "mouse released", event.getClickCount()
        pass

    def mouseClicked(self, event):
        row_data = self.getClickedRow(event)
        assert isinstance(row_data, Issue)

        from Components.AllInFuzzerPanel import AllInFuzzerPanel
        allInFuzzerPanel = event.getSource().mainPanel
        assert isinstance(allInFuzzerPanel, AllInFuzzerPanel)
        allInFuzzerPanel.textComponent.text = row_data.component
        allInFuzzerPanel.textStatusCode.text = str(row_data.status_code)
        allInFuzzerPanel.textLength.text = str(row_data.response_length)
        allInFuzzerPanel.textHeaderCount.text = str(row_data.header_count)
        allInFuzzerPanel.panelRequest.setMessage(row_data.getRequest(), True)
        allInFuzzerPanel.panelResponse.setMessage(row_data.getResponse(), False)


    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass


class IssueTable(JTable):
    def __init__(self):
        self.model = IssueTableModel()
        self.mainPanel = None
        self.setModel(self.model)
        self.setAutoCreateRowSorter(True)
        self.getTableHeader().setReorderingAllowed(False)
        self.addMouseListener(IssueTableMouseListener())
        self.addKeyListener(IssueTableKeyListener())
        self.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.lock = Lock()
        for i in range(0, self.model.getColumnCount()):
            self.getColumnModel().getColumn(i).setCellRenderer(DefaultTableCellRenderer())

    def addRow(self, issue):
        self.lock.acquire()
        try:
            issues_count = len(self.model.issues)
            issue.index = issues_count + 1
            self.getModel().addIssue(issue)
            # self.resizeColumnWidth()
        finally:
            self.lock.release()


    def resizeColumnWidth(self):
        column_model = self.getColumnModel()
        for column in range(0, self.getColumnCount()):
            width = 15
            for row in range(0, self.getRowCount()):
                renderer = self.getCellRenderer(row, column)
                comp = self.prepareRenderer(renderer, row, column)
                width = max(comp.getPreferredSize().width +1, width)
            if width > 300:
                width = 300
            column_model.getColumn(column).setPreferredWidth(width)
