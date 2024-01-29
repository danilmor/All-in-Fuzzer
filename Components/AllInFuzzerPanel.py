from javax.swing import (JScrollPane, JTable, JPanel, JTextField, JLabel,
                         JTabbedPane, JComboBox, table, BorderFactory,
                         GroupLayout, LayoutStyle, JFrame, JTextArea)

from burp import IMessageEditor, IBurpExtenderCallbacks
from java.awt import Color
from java.lang import Short

from IssueTable import IssueTable

class AllInFuzzerPanel(JFrame):

    # mostly converted generated code
    def __init__(self, window_title, callbacks):
        self.jScrollPane1 = JScrollPane()
        self.jPanel1 = JPanel()
        self.labelComponent = JLabel()
        self.textComponent = JTextField()
        self.labelPayload = JLabel()
        self.textPayload = JTextField()
        self.labelStatusCode = JLabel()
        self.textStatusCode = JTextField()
        self.labelLength = JLabel()
        self.labelHeaderCount = JLabel()
        self.textLength = JTextField()
        self.textHeaderCount = JTextField()
        self.tabIssue = JTabbedPane()
        self.panelRequest = callbacks.createMessageEditor(None, False)
        self.panelResponse = callbacks.createMessageEditor(None, False)
        self.table = IssueTable()
        self.table.mainPanel = self
        self.window_title = window_title
        self.setTitle(window_title)
        self.payload_count = 0
        self.payload_progress = 0
        # wrap the table in a scrollpane
        self.jScrollPane1.setViewportView(self.table)

        # top panel containing the table

        self.jPanel1.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)))

        # create the labels and textfields
        self.labelComponent.text = "Component"
        self.textComponent.text = ""
        self.textComponent.editable = False
        self.textComponent.setBackground(Color.LIGHT_GRAY)

        self.labelPayload.text = "Payload"
        self.textPayload.text = ""
        self.textPayload.editable = False
        self.textPayload.setBackground(Color.LIGHT_GRAY)

        self.labelStatusCode.text = "Status code"
        self.textStatusCode.text = ""
        self.textStatusCode.editable = False
        self.textStatusCode.setBackground(Color.LIGHT_GRAY)

        self.labelLength.text = "Length"
        self.textLength.text = ""
        self.textLength.editable = False
        self.textLength.setBackground(Color.LIGHT_GRAY)

        self.labelHeaderCount.text = "Header count"
        self.textHeaderCount.text = ""
        self.textHeaderCount.editable = False
        self.textHeaderCount.setBackground(Color.LIGHT_GRAY)

        # request tab
        self.panelRequest.setMessage("", True)
        self.tabIssue.addTab("Request", self.panelRequest.getComponent())

        # response tab
        self.panelResponse.setMessage("", False)
        self.tabIssue.addTab("Response", self.panelResponse.getComponent())



        jPanel1Layout = GroupLayout(self.jPanel1)
        self.jPanel1.setLayout(jPanel1Layout)
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                          .addContainerGap()
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                              .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                                        .addComponent(self.labelLength)
                                                        .addComponent(self.labelStatusCode)
                                                        .addComponent(self.labelComponent))
                                              .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                              .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                        .addComponent(self.textComponent)
                                                        .addGroup(jPanel1Layout.createSequentialGroup()
                                                                  .addComponent(self.textStatusCode, GroupLayout.PREFERRED_SIZE, 98, GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(0, 0, Short.MAX_VALUE))
                                                        .addGroup(jPanel1Layout.createSequentialGroup()
                                                                  .addComponent(self.textLength, GroupLayout.PREFERRED_SIZE, 330, GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(18, 18, 18)
                                                                  .addComponent(self.labelHeaderCount)
                                                                  .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                                  .addComponent(self.textHeaderCount))))
                                    .addComponent(self.tabIssue))
                          .addContainerGap())
        )

        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                          .addContainerGap()
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(self.labelComponent)
                                    .addComponent(self.textComponent, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                          .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(self.labelStatusCode)
                                    .addComponent(self.textStatusCode, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                          .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(self.labelLength)
                                    .addComponent(self.labelHeaderCount)
                                    .addComponent(self.textLength, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(self.textHeaderCount, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                          .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                          .addComponent(self.tabIssue)
                          .addContainerGap())
        )

        # create the main panel
        self.panel = self.getContentPane()
        layout = GroupLayout(self.getContentPane())
        self.panel.setLayout(layout)
        layout.setAutoCreateGaps(True)

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                          .addContainerGap()
                          .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(self.jPanel1, 1000, GroupLayout.DEFAULT_SIZE, 1000)
                                    .addComponent(self.jScrollPane1))
                          .addContainerGap())
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                          .addContainerGap()
                          .addComponent(self.jScrollPane1)
                          .addGap(18, 18, 18)
                          .addComponent(self.jPanel1, 800, GroupLayout.DEFAULT_SIZE, 800)
                          .addContainerGap())
        )

        self.pack()

    def incProgress(self):
        self.payload_progress += 1
        self.setTitle("{} | Progress: {}/{}".format(self.window_title, self.payload_progress, self.payload_count))

    def setWorkDone(self):
        self.setTitle("{} | Progress: Done".format(self.window_title))
