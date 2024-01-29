import json
import os
from javax.swing import (JScrollPane, JTable, JPanel, JTextField, JLabel,
                         JTabbedPane, JComboBox, table, BorderFactory,
                         GroupLayout, LayoutStyle, JFrame, JTextArea, JButton)
from java.awt import Font
from java.lang import Short


class AllInFuzzerTab(JFrame):
    def __init__(self):
        self.jLabel3 = JLabel()
        self.jLabel1 = JLabel()
        self.jTextFieldThreads = JTextField()
        self.jLabel2 = JLabel()
        self.jTextFieldDelay = JTextField()
        self.jButton1 = JButton("Save", actionPerformed=self.settings_save_action)

        self.jLabel3.setFont(Font("Segoe UI", 0, 24))
        self.jLabel3.setText("Settings")

        self.jLabel1.setText("Number of threads")

        self.jTextFieldThreads.setText("1")

        self.jLabel2.setText("Delay ms between requests in threads")

        self.jTextFieldDelay.setText("0")

        layout = GroupLayout(self.getContentPane())
        self.getContentPane().setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                      .addContainerGap()
                      .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(self.jLabel3, GroupLayout.PREFERRED_SIZE, 225,
                                              GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.jLabel1)
                                .addComponent(self.jLabel2)
                                .addComponent(self.jTextFieldDelay, GroupLayout.PREFERRED_SIZE,
                                              GroupLayout.DEFAULT_SIZE,
                                              GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.jTextFieldThreads, GroupLayout.PREFERRED_SIZE,
                                              GroupLayout.DEFAULT_SIZE,
                                              GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.jButton1))
                      .addContainerGap(864, Short.MAX_VALUE))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                      .addContainerGap()
                      .addComponent(self.jLabel3, GroupLayout.PREFERRED_SIZE, 39,
                                    GroupLayout.PREFERRED_SIZE)
                      .addGap(18, 18, 18)
                      .addComponent(self.jLabel1)
                      .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                      .addComponent(self.jTextFieldThreads, GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                      .addGap(12, 12, 12)
                      .addComponent(self.jLabel2)
                      .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                      .addComponent(self.jTextFieldDelay, GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                      .addGap(26, 26, 26)
                      .addComponent(self.jButton1)
                      .addContainerGap(527, Short.MAX_VALUE))
        )

        self.settings_load()
        self.pack()

    def get_components_dir(self):
        return "{}/Components".format(os.getcwd())

    def settings_save_action(self, event):
        settings = {"threads": int(self.jTextFieldThreads.getText()), "delay": int(self.jTextFieldDelay.getText())}
        with open('{}/settings.json'.format(self.get_components_dir()), 'w') as f:
            json.dump(settings, f)

    def settings_load(self):
        with open('{}/settings.json'.format(self.get_components_dir()), 'r') as f:
            settings = json.loads(f.readline())
            self.jTextFieldThreads.setText(str(settings["threads"]))
            self.jTextFieldDelay.setText(str(settings["delay"]))