import sys
import os
import json
from threading import Thread, Event, Lock
from time import sleep

from burp import IBurpExtender, ITab, IContextMenuFactory, IRequestInfo
from javax.swing import JMenuItem
from java.awt.event import WindowAdapter
from java.util.concurrent import Executors, Callable

from Components.AllInFuzzerUtils import AllInFuzzerUtils
from Components.AllInFuzzerTab import AllInFuzzerTab
from Components.AllInFuzzerPanel import AllInFuzzerPanel
from Components.PayloadGenerator import PayloadGenerator
from Components.Issue import Issue


EXTENSION_NAME = "All-In Fuzzer"
MENU_ITEM_FUZZ_PARAMS = "FUZZ params"
MENU_ITEM_FUZZ_HEADERS = "FUZZ headers"
MENU_ITEM_FUZZ_BODY = "FUZZ body (json)"


class Task(Callable):
    def __init__(self, function, *args):
        self.function = function
        self.args = args

    def call(self):
        return self.function(*self.args)


class CancellationWindowAdapter(WindowAdapter):
    def __init__(self, cancellation_token):
        self.cancellation_token = cancellation_token

    def windowClosing(self, event):
        self.cancellation_token.set()


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.setExtensionName(EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.utils = AllInFuzzerUtils(self.helpers)

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        print "Successfully loaded " + EXTENSION_NAME

    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return AllInFuzzerTab().getContentPane()

    def createMenuItems(self, _invocation):
        self.invocation = _invocation
        self.menuList = []
        self.menuItem1 = JMenuItem(MENU_ITEM_FUZZ_PARAMS, actionPerformed=self.menu_item_click)
        self.menuItem2 = JMenuItem(MENU_ITEM_FUZZ_HEADERS, actionPerformed=self.menu_item_click)
        self.menuItem3 = JMenuItem(MENU_ITEM_FUZZ_BODY, actionPerformed=self.menu_item_click)
        self.menuList.append(self.menuItem1)
        self.menuList.append(self.menuItem2)
        self.menuList.append(self.menuItem3)
        return self.menuList

    def menu_item_click(self, event):
        cancellation_token = Event()
        panel = self.show_ui(event.getActionCommand())
        panel.addWindowListener(CancellationWindowAdapter(cancellation_token))
        selected_messages = self.invocation.getSelectedMessages()

        for message in selected_messages:
            if event.getActionCommand() == MENU_ITEM_FUZZ_PARAMS:
                Thread(target=self.fuzz_params, args=(message, panel, cancellation_token)).start()
            elif event.getActionCommand() == MENU_ITEM_FUZZ_HEADERS:
                Thread(target=self.fuzz_headers, args=(message, panel, cancellation_token)).start()
            elif event.getActionCommand() == MENU_ITEM_FUZZ_BODY:
                Thread(target=self.fuzz_body, args=(message, panel, cancellation_token)).start()

    def show_ui(self, panel_name):
        panel = AllInFuzzerPanel("{}: {}".format(EXTENSION_NAME, panel_name), self.callbacks)
        panel.show()
        return panel

    def make_request(self, http_service, request, panel, menu_item, original_payload, new_payload, delay, cancellation_token):
        try:
            if cancellation_token.is_set():
                return
            sleep(delay/1000.0)
            new_request = self.utils.safe_bytes_to_string(request).replace(original_payload, new_payload.decode('utf-8'))
            http_request_response = self.callbacks.makeHttpRequest(http_service, new_request)
            issue = self.create_issue(http_request_response, menu_item)
            panel.table.addRow(issue)
            panel.incProgress()
        except Exception as e:
            panel.setTitle("Error: {}".format(e.__class__.__name__))
            raise e

    def create_issue(self, http_request_response, fuzz_item):
        return Issue(
            http_request_response.getRequest(),
            http_request_response.getResponse(),
            http_request_response.getHttpService().getHost(),
            fuzz_item,
            self.helpers.analyzeResponse(http_request_response.getResponse()).getStatusCode(),
            len(http_request_response.getResponse()),
            self.helpers.analyzeResponse(http_request_response.getResponse()).getBodyOffset(),
            len(self.helpers.analyzeResponse(http_request_response.getResponse()).getHeaders()))

    def fuzz_params(self, selected_messages, panel, cancellation_token):
        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        url = request_info.getUrl()
        payloads = PayloadGenerator(self.utils.get_wordlists_dir()).params_payloads(url.toString())
        panel.payload_count = len(payloads)
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        for new_query in payloads:
            task = Task(
                self.make_request,
                http_service, request, panel, MENU_ITEM_FUZZ_PARAMS, url.getQuery(), new_query, self.utils.get_settings()["delay"], cancellation_token)
            executor.submit(task)

        executor.shutdown()

    def fuzz_headers(self, selected_messages, panel, cancellation_token):
        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        headers = request_info.getHeaders()
        payloads = PayloadGenerator(self.utils.get_wordlists_dir()).headers_payloads(headers)
        panel.payload_count = len(payloads)
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        for old_header, new_header in payloads:
            task = Task(self.make_request, http_service, request, panel, MENU_ITEM_FUZZ_PARAMS, old_header, new_header, self.utils.get_settings()["delay"], cancellation_token)
            executor.submit(task)

        executor.shutdown()

    def fuzz_body(self, selected_messages, panel, cancellation_token):
        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        content_type = request_info.getContentType()
        body = self.utils.safe_bytes_to_string(request[request_info.getBodyOffset():])
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        # send big content length
        panel.payload_count += 1
        new_request = self.utils.update_content_length(request, "!" * 99999)
        task = Task(self.make_request, http_service, new_request, panel, MENU_ITEM_FUZZ_BODY, body, "empty", self.utils.get_settings()["delay"], cancellation_token)
        executor.submit(task)

        # json 
        if content_type == IRequestInfo.CONTENT_TYPE_JSON:
            payloads = PayloadGenerator(self.utils.get_wordlists_dir()).json_payloads(body)
            panel.payload_count = len(payloads)
            for payload in payloads:
                new_request = self.utils.update_content_length(request, payload)
                task = Task(self.make_request, http_service, new_request, panel, MENU_ITEM_FUZZ_BODY, body, payload, self.utils.get_settings()["delay"], cancellation_token)
                executor.submit(task)



        executor.shutdown()
