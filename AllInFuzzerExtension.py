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
MENU_ITEM_FUZZ_COOKIES = "FUZZ cookies"
MENU_ITEM_FUZZ_BODY_JSON = "FUZZ body (json)"
MENU_ITEM_FUZZ_BODY_URL = "FUZZ body (url)"
MENU_ITEM_FUZZ_SELECTED = "FUZZ selected"


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
        self.menuItem3 = JMenuItem(MENU_ITEM_FUZZ_COOKIES, actionPerformed=self.menu_item_click)
        self.menuItem4 = JMenuItem(MENU_ITEM_FUZZ_BODY_JSON, actionPerformed=self.menu_item_click)
        self.menuItem5 = JMenuItem(MENU_ITEM_FUZZ_BODY_URL, actionPerformed=self.menu_item_click)
        self.menuItem6 = JMenuItem(MENU_ITEM_FUZZ_SELECTED, actionPerformed=self.menu_item_click)
        self.menuList.append(self.menuItem1)
        self.menuList.append(self.menuItem2)
        self.menuList.append(self.menuItem3)
        self.menuList.append(self.menuItem4)
        self.menuList.append(self.menuItem5)
        self.menuList.append(self.menuItem6)
        return self.menuList

    def menu_item_click(self, event):
        cancellation_token = Event()
        panel = self.show_ui(event.getActionCommand())
        panel.addWindowListener(CancellationWindowAdapter(cancellation_token))
        selected_messages = self.invocation.getSelectedMessages()
        selection_bounds = self.invocation.getSelectionBounds()

        for message in selected_messages:
            if event.getActionCommand() == MENU_ITEM_FUZZ_PARAMS:
                Thread(target=self.fuzz_params, args=(message, panel, cancellation_token)).start()
            elif event.getActionCommand() == MENU_ITEM_FUZZ_HEADERS:
                Thread(target=self.fuzz_headers, args=(message, panel, cancellation_token)).start()
            elif event.getActionCommand() == MENU_ITEM_FUZZ_COOKIES:
                Thread(target=self.fuzz_cookies, args=(message, panel, cancellation_token)).start()
            elif event.getActionCommand() == MENU_ITEM_FUZZ_BODY_JSON:
                Thread(target=self.fuzz_body_json, args=(message, panel, cancellation_token)).start()
            elif event.getActionCommand() == MENU_ITEM_FUZZ_BODY_URL:
                Thread(target=self.fuzz_body_url, args=(message, panel, cancellation_token)).start()
            elif event.getActionCommand() == MENU_ITEM_FUZZ_SELECTED:
                Thread(target=self.fuzz_selected, args=(message, selection_bounds, panel, cancellation_token)).start()

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
            issue = self.create_issue(http_request_response, menu_item, new_payload)
            panel.table.addRow(issue)
            panel.incProgress()
        except Exception as e:
            panel.setTitle("Error: {}".format(e.__class__.__name__))
            raise e

    def create_issue(self, http_request_response, menu_item, payload):
        return Issue(
            http_request_response.getRequest(),
            http_request_response.getResponse(),
            http_request_response.getHttpService().getHost(),
            menu_item,
            payload,
            self.helpers.analyzeResponse(http_request_response.getResponse()).getStatusCode(),
            len(http_request_response.getResponse()),
            self.helpers.analyzeResponse(http_request_response.getResponse()).getBodyOffset(),
            len(self.helpers.analyzeResponse(http_request_response.getResponse()).getHeaders()))

    def fuzz_params(self, selected_messages, panel, cancellation_token):
        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        url = request_info.getUrl()
        payloads = PayloadGenerator(self.utils.get_wordlists_dir()).params_payloads_from_url(url.toString())
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
        payloads = PayloadGenerator(self.utils.get_wordlists_dir()).headers_payloads(headers, skip_headers=["Cookie"])
        panel.payload_count = len(payloads)
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        for old_header, new_header in payloads:
            task = Task(self.make_request, http_service, request, panel, MENU_ITEM_FUZZ_HEADERS, old_header, new_header, self.utils.get_settings()["delay"], cancellation_token)
            executor.submit(task)

        executor.shutdown()

    def fuzz_cookies(self, selected_messages, panel, cancellation_token):
        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        headers = request_info.getHeaders()
        payloads = PayloadGenerator(self.utils.get_wordlists_dir()).cookies_payloads(headers)
        panel.payload_count = len(payloads)
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        for old_cookies, new_cookies in payloads:
            task = Task(self.make_request, http_service, request, panel, MENU_ITEM_FUZZ_COOKIES, old_cookies, new_cookies, self.utils.get_settings()["delay"], cancellation_token)
            executor.submit(task)

        executor.shutdown()

    def fuzz_body_json(self, selected_messages, panel, cancellation_token):
        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        content_type = request_info.getContentType()
        body = self.utils.safe_bytes_to_string(request[request_info.getBodyOffset():])
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        # Send big content length first. Because it's a long time to wait for an answer
        panel.payload_count += 1
        new_request = self.utils.update_content_length(request, "!" * 99999)
        task = Task(self.make_request, http_service, new_request, panel, MENU_ITEM_FUZZ_BODY_JSON, body, "empty", self.utils.get_settings()["delay"], cancellation_token)
        executor.submit(task)

        # json 
        if content_type == IRequestInfo.CONTENT_TYPE_JSON:
            payloads = PayloadGenerator(self.utils.get_wordlists_dir()).json_payloads(body)
            panel.payload_count = len(payloads)
            for payload in payloads:
                new_request = self.utils.update_content_length(request, payload)
                task = Task(
                    self.make_request,
                    http_service, new_request, panel, MENU_ITEM_FUZZ_BODY_JSON, body, payload, self.utils.get_settings()["delay"], cancellation_token)
                executor.submit(task)

        executor.shutdown()

    def fuzz_body_url(self, selected_messages, panel, cancellation_token):
        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        body = self.utils.safe_bytes_to_string(request[request_info.getBodyOffset():])
        payloads = PayloadGenerator(self.utils.get_wordlists_dir()).params_payloads_from_query(body)
        panel.payload_count = len(payloads)
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        for payload in payloads:
            new_request = self.utils.update_content_length(request, payload)
            task = Task(
                self.make_request,
                http_service, new_request, panel, MENU_ITEM_FUZZ_BODY_URL, body, payload, self.utils.get_settings()["delay"], cancellation_token)
            executor.submit(task)

        executor.shutdown()

    def fuzz_selected(self, selected_messages, selection_bounds, panel, cancellation_token):

        request = selected_messages.getRequest()
        http_service = selected_messages.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        selected = self.utils.safe_bytes_to_string(request[selection_bounds[0]:selection_bounds[1]])
        body_offset = request_info.getBodyOffset()
        payloads = PayloadGenerator(self.utils.get_wordlists_dir()).selected_payloads(selected)
        panel.payload_count = len(payloads)
        executor = Executors.newFixedThreadPool(self.utils.get_settings()["threads"])

        # selected in the body
        if selection_bounds[0] >= body_offset:
            body = self.utils.safe_bytes_to_string(request[body_offset:])
            for payload in payloads:
                body_array = list(body)
                body_array[selection_bounds[0] - body_offset: selection_bounds[1] - body_offset] = list(payload)
                new_body = ''.join(body_array)
                new_request = self.utils.update_content_length(request, new_body)
                task = Task(
                    self.make_request,
                    http_service, new_request, panel, MENU_ITEM_FUZZ_SELECTED, body, new_body,
                    self.utils.get_settings()["delay"], cancellation_token)
                executor.submit(task)
        # selected outside the body
        else:
            for payload in payloads:
                task = Task(self.make_request, http_service, request, panel, MENU_ITEM_FUZZ_SELECTED, selected,
                            payload, self.utils.get_settings()["delay"], cancellation_token)
                executor.submit(task)

        executor.shutdown()
