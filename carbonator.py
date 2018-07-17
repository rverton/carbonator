import time
import os

from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
from java.net import URL
from java.io import File

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Carbonator")
        self._helpers = self._callbacks.getHelpers()
        self.clivars = None

        self.spider_results = []
        self.scanner_results = []
        self.packet_timeout = 5

        self.last_packet_seen = int(
            time.time()
        )  # initialize the start of the spider/scan

        if not self.processCLI():
            return None

        self.clivars = True

        print("Initiating Carbonator against '{}'".format(self.url))

        # add to scope if not already in there
        if self._callbacks.isInScope(self.url) == 0:
            self._callbacks.includeInScope(self.url)

        # ensure that the root directory is scanned
        base_request = "GET {} HTTP/1.1\nHost: {}\n\n".format(self.path, self.fqdn)
        
        if self.scheme == "HTTPS":
            print(self._callbacks.doActiveScan(self.fqdn, self.port, 1, base_request))
        else:
            print(self._callbacks.doActiveScan(self.fqdn, self.port, 0, base_request))

        self._callbacks.sendToSpider(self.url)
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerListener(self)

        while int(time.time()) - self.last_packet_seen <= self.packet_timeout:
            time.sleep(1)

        print("No packets seen in the last {} seconds".format(self.packet_timeout))
        print("Removing Listeners")
        self._callbacks.removeHttpListener(self)
        self._callbacks.removeScannerListener(self)
        self._callbacks.excludeFromScope(self.url)

        print("Generating Report")

        self.generateReport(self.export)

        print("Report Generated")
        print("Closing Burp in {} seconds.".format(self.packet_timeout))

        time.sleep(self.packet_timeout)

        if self.clivars:
            self._callbacks.exitSuite(False)

    def processHttpMessage(self, tool_flag, isRequest, current):
        self.last_packet_seen = int(time.time())
        if (
            tool_flag == self._callbacks.TOOL_SPIDER and isRequest
        ):  # if is a spider request then send to scanner
            self.spider_results.append(current)
            print("Sending new URL to Vulnerability Scanner: URL #".format(len(self.spider_results)))

            if self.scheme == "https":
                self._callbacks.doActiveScan(
                    self.fqdn, self.port, 1, current.getRequest()
                )  # returns scan queue, push to array
            else:
                self._callbacks.doActiveScan(
                    self.fqdn, self.port, 0, current.getRequest()
                )  # returns scan queue, push to array

    def newScanIssue(self, issue):
        self.scanner_results.append(issue)
        print("New issue identified: Issue #{}".format(len(self.scanner_results)))

    def generateReport(self, filename):
        _, format = os.path.splitext(filename)

        if not format in ['xml', 'html']:
            format = 'xml'

        self._callbacks.generateScanReport(
            format.upper(), self.scanner_results, File(filename)
        )

        time.sleep(5)

    def processCLI(self):
        cli = self._callbacks.getCommandLineArguments()

        if len(cli) < 0:
            print("Incomplete target information provided.")
            return False

        if not cli:
            print("""Integris Security Carbonator is now loaded.\nIf Carbonator was loaded through the BApp store then you can run in headless mode simply adding the `-Djava.awt.headless=true` flag from within your shell. Note: If burp doesn't close at the conclusion of a scan then disable Automatic Backup on Exit.\nFor questions or feature requests contact us at carbonator at integris security dot com.\nVisit carbonator at https://www.integrissecurity.com/Carbonator""")

            return False

        if cli[0] == "https" or cli[0] == "http":
            self.scheme = cli[0]
            self.fqdn = cli[1]
            self.port = int(cli[2])
            self.path = cli[3]

            if len(cli) >= 4:
                self.export = cli[4]

            self.url = URL(self.scheme, self.fqdn, self.port, self.path)

        else:
            print("Invalid command line arguments supplied")
            return False

        return True