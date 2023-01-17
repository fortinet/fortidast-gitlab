'''
Gitlab CI/CD establishes connection with FortiDAST REST API server and
triggers automated scan upon each commit.
'''

import sys
import json
import time
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

errorCodes = {
  "0":  "",
  "1": "Please recheck your scan configuration before rescanning.",
  "2": "Please verify HTTP Authentication (Basic/Digest/NTLM) credentials in "\
        "scan configuration before rescanning.",
  "3": "Crawler/fuzzer encountered an invalid SSL/TLS cert. Please check "\
        "InsecureSSL in configuration before rescanning.",
  "4": "Crawler/fuzzer encountered an error using the proxy. Please check "\
        "proxy configuration before rescanning.",
  "5": "Forced Browsing has reached timeout. There is a possibility for "\
        "partially scanned results.",
  "6": "Login URL is not reachable. Please check if login URL provided is "\
        "correct.",
  "7": "Login URL doesn't have HTTP or form authentication. Please check if "\
        "login URL provided is correct.",
  "8": "Login is unsuccessful. Please check if user/password/login URL "\
        "provided is correct.",
  "9": "Login URL is not in the same domain as target URL.",
  "10": "Invalid HTTP request headers. Please check if the headers provided "\
        "are correct.",
  "256": "Crawler/fuzzer encountered error during scan. Please check "\
            "logs/contact tech support.",
  "257": "Crawler/fuzzer could not parse URL. Please check logs/contact tech "\
            "support.",
  "258": "Crawler/fuzzer encountered error during initialization. Please "\
            "check logs/contact tech support.",
  "259": "Crawler/fuzzer encountered error during initialization.  Please "\
            "check logs/contact tech support.",
  "260": "Crawler/fuzzer encountered error accessing backend services. Please "\
            "check logs/contact tech support.",
  "261": "Crawler/fuzzer encountered error during scan. Please check "\
            "logs/contact tech support.",
  "262": "Crawler/fuzzer encountered error during scan. Please check "\
            "logs/contact tech support.",
  "263": "Crawler/fuzzer encountered error during scan. Please check "\
            "logs/contact tech support.",
  "512":  "URL could not be accessed. Please check web server or try "\
            "rescanning.",
  "513":  "DNS lookup failed. Please try rescanning.",
  "514":  "Browser automation failed. Please try rescanning.",
  "515":  "Browser automation failed. Please try rescanning.",
  "516":  "Code initialization failed. Please try rescanning.",
  "517":  "Backend services failed to respond. Please try rescanning.",
  "518":  "Fuzzer reached configured timeout. Please try rescanning.",
  "768":  "Stop requested by user.",
  "769": "Internal error with initiation of crawler module.",
  "770":  "Internal error with initiation of scan module.",
  "771":  "Resource unavailable. Retry after sometime.",
  "772": "Exception has been occured while accessing the object in database",
  "773":  "AMQP channel is not ready",
  "774":  "Scanagent Timed out waiting for scan command after authorization",
  "1024":  "Please be aware that the maximum time allotted for crawling the "\
            "asset has been reached. There is a possibility for partially "\
            "scanned results."
}

class ScanEngine:

    ''' initializing class variables '''
    # pylint: disable=too-many-instance-attributes
    # Six looks reasonable.
    def __init__(self, apiUrl, scanUrl, assetUuid, scanType, apiKey):
        self.apiUrl = apiUrl
        self.scanUrl = scanUrl
        self.assetUuid = assetUuid
        self.scanType = scanType
        self.apiKey = apiKey
        self.headers = {"X-API-Key":"{0}".format(apiKey)}
        self.scanStartApiUrl = '{0}/cmdb/scan/start'.format(apiUrl)
        self.scanStopApiUrl = '{0}/cmdb/scan/stop'.format(apiUrl)
        self.scanStatusApiUrl='{0}/query/scanstatus?url={1}&uuid={2}'.format(
                apiUrl, scanUrl, assetUuid)
        self.client = requests.Session()

    def GetScanStatus(self):
        ''' Gets the scan status of an asset '''
        responseJson = None
        resp= self.client.get(self.scanStatusApiUrl, headers=self.headers,
                              verify=False, timeout=25)
        responseJson = resp.json()
        if resp.status_code >= 400 and resp.status_code <= 599:
            status = None
            try:
                statusObj = responseJson['Status']
                status = statusObj['status']
            except Exception:
                status = responseJson['Status']
            return status, True
        jsonTxt = json.dumps(responseJson)

        if "Authorization Failed" in jsonTxt:
            return "Asset not Authorized.Authorize the Scan URL from UI", True
        if "Scan Request in Queue" in jsonTxt:
            print("Scan Request in Queue")
        return jsonTxt, False

    def DoPostRequest(self, endPoint, requestBody):
        ''' Do Post Request '''
        responseJson = None
        resp= self.client.post(endPoint, headers=self.headers, data=requestBody,
                               verify=False, timeout=25)
        responseJson = resp.json()
        if resp.status_code >= 400 and resp.status_code <= 599:
            status = None
            try:
                statusObj = responseJson['Status']
                status = statusObj['status']
            except:
                status = responseJson['Status']
            return status,True
        jsonTxt = json.dumps(responseJson)
        return jsonTxt, False

    def StopScan(self):
        ''' Stops the scan '''
        requestBody = {}
        requestBody['url'] = self.scanUrl
        requestBody['uuid'] = self.assetUuid
        jsonData = json.dumps(requestBody)
        return self.DoPostRequest(self.scanStopApiUrl, jsonData)

    def StartScan(self):
        ''' starts the scan '''
        requestBody = {}
        requestBody['url'] = self.scanUrl
        requestBody['uuid'] = self.assetUuid
        requestBody['scan_type'] = self.scanType
        jsonData = json.dumps(requestBody)
        return self.DoPostRequest(self.scanStartApiUrl, jsonData)

    def GetErrorCode(self):
        '''
        Gets the error code if any error occurs while scanning
        the target
        '''
        scanStatusRes, isErr = self.GetScanStatus()
        if isErr:
            print(scanStatusRes)
            sys.exit(1)
        jsonObj = json.loads(scanStatusRes)
        statusObj = jsonObj['Status'][0]
        scanError = statusObj['scan_error']
        return str(scanError)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description= "Scan Configuration for "\
                                     "trigering Scan.")

    parser.add_argument("apiUrl", help="FortiDAST REST API URL")
    parser.add_argument("scanUrl",help="Scan Url on which scan to be triggered")
    parser.add_argument("Uuid", help="Asset UUID")
    parser.add_argument("scanType", help="Quick Scan=0, Full Scan=1")
    parser.add_argument("apiKey", help="API Key")
    args = parser.parse_args()

    inargs_apiUrl = args.apiUrl
    inargs_scanUrl = args.scanUrl
    inargs_assetUuid = args.Uuid
    inargs_scanType = int(args.scanType)
    inargs_apiKey = args.apiKey

    scanEngine = ScanEngine(inargs_apiUrl, inargs_scanUrl, inargs_assetUuid,
                            inargs_scanType, inargs_apiKey)

    try:
        requests.packages.urllib3.disable_warnings(category=
                                                   InsecureRequestWarning)
        scanStatusResp, isError = scanEngine.GetScanStatus()
        ISSTOPPED = False
        if isError:
            print(scanStatusResp)
            sys.exit(1)

        if "In Progress" in scanStatusResp:
            print("stopping current Active Scan")
            stopScanResp, isError = scanEngine.StopScan()
            time.sleep(10)
            if not "Scan Stop Request Successfull" in stopScanResp or isError:
                print(stopScanResp)
                print("Fail to trigger Stop Scan")
                sys.exit(1)
            ISSTOPPED = True
        startScanResp, isError = scanEngine.StartScan()
        time.sleep(10)

        if not "Scan Request Successfull" in startScanResp or isError:
            print(startScanResp)
            print("Failed to start scan")
            sys.exit(1)

        print("Scan started on the target %s" %(scanEngine.scanUrl))
        scanStatusResp, isError = scanEngine.GetScanStatus()

        if isError:
            print(scanStatusResp)
            sys.exit(1)

        while "Scan Complete" not in scanStatusResp:
            scanStatusResp, isError = scanEngine.GetScanStatus()
            if isError:
                print(scanStatusResp)
                sys.exit(1)
            ERRORCODE = scanEngine.GetErrorCode()
            if not ERRORCODE is None and ERRORCODE != "0" and not ISSTOPPED:
                try:
                    print(errorCodes[ERRORCODE])
                except:
                    print("Scan exited with Internal Server Error")
                sys.exit(1)

            if  "Stopped" in scanStatusResp:
                print("Scan stopped externally")
                sys.exit(1)

            time.sleep(30)

        print("Scan completed Successfully")

    except Exception as ex:
        print("Exception while triggering scan:", ex.__class__)
        sys.exit(1)
    finally:
        scanEngine.client.close()
