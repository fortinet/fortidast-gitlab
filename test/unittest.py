'''
Test util that establishes connection with FortiPenTest REST API server and
triggers automated scan upon each commit.
'''

import sys
import os
import argparse
from src.scan import ScanEngine
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))



def main():
    '''
    main function for test utility
    '''
    parser = argparse.ArgumentParser(description= "Scan Configuration for "\
                                     "trigering Scan.")

    parser.add_argument("apiUrl", help="FortiPentest REST API URL")
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
    if scanEngine is None:
        print("Unit test failed")


if __name__ == "__main__":
    main()
