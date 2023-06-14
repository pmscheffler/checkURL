from math import fabs
from xml.etree.ElementInclude import include
import requests
import json
import pprint
import urllib3
import datetime
import getopt, sys, re, time

urllib3.disable_warnings()


def checkURL(argv):
    bigip_host = "hostname or IP"
    username = "admin"
    hiddenpassword = "SomePassword"
    policyName = ""
    managementUrl = ""
    targetMethod = "GET"
    targetHeaders = {}
    targetData = ""

    try:
        opts, args = getopt.getopt(argv, "?h:u:p:n:t:m:d:H", ["host=", "user=", "password=", "name=", "target", "method", "data", "headers"])
    except getopt.GetoptError:
        print('Show policy audit details.')
        print('-? checkURL.py')
        print('-h <hostname or ip> (host=)')
        print('-u <username> (username=)')
        print('-p <password> (password=)')
        # print('-n <policyfilter> (name=)')
        print('-t <targetURL> to test (--target)')
        print('-m <method> for the target to be tested (--method)')
        print('-d <escaped data> for the target to be tested (--data)')
        print('-H <escaped JSON headers  for the target to be tested {"Header1": "Value", "Header2": "Value"} (--headers)')
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-?":
            print('Show policy audit details.')
            print('-? checkURL.py')
            print('-h <hostname or ip> (host=)')
            print('-u <username> (username=)')
            print('-p <password> (password=)')
            # print('-n <policyfilter> (name=)')
            print('-t <targetURL> to test')
            print('-m <method> for the target to be tested')
            print('-d <escaped data> for the target to be tested')
            print('-H <escaped JSON headers  for the target to be tested {"Header1": "Value", "Header2": "Value"} (--headers)')
            sys.exit(1)
        elif opt in ("-h", "--host"):
            bigip_host = arg
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            hiddenpassword = arg
        elif opt in ("-n", "--name"):
            policyName = arg
        elif opt in ("-t", "--target"):
            targetUrl = arg
        elif opt in ("-m", "--method"):
            targetMethod = arg
        elif opt in ("-d", "--data"):
            targetData = arg
        elif opt in ("-H", "--headers"):
            targetHeaders = json.JSONEncoder.dumps(arg)

    testResponse = requests.request(targetMethod, targetUrl, headers=targetHeaders, data=targetData, verify=False)

    print(testResponse.text)

    if (testResponse.text.find('<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br>Your support ID is: ') > 0):
        print('Not blocked')
        sys.exit(0)
        
    regex = r":\s(\d+)"
    supportId = re.findall(regex, testResponse.text)

    if(supportId):
        print(supportId[0])
    else:
        print('unable to locate a SupportId')          
        sys.exit(1)

    # wait for the log to be written
    time.sleep(5)

    managementUrl = "https://" + bigip_host + "/mgmt/shared/authn/login"

    payload = json.dumps({
        "username": username,
        "password": hiddenpassword,
        "loginProviderName": "tmos"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request(
        "POST", managementUrl, headers=headers, data=payload, verify=False)

    data = json.loads(response.text)

    authToken = data['token']['token']

    managementUrl = "https://" + bigip_host + "/mgmt/tm/asm/events/requests/" + supportId[0] + "?$expand=violations%2FhttpSubviolationReference,violations%2FwssSubviolationReference,violations%2FevasionSubviolationReference,suggestionReferences&servertime=true"

    payload = {}
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': authToken
    }

    print(managementUrl)

    response = requests.request(
        "GET", managementUrl, headers=headers, data=payload, verify=False)
    
    print(response.text)
  
    violationData = json.loads(response.text)

    pprint.pprint(violationData)
    sys.exit(0)

    for policy in policyData['items']:
        policyID = policy['id']
        policyName = policy['name']
        print("\n*********\nPolicy: " + policyName)
        managementUrl = "https://" + bigip_host + "/mgmt/tm/asm/policies/" + policyID + "/audit-logs/"

        payload = ""

        response = requests.request(
            "GET", managementUrl, headers=headers, data=payload, verify=False, timeout=3600)

        auditRecs = json.loads(response.text)
        for auditItem in auditRecs['items']:
            pcDescription = auditItem['description']
            pcEventType = auditItem['eventType']
            pcTimeStamp = policy['lastUpdateMicros']

            print("\nPolicy change info (" + pcEventType + "): " + "\nChange Detail:" +
                  pcDescription + "\nOn: " + str(datetime.datetime.fromtimestamp(pcTimeStamp/1000000.0)))

if __name__ == "__main__":
    checkURL(sys.argv[1:])

