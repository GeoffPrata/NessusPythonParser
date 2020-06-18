#!/usr/bin/python
#Built by Geoff Prata

import sys
import requests
import json
import csv
#Disables security warnings
requests.packages.urllib3.disable_warnings()
# Fill in these variables with the information required.
# 'https://EnterNessusIP:8834'
# Also change the accessKey and secretKey
tempValue = {}

for x in range(9999,250000):
    print ("plugin ID: " + str(x) + " parsed")
    url = "https://172.26.32.180:8834/plugins/plugin/" + str(x)
    headers = {
    'content-type': 'application/json',
     'X-ApiKeys':'accessKey=c2fcef8c59e86891410c19189097f426dfbca7af2b96ac79fe45fbd502594528;secretKey=cc1ae04544386114b08f5a5e47e55c05ebea7b2fa8b3e43e2d734c697a40ca53;'}
    r = requests.get(url, headers=headers, verify=False)
    if (r.text) == "":
        continue
    else:
        data = json.loads(r.text)
        for x in data["attributes"]:
            tempValue[x["attribute_name"]] = x["attribute_value"]

        if ("vuln_publication_date" not in tempValue):
            continue
        elif("exploit_available" not in tempValue):
            continue
        else:
                #Print specific keys/values to CSV
            f = open("myTestCSVDescription.csv", "a", newline='')
            with f:
                fnames = ["fname", "plugin_name","script_version", "vuln_publication_date", "plugin_publication_date" ,"plugin_modification_date" , "risk_factor" ,"plugin_type" ,"exploit_available" ,"exploitability_ease"]
                writer = csv.DictWriter(f, fieldnames=fnames, extrasaction='ignore')
                writer.writerow(tempValue)
print ("Task Completed")
