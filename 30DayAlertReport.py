#!/bin/env python
#This script will pull all alerts triggered over the past 30 days. 
#30 reports will be generated, run, parsed, and destroyed to get this info each time script runs

import requests
import json
import hashlib
import base64
import time
import hmac
import csv
from datetime import datetime, timedelta
import urllib.request
import getpass

#Account Info - uses an API user with manage access to reports and view access to all resources. Creds hard-coded so it can be used in automated jobs.
AccessId = getpass.getpass(prompt='Enter the Access ID of the LM user: ')
AccessKey = getpass.getpass(prompt='Enter the Access Key of the LM user: ')
Company = getpass.getpass(prompt='Enter the comapany name in LM: example is haservices) ')
numDaysAlerts = getpass.getpass(prompt='Enter the number of days you want alerts for. Max 30: ')


#initialize variables
dayCounter = 1
#lowerBoundValue needs to be edited if you want to adjust the length that this will go back (30 days, 7 days, etc.)
lowerBoundValue = 7
dayDecrementer = 1
upperBoundValue = lowerBoundValue - dayDecrementer
lowerBoundDate = datetime.now() - timedelta(lowerBoundValue)
upperBoundDate = datetime.now() - timedelta(upperBoundValue)
reportIdList = []

#run a report of all alerts triggered over the past 30 days, 1 day at a time
if int(numDaysAlerts) <=30:
    while dayCounter <= int(numDaysAlerts):
        formattedLowerBoundDate = (datetime.now() - timedelta(lowerBoundValue)).strftime('%Y-%m-%d %H:%M')
        formattedUpperBoundDate = (datetime.now() - timedelta(upperBoundValue)).strftime('%Y-%m-%d %H:%M')
        
        #Request Info
        httpVerb ='POST'
        resourcePath = '/report/reports'
        #report is defined in the data variable, including what columns are displayed
        data = '{"type":"Alert","groupId":199,"name":"' + str(lowerBoundValue) + ' Day Report - Part ' + str(dayCounter) + '","includePreexist":false,"sdtFilter":"nonsdt","timing":"start","dateRange":"' + formattedLowerBoundDate + ' TO ' + formattedUpperBoundDate + '","format":"CSV","description":"Series of reports to get all alerts triggered in the past 30 days.","delivery":"none","groupFullPath":"*","level":"all","activeOnly":false,"columns":[{"name":"Severity","isHidden":false},{"name":"Device","isHidden":false},{"name":"Datasource","isHidden":false},{"name":"Instance","isHidden":false},{"name":"Datapoint","isHidden":false},{"name":"Value","isHidden":true},{"name":"Began","isHidden":false},{"name":"Group","isHidden":false},{"name":"Thresholds","isHidden":true},{"name":"End","isHidden":true},{"name":"Rule","isHidden":true},{"name":"Chain","isHidden":true},{"name":"Acked","isHidden":true},{"name":"Acked By","isHidden":true},{"name":"Acked On","isHidden":true},{"name":"Notes","isHidden":true},{"name":"In SDT","isHidden":true}]}'
        lowerBoundValue -= dayDecrementer
        upperBoundValue -= dayDecrementer
        dayCounter +=1

        #Construct URL 
        url = 'https://'+ Company +'.logicmonitor.com/santaba/rest' + resourcePath 
        
        #Get current time in milliseconds
        epoch = str(int(time.time() * 1000))

        #Concatenate Request details
        requestVars = httpVerb + epoch + data + resourcePath

        #Construct signature
        hmac1 = hmac.new(AccessKey.encode(),msg=requestVars.encode(),digestmod=hashlib.sha256).hexdigest()
        signature = base64.b64encode(hmac1.encode())

        #Construct headers
        auth = 'LMv1 ' + AccessId + ':' + signature.decode() + ':' + epoch
        headers = {'Content-Type':'application/json','Authorization':auth}

        #Make request
        response = requests.post(url, data=data, headers=headers)

        #Print status and body of response
        #print('Response Status:',response.status_code)

        #format response as JSON
        data = json.loads(response.content)
        reportId = data["data"]["id"]
        reportIdList.append(reportId)    
else:
    print("Too many days selected. Try running the script again.")
    quit()

print("Reports successfully generated")

#Placeholder list that alerts from all reports will be appended to
masterList = []
reportCounter = 1

#run each report that was generated earlier and parse results. Append results to master list
for reportId in reportIdList:
    #Request Info
    runReporthttpVerb ='POST'
    runReportresourcePath = '/functions'
    runReportdata = '{"type":"generateReport","reportId":' + str(reportId) + '}'
    #Construct URL
    runReporturl = 'https://'+ Company +'.logicmonitor.com/santaba/rest' + runReportresourcePath

    #Get current time in milliseconds
    runReportepoch = str(int(time.time() * 1000))

    #Concatenate Request details
    runReportrequestVars = runReporthttpVerb + runReportepoch + runReportdata + runReportresourcePath

    #Construct signature
    runReporthmac1 = hmac.new(AccessKey.encode(),msg=runReportrequestVars.encode(),digestmod=hashlib.sha256).hexdigest()
    runReportsignature = base64.b64encode(runReporthmac1.encode())
    
    #Construct headers
    runReportauth = 'LMv1 ' + AccessId + ':' + runReportsignature.decode() + ':' + runReportepoch
    runReportheaders = {'Content-Type':'application/json','Authorization':runReportauth}

    #Make request
    runReportresponse = requests.post(runReporturl, data=runReportdata, headers=runReportheaders)

    #print('Response Body:',response.content)
    runReportdata = json.loads(runReportresponse.content)
    reportUrl = runReportdata["data"]["resulturl"]

    #open a connection to a URL using urllib
    webUrl  = urllib.request.urlopen(reportUrl)

    #read the data from the URL and decode it
    webData = webUrl.read()
    decodedData = webData.decode()
    decodedData.replace("\u200b", "")
    
    #split output on each new line from the report to get our rows. Remove first 5 rows of each report
    rawAlertList = decodedData.split('\n')
    alertList = rawAlertList[5:]
    
    #loop over each line of the alert list and split on commas to get our individual cell values for row
    for item in alertList:
        #below logic will allow us to split on commas while ignoring commas enclosed within quotation marks
        alertArray = [ '"{}"'.format(x) for x in list(csv.reader([item], delimiter=',', quotechar='"'))[0] ]
        if len(alertArray) >= 6:
            #append row to master list
            masterList.append(alertArray)
    print("Cumulative alerts so far on day " + str(reportCounter) + " - " + str(len(masterList)))
    reportCounter +=1

#define values for CSV file
csv_columns = ["Severity", "Device", "Datasource", "Instance", "Datapoint", "Began", "Client Code", "Group"]
csv_filename = "alertListv3.csv"
csvList = []
for alertEntry in masterList:
    severity = alertEntry[0].strip('"')
    deviceName = alertEntry[1].strip('"')
    datasource = alertEntry[2].strip('"')
    instanceName = alertEntry[3].strip('"')
    datapoint = alertEntry[4].strip('"')
    began = alertEntry[5].strip('"')
    group = alertEntry[6].strip('"')
    #some logic here to parse the group value and look for the presence of "1. Clients/" then grab the following 3 characters
    splitGroup = group.split("Clients/")
    previous = next_object = None
    splitGroupLength = len(splitGroup)
    #default value for client_code is defined below. If device belongs to a client, it will be adjusted to be the client code
    client_code = "CDI Internal"
    for index, obj in enumerate(splitGroup):
        #check split array for presence of '1. '. Since we split on 'Clients/', the next iteration after '1. ' will start with the client code
        if obj.endswith("1. "):
            if index < (splitGroupLength - 1):
                next_object = splitGroup[index + 1]
                #pull the client code off of the first 3 characters of this object
                client_code = next_object[0:3]

    #append values to dictionary object which represents 1 row on the report.
    temp_dict = {"Severity": severity, "Device": deviceName, "Datasource": datasource, "Instance": instanceName, "Datapoint": datapoint, "Began": began, "Client Code": client_code, "Group": group}
    csvList.append(temp_dict)

totalAlerts = len(csvList)
print("Total alerts past " + str(numDaysAlerts) + " days - " + str(totalAlerts))

#write data to CSV file with collector informatio
with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()
    for entry in csvList:
        writer.writerow(entry)

print("CSV file written to local directory")

#Once I get the output all pieced together, I need to delete all the reports generated
for reportIdToDelete in reportIdList:
    #Request Info to delete reports
    deleteReporthttpVerb ='DELETE'
    deleteReportresourcePath = '/report/reports/' + str(reportIdToDelete)

    #Construct URL 
    deleteReporturl = 'https://'+ Company +'.logicmonitor.com/santaba/rest' + deleteReportresourcePath 

    #Get current time in milliseconds
    deleteReportepoch = str(int(time.time() * 1000))

    #Concatenate Request details
    deleteReportrequestVars = deleteReporthttpVerb + deleteReportepoch + deleteReportresourcePath

    #Construct signature
    deleteReporthmac1 = hmac.new(AccessKey.encode(),msg=deleteReportrequestVars.encode(),digestmod=hashlib.sha256).hexdigest()
    deleteReportsignature = base64.b64encode(deleteReporthmac1.encode())

    #Construct headers
    deleteReportauth = 'LMv1 ' + AccessId + ':' + deleteReportsignature.decode() + ':' + deleteReportepoch
    deleteReportheaders = {'Content-Type':'application/json','Authorization':deleteReportauth}

    #Make request
    deleteReportresponse = requests.delete(deleteReporturl, headers=deleteReportheaders)

    #Print status and body of response
    print('Response Status:',deleteReportresponse.status_code)

print("Reports successfully deleted")
