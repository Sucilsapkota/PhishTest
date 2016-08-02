#=============================#
#          PhishTest          #
#  	   Author: dhruvin917     #
#        Version: 1.0         #
#=============================#

#Import Libraries to pull Feed and Scan URLs and parse it for status
import json
import urllib
import urllib2
import simplejson

#Start
continueCode = 1

while (continueCode == 1):

    #Ask for URL
    testThis = raw_input("Enter the URL to test: ")

    #Check OpenPhish Feed
    txt = urllib2.urlopen("https://www.openphish.com/feed.txt")
    if testThis in txt.read():
        OpenPhishResult = "True"
    else:
        OpenPhishResult = "False"

    #Check Phish Tank
    PhishTankURL = "http://checkurl.phishtank.com/checkurl/"
    PhishTParm = {"url": testThis,
                  "format": "json",
                  "app_key": " ** Enter PhishTank App Key ** "}
    data_PT = urllib.urlencode(PhishTParm)
    request_PT = urllib2.Request(PhishTankURL, data_PT)
    response_PT = urllib2.urlopen(request_PT)
    json_PT = response_PT.read()
    response_PT_dict = simplejson.loads(json_PT)

    responseThingMeta = response_PT_dict.get("meta")
    PhishTankStatus = responseThingMeta.get("status")

    if PhishTankStatus == "error":
        PhishTankResult = response_PT_dict.get("errortext")
    else:
        PhishTankResult = response_PT_dict.get("results")
        PhishTankResult = PhishTankResult.get("in_database")
    
    #Start VirusTotal Scan
    virusTotalURL = "https://www.virustotal.com/vtapi/v2/url/report"
    parameters = {"resource": testThis,
                  "apikey":"** Enter VirusToatal App Key ** "}
    data = urllib.urlencode(parameters)
    request = urllib2.Request(virusTotalURL, data)
    response = urllib2.urlopen(request)
    json = response.read()
    response_dict = simplejson.loads(json)

    responseCode = response_dict.get("response_code")

    if responseCode == 0:
        scan_date = "Scan failed"
        Positives = "Scan failed"
        scanMessage = response_dict.get("verbose_msg")
        Positives = "Scan failed"
    else:
        scan_id = response_dict.get("scan_id")
        link = response_dict.get("url")
        response_code = response_dict.get("response_code")
        scan_date = response_dict.get("scan_date")
        analysis = response_dict.get("permalink")
        Positives = response_dict.get("positives")
        total = response_dict.get("total")
        scanMessage = "Success"

    #Print Results
    print "Scan finished, Check your scan information bellow:\n"
    print "| Scan Complete Date:        "+scan_date
    print "| VirustTotal Scan Status:   "+str(scanMessage)
    print "| VirustTotal Positives:     "+str(Positives)
    print "| OpenPhish feed search:     " + OpenPhishResult
    print "| Found in PhishTank DB:     " +str(PhishTankResult)

    #Ask to scan again
    scanAnother = raw_input("\nDo you want to scan different site? (y/n): ").lower().strip()
    if scanAnother[0] == 'y':
        print "\n-------------------------------------\n"
        continue
    if scanAnother[0] == 'n':
        continueCode = 0
        print "\n-------------------------------------\n"
        print "Goodbye..."
    else:
        print "\n--------------- ERROR ---------------\n"
        print "\nInvalid input! Exitting prongram..."
        break
