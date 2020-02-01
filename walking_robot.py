#!/usr/bin/python3

import http.client
import nmap
import sys
import threading
import time
import imports.req

http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

def banner():
    print('''
              _ _   _                     _         _   
 __ __ ____ _| | |_(_)_ _  __ _   _ _ ___| |__  ___| |_ 
 \ V  V / _` | | / / | ' \/ _` | | '_/ _ \ '_ \/ _ \  _|
  \_/\_/\__,_|_|_\_\_|_||_\__, | |_| \___/_.__/\___/\__|
                          |___/                         
''')
    print("Usage: python walking_robot.py [options]")
    print("Options:")
    print("python walking_robot.py ip")
    print("python walking_robot.py -u ip -p port")
    print("python walking_robot.py -f urls.txt")
    print("python walking_robot.py -r urls.txt -p port")
    print("python walking_robot.py -h --help\r\n")

def function(ip_addr, port):
    if port == 80:
        req = imports.req.req_verify(ip_addr, str(port))
        req.req80()
    elif port == 161:
        req = imports.req.req_verify(ip_addr, str(port))
        req.req161()
    elif port == 8081:
        req = imports.req.req_verify(ip_addr, str(port))
        req.req8081()

def thread(ip_addr):
    try:
        start =time.clock()
        scanner = nmap.PortScanner()
        scanner.scan(ip_addr, '1-10000', '-sS -Pn --open -T4')
        tcport = list(scanner[ip_addr]['tcp'].keys())
        tcport.sort()
        print(">>> Target url : " + ip_addr)
        for port in tcport:
            print("{0}:{1}".format(ip_addr, port))
            function(ip_addr, port)
        end = time.clock()
        print('\r\nRunning time: %s Seconds'%(end-start))
    except Exception as e:
        print(e)

def main(ip_addr):
    th = threading.Thread(target=thread,args=(ip_addr,))
    th.start()

if __name__ == "__main__":
    try:
        if sys.argv[1] == "-f":
            with open(sys.argv[2]) as f:
                for line in f.readlines():
                    line = line.strip()
                    main(line)
        elif sys.argv[1] == "-r" and sys.argv[3] == "-p":
            with open(sys.argv[2]) as f:
                for line in f.readlines():
                    line = line.strip()
                    function(line, int(sys.argv[4]))
        elif sys.argv[1] == "-u" and sys.argv[3] == "-p":
            if type(int(sys.argv[4])) == int:
                print(">>> Target url : " + sys.argv[2])
                function(sys.argv[2], int(sys.argv[4]))
        elif sys.argv[1] == "-h" or "--help":
            banner()
        else:
            main(sys.argv[1])
    except Exception as e:
        banner()
        print(e)
