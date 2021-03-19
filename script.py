import concurrent.futures
import sys
import requests
import re
from colorama import Fore, Style
import time

# Reading givien input file and add =FUZZ then output it.
def readFile(filePath, output):
    with open(filePath, 'r') as file:
        for line in file:
            if '=' in line:
                patern = re.sub(r'=[a-zA-Z0-9%\-_.+:/]{0,}', '=FUZZ', line)
                print(patern, file=open(output, "a"))
            else:
                pass


# Sorting and delete dubplicated lines
def sorting(output):
    with open(output) as resultx:
            uniqlines = set(resultx.readlines())
            delemptylines = filter(lambda x: not x.isspace(), uniqlines)
            with open(output, 'w') as final_file:
                final_file.writelines(set(delemptylines))

# Threading
def Thread(vuln):
    myList = open(sys.argv[2]).readlines()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for url in myList:
            futures.append(executor.submit(vuln, url))
        for future in concurrent.futures.as_completed(futures):
            #print(future.result())
            pass

def testSQLI(url, timeout=10):
    r1 = requests.get(url, timeout)
    re1 = (len(r1.text))
    x = url.replace("FUZZ", "'")
    r2 = requests.get(x)
    re2 = (len(r2.text))

    if re2 < re1:
        print(Fore.GREEN + '[*] Vulnerable to SQLI => ' + Fore.YELLOW +url, end='')
    else:
        print(Fore.RED + '[*] Not Vulnerable to SQLI => ' + Fore.BLUE + url, end='')


def testXSS(url, timeout=10):
    x = url.replace('FUZZ', '<script>alert("AT7")</script>')
    r = requests.get(x, timeout)
    if "AT7" in r.text:
        print(Fore.GREEN + '[*] Vulnerable to XSS => ' + Fore.YELLOW +url, end='')
    else:
        print(Fore.RED + '[*] Not Vulnerable to XSS => ' + Fore.BLUE + url, end='')


if __name__=='__main__':
    try:
        if len(sys.argv) > 2:
            t1 = time.perf_counter()
            
            print(Style.BRIGHT + Fore.RED + '''
	    ___  ______  _____
	   /   |/_  __/ /__  /
	  / /| | / /      / / 
	 / ___ |/ /      / /  
	/_/  |_/_/_____ /_/   
	         /_____/
''')
            print(Fore.YELLOW + '''              CODED BY : A.Tarek
''')

            #Running Functions
            readFile(sys.argv[1], sys.argv[2])
            sorting(sys.argv[2])
            print(Fore.CYAN + "[#]Testing SQLI[#]")
            Thread(testSQLI)
            print(Fore.CYAN + "[#]Testing XSS[#]")
            Thread(testXSS)
            t2 = time.perf_counter() - t1
            print(f'Total time taken: {t2:0.2f} seconds')

        else:
            print(Fore.YELLOW + '[*] Usage: python3 script.py list.txt output.txt')
    except:
        sys.exit()
