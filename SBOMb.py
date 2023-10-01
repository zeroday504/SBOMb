import json
import argparse
import nvdlib
import colorama
from colorama import Fore
import xml.etree.ElementTree as ET
import time
import progressbar
from googlesearch import search
import cve_searchsploit as CS



parser = argparse.ArgumentParser(description='SBOMb.py is a tool built to easily parse files that are a part of the CycloneDX SBOM format (JSON or XML) as well as take user-generated txt files that meet specific formatting requirements. SBOM.py will then query the NVD and see if any of the packages listed in the SBOM files are predisposed to documented vulnerabilities. Please reference the included \'dependencies.txt\' to understand how to format txt files for this program.')
parser.add_argument('--jsonfilepath', nargs=1, help="Path to JSON file from SBOM to be parsed", dest='jsonfile', type=argparse.FileType('r', encoding="utf8"))
parser.add_argument('--txtfilepath', nargs=1, help="Path to txt file with SBOM dependency names", dest='txtfile', type=str)
parser.add_argument('--xmlfilepath', nargs=1, help="Path to XML file from SBOM to be parsed", dest='xmlfile', type=argparse.FileType('r', encoding="utf8"))
parser.add_argument('--exploitcheck', help="Check for existing exploits against identified CVEs, MAY GET RATE LIMITED", dest='exploitcheck', action='store_true')
arguments = parser.parse_args()

#ASCII Art
def art():
    print("    ___  ___   _   _   __                   __.!,   ")
    print("  ,' _/ / o.),' \ / \,' //7     _ _ __   __/  -*-   ") 
    print(" _\ `. / o \/ o |/ \,' //o\    /o|\V / ,d08b. '|`   ")
    print("/___,'/___,'|_,'/_/ /_//_,'() /_,' )/  0088MM       ")
    print("                             //   //   '9MMp'       ")
    print('==========================================================')
    print("Keeping your software safe from going BOOM post-production")
    print('==========================================================\n')

cve_listing = open("cves.txt", "a")
if arguments.exploitcheck == True:
    CS.update_db()


def barofprogress():
    bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)
    for i in range(20):
        time.sleep(0.1)
        bar.update(i)

def NVD_search(x,y):
    query = x + " " + y
    print("Checking against NVD for documented vulnerabilities...")
    result = nvdlib.searchCVE(keywordSearch=query)
    #barofprogress()
    #print("\n")
    if len(result) == 0:
        print (Fore.GREEN + "No CVEs found for " + query + "\n")
    else:
        for y in range(len(result)):
            print(Fore.RED + "CVE identified: " + str(result[y].id))
            CVE = str(result[y].id)
            cve_listing.write("\n" + CVE + " (" + x + "package)" + "\n")
            if str(result[y].score[2]) == "CRITICAL":
                print(Fore.LIGHTRED_EX + "Severity: " + str(result[y].score[2]))
            elif str(result[y].score[2]) == "HIGH":
                print(Fore.RED + "Severity: " + str(result[y].score[2]))
            elif str(result[y].score[2]) == "MEDIUM":
                print(Fore.YELLOW + "Severity: " + str(result[y].score[2]))
            else:
                print(Fore.WHITE + "Severity: " + str(result[y].score[2]))
            #print(Fore.WHITE + "Description: " + str(result[y].descriptions[0].value))
            print("Additional details can be found at: " + str(result[y].url))
            if arguments.exploitcheck == True:
                print(Fore.WHITE + "\nChecking for CVE exploits in searchsploit...")
                exploit_search = CS.edbid_from_cve(str(CVE))
                print(exploit_search)
                #for result in exploit_search:
                 #   if "exploit-db.com/exploits" in result:
                  #      print(Fore.YELLOW + "Potential CVE exploits identified, URLs below:")
                   #     print(result)
                    #    cve_listing.write("Exploit-DB Potential Exploits:\n")
                     #   cve_listing.write(result + "\n")
                #print(Fore.WHITE + "\nChecking for CVE exploits on GitHub...")
                #barofprogress()
                #github_search = search(str(CVE) + "exploit site:https://www.github.com", stop=10)
                #for result in github_search:
                 #   if "www.github.com" in result:
                  #      print(Fore.YELLOW + "Potential CVE exploits found, URLs below:")
                   #     print(result)
                    #    cve_listing.write("GitHub Potential Exploits:\n")
                     #   cve_listing.write(result + "\n")
            print("===================================================================\n")

#Loading the JSON object and generating the dictionaries of data
#data_output_file = open("componentsandversions.txt", "a")

if arguments.jsonfile is not None:
    art()
    json_data = json.load(arguments.jsonfile[0])
    for component in json_data['components']:
        name = str({component['name']})
        name_formatted = name[2:-2]
        version = str({component['version']})
        version_formatted = version[2:-2]
        print(Fore.WHITE + "Querying component name: " + Fore.GREEN + name_formatted + " | " + Fore.WHITE + "version: " + Fore.GREEN + version_formatted)
        print(Fore.WHITE + "===================================================================")
        #data_output_file.write(f"Component name: {component['name']} | version: {component['version']}\n")
        NVD_search(name_formatted,version_formatted)


if arguments.txtfile is not None:
    art()
    txt_data = (arguments.txtfile[0])
    txt_file = open(txt_data, 'r')
    for line in txt_file.readlines():
        name = line.split("@")[0]
        version = line.split("@")[1]
        print(Fore.WHITE + "Searching NVD for vulnerabilities related to: " + Fore.GREEN + name + Fore.WHITE + " version: " + Fore.GREEN + version)
        ##NVD_search(line)

if arguments.xmlfile is not None:
    art()
    xml_file = (arguments.xmlfile[0])
    tree = ET.parse(xml_file)
    root = tree.getroot()
    component_names = []
    for x in root[1]:
        value = x.get('bom-ref')
        #print(value)
        formatted_value1 = value.split("@")[0]
        comp_name = formatted_value1.split("/")[1]
        version_number = value.split("@")[1]
        if "%" in comp_name:
            print(Fore.YELLOW + "Component name may be erroneous, double check original document: " + comp_name + " | " + "version: " + version_number)
        else:
            print(Fore.WHITE + "Component name: " + Fore.GREEN + comp_name + " | " + Fore.WHITE + "version: " + Fore.GREEN + version_number)
            print(Fore.WHITE + "===================================================================")
            #data_output_file.write("Component name: " + comp_name + " | " + "version: " + version_number)
            NVD_search(comp_name,version_number)

#data_output_file.close()

