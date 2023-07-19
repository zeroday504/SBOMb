import json
import argparse
import nvdlib
import colorama
from colorama import Fore


parser = argparse.ArgumentParser()
parser.add_argument('--jsonfilepath', nargs=1, help="Path to JSON file from SBOM to be parsed", dest='file', type=argparse.FileType('r', encoding="utf8"))
parser.add_argument('--txtfilepath', nargs=1, help="Path to txt file with SBOM dependency names", dest='txtfile', type=str)
arguments = parser.parse_args()

#ASCII Art
print("    ___  ___   _   _   __             ")
print("  ,' _/ / o.),' \ / \,' //7     _ _ __")
print(" _\ `. / o \/ o |/ \,' //o\    /o|\V /")
print("/___,'/___,'|_,'/_/ /_//_,'() /_,' )/") 
print("                             //   //")
print('==========================================================')
print("Keeping your software safe from going BOOM post-production")
print('==========================================================\n')

#Loading the JSON object and generating the dictionaries of data
#data_output_file = open("componentsandversions.txt", "a")

if arguments.file is not None:
    json_data = json.load(arguments.file[0])
    for component in json_data['components']:
        print(f"Component name: {component['name']} | version: {component['version']}")
        #data_output_file.write(f"Component name: {component['name']} | version: {component['version']}\n")
        #CVE_search = nvdlib.searchCVE(keywordSearch=component['name'])
        #print(CVE_search)
#data_output_file.close()

if arguments.txtfile is not None:
    txt_data = (arguments.txtfile[0])
    txt_file = open(txt_data, 'r')
    for line in txt_file.readlines():
        print("Searching NVD for vulnerabilities related to: " + Fore.GREEN + line + Fore.WHITE + " package/dependency")
        #CVE_search = nvdlib.searchCVE(keywordSearch=line)

    




