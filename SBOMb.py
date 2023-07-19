import json
import argparse
import nvdlib
import colorama
from colorama import Fore
import xml.etree.ElementTree as ET


parser = argparse.ArgumentParser(description='SBOMb.py is a tool built to easily parse files that are a part of the CycloneDX SBOM format (JSON or XML) as well as take user-generated txt files that meet specific formatting requirements. SBOM.py will then query the NVD and see if any of the packages listed in the SBOM files are predisposed to documented vulnerabilities. Please reference the included \'dependencies.txt\' to understand how to format txt files for this program.')
parser.add_argument('--jsonfilepath', nargs=1, help="Path to JSON file from SBOM to be parsed", dest='jsonfile', type=argparse.FileType('r', encoding="utf8"))
parser.add_argument('--txtfilepath', nargs=1, help="Path to txt file with SBOM dependency names", dest='txtfile', type=str)
parser.add_argument('--xmlfilepath', nargs=1, help="Path to XML file from SBOM to be parsed", dest='xmlfile', type=argparse.FileType('r', encoding="utf8"))
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

if arguments.jsonfile is not None:
    json_data = json.load(arguments.jsonfile[0])
    for component in json_data['components']:
        name = str({component['name']})
        name_formatted = name[2:-2]
        version = str({component['version']})
        version_formatted = version[2:-2]
        print(Fore.WHITE + "Component name: " + Fore.GREEN + name_formatted + " | " + Fore.WHITE + "version: " + Fore.GREEN + version_formatted)
        #data_output_file.write(f"Component name: {component['name']} | version: {component['version']}\n")
        #CVE_search = nvdlib.searchCVE(keywordSearch=component['name'])
        #print(CVE_search)


if arguments.txtfile is not None:
    txt_data = (arguments.txtfile[0])
    txt_file = open(txt_data, 'r')
    for line in txt_file.readlines():
        name = line.split("@")[0]
        version = line.split("@")[1]
        print(Fore.WHITE + "Searching NVD for vulnerabilities related to: " + Fore.GREEN + name + Fore.WHITE + " version: " + Fore.GREEN + version)
        #CVE_search = nvdlib.searchCVE(keywordSearch=line)
        #print(CVE_search)

if arguments.xmlfile is not None:
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
            #data_output_file.write("Component name: " + comp_name + " | " + "version: " + version_number)
            #CVE_search = nvdlib.searchCVE(keywordSearch=comp_name)
            #print(CVE_search)

#data_output_file.close()