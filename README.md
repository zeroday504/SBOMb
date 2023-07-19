# SBOMb

SBOMb.py is a tool built to easily parse files that are a part of the CycloneDX SBOM format (JSON or XML) as well as take   
user-generated txt files that meet specific formatting requirements.

SBOM.py will then query the NVD and see if any of the packages listed in the SBOM files are predisposed to documented vulnerabilities. Please reference the included
`dependencies.txt` to understand how to format txt files for this program.

The `bom.xml` and `bom.json` files are simple test files included for running the program and understanding what output should look like. These files are the SBOMs for OWASP's Juice Shop.

```
    ___  ___   _   _   __             
  ,' _/ / o.),' \ / \,' //7     _ _ __
 _\ `. / o \/ o |/ \,' //o\    /o|\V /
/___,'/___,'|_,'/_/ /_//_,'() /_,' )/
                             //   //
usage: SBOMb.py [-h] [--jsonfilepath JSONFILE] [--txtfilepath TXTFILE] [--xmlfilepath XMLFILE]

optional arguments:
  -h, --help            show this help message and exit
  --jsonfilepath JSONFILE
                        Path to JSON file from SBOM to be parsed
  --txtfilepath TXTFILE
                        Path to txt file with SBOM dependency names
  --xmlfilepath XMLFILE
                        Path to XML file from SBOM to be parsed
```

# Why SBOMb?
For several years, SBOMs have been implemented as a requirement in order to hold software developers accountable for the risks that come with using vulnerable code libraries. This tool is a "purple team tool," ideal for both performing risk assessments and mitigating vulnerabilities as well as enumerating target programs and identifying exploit opportunities.

Some cyber-focused organizations have developed intricate threat dashboards that do a lot of this work and present it in an eye-catching graphical display, but the developers behind SBOMb understand that not everyone has a budget that allows for purchasing that insight. We hope to continue building on SBOMb so that it provides additional value at minimal cost.
