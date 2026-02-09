## Overview:
Automating the process of extracting files from a mobile device (Android and iOS). THis tool will enumerate package names if needed, identify the data/storage directories and download them to your local device. The output will include a `DB_files.txt` and `plist_files.txt` for those files identified during extraction.  

## Install:
This tool relies on libmagic for when searching for specific file types. The import within the Python script is a pointer to the library but does not actuially install the binary onto the system. Install of the binary is different based on the OS you are using.  

Mac: `brew install libmagic`  
Linux:  `sudo apt-get install libmagic1`  or  `sudo yum install file-libs`  
Windows: `pip install python-magic-bin`

Install the python library requirements:  
`pip install -r requirements.txt`
    
## Config:
The script uses a config.ini for storing default parameters when connecting to an iOS device over SSH. The values within the config file can be overridden by command line options. Make sure the config.ini is in the same directory as the Python script.

## Usage:
`python3 mobile_extractor.py`
The script has been designed to be interactive for choosing the OS, connection details, and output directory. Just follow the prompts!