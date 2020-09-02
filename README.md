# XRAY
SAST Tool for any coding language  
  
To use it, execute:  
`python main.py ./route/to/source/code`  
  
It will drop a file named by timestamp.json. For example 152484.48754.json  
  
To view detected vulnerabilities, use search.py:  
`python search.py timestamp.json`  
  
You can blacklist vulnerabilities to view by file extension adding or removing theme in the 5th line of the search.py file.  
Default filter  --->  `EXCLUDED_EXTENSIONS = ['xml', 'ftl', 'js', 'map']`
