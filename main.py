#!/usr/bin/env python3
import sys, time, re, os, json

# Global variables
global_patterns = []
def load_global_patterns():
	'''

	'''
	for base, dirs, files in os.walk(f'{sys.argv[0]}/../patterns/'):
		for file in files:
			# Append the vulnerabilities of the project's file into the JSON Array of vulnerabilities of the project
			global_patterns.append(
				json.loads(
					open(f'{base}/{file}').read()
				)
			)



def scanLine(line, g_patterns_index):
	'''

	'''
	# JSON Array with the vulnerabilities of the Project's File
	vulnerability = {}

	for i in g_patterns_index:
		for pattern in global_patterns[i]['patterns']:
			for regex in pattern['pattern']:
				if re.search(regex, line):
					vulnerability = pattern.copy()
					del vulnerability['pattern']
					return vulnerability

	# Return the vulnerabilities of the Project's File
	return vulnerability



def scanFile(project_file):
	'''

	'''
	# JSON Array with the vulnerabilities of the Project's File
	vulnerabilities  = []

	# Index number of JSONs in global_patterns that can analyze the file using its extension to indentify the language
	g_patterns_index = []
	
	# Add index number of JSONs with the detected language
	for i in range(len(global_patterns)):
		for extension in global_patterns[i]['extensions']:
			if project_file.endswith(extension):
				g_patterns_index.append(i)
				break

	# If language is not supported return no vulnerabilities
	if g_patterns_index == []:
		return vulnerabilities

	# Try without raising exceptions so if the code reaches a binary file it doesnt crash
	try:
		# Read line by line
		line_num = 0
		for line in open(project_file, 'r'):
			line_num += 1
			# Get the vulnerability JSON Object of this specific line
			vulnerability = scanLine(line, g_patterns_index)
			# If the vulnerability JSON Object of the line is not empty, add it to the JSON Array
			if vulnerability != {}:
				vulnerability['file']     = project_file
				vulnerability['line']     = line.strip()
				vulnerability['line_num'] = line_num
				vulnerabilities.append(vulnerability)
	except:
		a=None
	# Return the vulnerabilities of the Project's File
	return vulnerabilities



def scanProject(project_path):
	'''

	'''
	# JSON Array with the vulnerabilities
	vulnerabilities = []

	# Get every file of the Project's Path
	for base, dirs, files in os.walk(project_path):
		for file in files:
			# Append the vulnerabilities of the project's file into the JSON Array of vulnerabilities of the project
			vulnerabilities += scanFile(f'{base}/{file}')

	# Return all the vulnerabilities
	return vulnerabilities



def showVulns(vulns):
	for vuln in vulns:
		#print(f"{vuln['line_num']}: {vuln['file']}\n{vuln['line']}\n\n\n")
		print(f"{vuln['title']}\n{vuln['line_num']} : {vuln['file']}\n{vuln['line']}\n\n\n")
		#print(vuln['line'])


def saveFile(vulnerabilities):
	filename_results = str(time.time())
	with open(f"{filename_results}.json", 'w') as f:
		f.write('[')

		for obj in vulnerabilities[:-1]:
			json.dump(obj, f)
			f.write(',')

		json.dump(vulnerabilities[-1], f)
		f.write(']')


def main():
	'''

	'''
	# If the path hasn't been provided as parameter, exit the scanner
	if len(sys.argv) != 2:
		exit(1)

	# Load patterns files
	load_global_patterns()

	# Project's path
	project_path = sys.argv[1]
	if os.path.exists(project_path):
		# Vulnerabilities found in the project
		vulnerabilities = scanProject(project_path)

		# Save the JSON of the vulnerabilities in a JSON file with the filename as the current timestamp returned by python
		#saveFile(vulnerabilities)

		# Show vulnerabilities
		showVulns(vulnerabilities)

		# Exit without errors
		exit(0)
	else:
		exit(1)


main()
