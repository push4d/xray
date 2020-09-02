#!/usr/bin/env python3
import json, sys, os

# Exclusion list for file extensions
EXCLUDED_EXTENSIONS = ['xml', 'ftl', 'js', 'map']

def showVulnerabilityTypes(vulnerabilities):
	'''
	This function returns the type of vulnerabilities found.
	
	Parameters:
	- vulnerabilities   : JSON Array of vulnerabilities

	Returns an Array with the vulnerability types
	'''

	# Empty Array that will contain the type of vulnerabilities
	types = []
	# Iterate through the JSON Array to gather the different types
	for vulnerability in vulnerabilities:
		# If the type of vulnerability is not inside the "types" array, append it
		if not vulnerability['title'] in types:
			types.append(vulnerability['title'])
	# Return the array with the vulnerability types
	return types

def showVulnerabilities(vulnerabilities, title):
	'''
	This function prints vulnerabilities in console.
	
	Parameters:
	- vulnerabilities   : JSON Array of vulnerabilities
	- title             : Type of the vulnerability
	- EXCLUDED_EXTENSIONS: Exclusion list of file extensions
	'''
	# Get every vulnerability from the vulnerabilities array
	for vulnerability in vulnerabilities:
		# Check if the type of the vulnerability is the one specified to show, and if its file extension
		# is not in the exclusion list
		if vulnerability['title'] == title and (
			len(vulnerability['file'].split('.')) > 1 and not vulnerability['file'].split('.')[-1] in EXCLUDED_EXTENSIONS
		):
			# Show the vulnerability
			print(
				f"Archivo: {vulnerability['file']}\n" +
				f"Linea  : {str(vulnerability['line_num'])}\n" +
				f"{vulnerability['line']}\n"
			)


def main():
	'''
	Main function of the program
	'''
	# Check if JSON file with vulnerabilities is passed as parameter
	if len(sys.argv) != 2:
		print(f"How to use: python {sys.argv[0]} vulnerabilities.json")
		exit(1)

	# Read file with the JSON Array of vulnerabilities
	vulnerabilities = json.loads(open(sys.argv[1]).read())

	# Different vulnerability types are filtered
	vulnerabilityTypes = showVulnerabilityTypes(vulnerabilities)

	while True:
		# Show vulnerability types
		print("\nTipos de vulnerabilidades:") 
		for i in range(len(vulnerabilityTypes)): print(f"{i}. {vulnerabilityTypes[i]}")

		# Show exclusion list
		if len(EXCLUDED_EXTENSIONS) > 0:
			print("\nLista de exclusion de extensiones de archivo:")
			for extension in EXCLUDED_EXTENSIONS: print(f"- {extension}")

		# Get user input to show the specified vulnerability type
		option = int(input("\nElige el tipo de vulnerabilidad a mostrar, o -1 si ya has terminado: "))
		
		# Exit the program if the user says so
		if option == -1:
			exit(0)

		# Show vulnerabilities
		os.system("cls")
		showVulnerabilities(vulnerabilities, vulnerabilityTypes[option])
		print("\n##########################################################################################################")

# Start program
main()