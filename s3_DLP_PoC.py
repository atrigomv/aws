#!/usr/bin/python

# Description: Data Loss Prevention proof of concept in S3 bucket. The script connect to S3 bucket, analyze all the objects storaged and rise a flag if a name,
# 'password' word, DNI, spanish car plate and/or NIE is detected. The script only works fine with flat files (txt, csv, json...etc). 

import boto3
import re

### Configuring environment

BUCKET_NAME='atrigomvtest'
names = ['ALVARO','BELEN','CARMEN','DAVID','FRANCISCO','MANOLO','MARIA','PABLO','SANTIAGO','UBALDO']
passwords = ['PASSWORD','CONTRASENA']

### Defining variables

cont_name = 0
cont_pass = 'false'
cont_dni = 'false'
cont_mat = 'false'
cont_nie = 'false'

### Configuring S3 resource

s3 = boto3.resource('s3')
bucket = s3.Bucket(BUCKET_NAME)

### Executing check

print('[+] ' + BUCKET_NAME + '.  Bucket creation date:' + str(bucket.creation_date))

try:
	for objeto in bucket.objects.all():
		try:
			key = objeto.key
			body = objeto.get()['Body'].read() # Muestra contenido
			body_mayus = body.upper()
			print('   [+] ' + key)
		except:
			print('   [-] Something wrong with ' + key)
			body_mayus=""
			body = ""

		# Checking personal names
	
		for name in names:
			#print body_mayus.find(name)
			if body_mayus.find(name) !=  -1:
				cont_name = cont_name + 1

		# Checking presence of 'password' word in the document

		for contrasena in passwords:
			if body_mayus.find(contrasena) != -1:
				cont_pass = 'true'
	
		# Checking DNIs

		dni = re.search(r'(?<![\w\d])([0-9]{8}[A-Za-z])(?![\w\d])', body)
		if dni:
			cont_dni = 'true'

		# Checking car plates

		matricula = re.search(r'(?<![\w\d])([0-9]{4,4}[A-Za-z]{3,3})(?![\w\d])', body)
        	if matricula:
                	cont_mat = 'true'

		# Checking NIEs

		nie = re.search(r'(?<![\w\d])([X-Zx-z]{1}[0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKET])(?![\w\d])', body)
        	if nie:
                	cont_nie = 'true'
	
		# Printing results

		print('      [*] Names detected:             ' + str(cont_name))
		print('      [*] DNIs detected:              ' + cont_dni)
		print('      [*] NIEs detected:              ' + cont_nie)
		print('      [*] Car plates detected:        ' + cont_mat)
		print('      [*] Word \"password\" detected:   ' + cont_pass)

		# Cleaning variables
		cont_name = 0
		cont_pass = 'false'
		cont_dni = 'false'
		cont_mat = 'false'
		cont_nie = 'false'
except:
	print('[-] Generic error')
