#!/usr/bin/python

import boto3
import re
import time
import csv
import argparse

##	Defining arguments

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
parser.add_argument('-n', '--nonreport', help='If is checked no report will be generated', action='store_true')
args = parser.parse_args()

##	Creating AWS clients and resources

client_s3 = boto3.client('s3')
s3 = boto3.resource('s3')

##	Creating regex

patron_exclusion_files = re.compile(r'([\w](.ZIP|.RAR|.7Z|.TAR|.GZ|.DOC|.XLS|.PPT)$)')
patron_name_key = re.compile(r'(USUARIO|USER|PASSWORD|CLIENTE|NOMINA|CONTRASENA|CREDENCIAL|DNI|CONFIDENCIAL|SECRET|INTERNO|KEY|CONTRATO)')

timestamp = str(time.time())
timestamp = timestamp[:(len(timestamp))-3]

##      Initializing CSV

if(args.nonreport is False):
	myData = [['object','object_name','object_key','id','title','details','risk','confidence']]
	myFile = open('Scan_Results_' + timestamp + '.csv', 'w')
	with myFile:
		writer = csv.writer(myFile)
		writer.writerows(myData)

##	Creating variables

inf_vuln = 0
low_vuln = 0
med_vuln = 0
hig_vuln = 0

inf_list = []
low_list = []
med_list = []
hig_list = []

sus_list = []


##	Defining addional functions

def write_vuln(object, object_name, object_key, id, title, details, risk, confidence):
	global inf_vuln
	global inf_list
	global low_vuln
	global low_list
	global med_vuln
	global med_list
	global hig_vuln
	global hig_list
	if(object == 's3'):
		if(risk == 'INFO'):
			inf_vuln = inf_vuln + 1
			inf_list.append(details)
		if(risk == 'LOW'):
			low_vuln = low_vuln + 1
			low_list.append(details)
		if(risk == 'MEDIUM'):
			med_vuln = med_vuln + 1
			med_list.append(details)
		if(risk == 'HIGH'):
			hig_vuln = hig_vuln + 1
			hig_list.append(details)
	if(args.nonreport is False):
		myData = [[object,object_name,object_key,id,title,details,risk,confidence]]
		myFile = open('Scan_Results_' + timestamp + '.csv', 'a')
		with myFile:
			writer = csv.writer(myFile)
			writer.writerows(myData)

def s3_sensitive_checker(bucket):
	global cont_sus
	global sus_list

	bucket_s3 = s3.Bucket(bucket)
	cont_sus = 0
	for objeto in bucket_s3.objects.all():
		key = objeto.key
		key_mayus = key.upper()
		
		# Check if the file has a suspicius content based on its name:
		s = patron_name_key.search(key_mayus)
		if(s):
			if(args.verbose):
				print('\t [-] Suspicius name file: ' + key)
			sus_list.append('BUCKET: ' + bucket + '\tSUSPICIUS NAME FILE: ' + key)
			cont_sus = cont_sus + 1
			write_vuln('s3',bucket,key,'VS1','Suspicius name file in S3','INFO - Suspicius name file detected:  BUCKET: ' + bucket + '  FILE: ' + key, 'INFO','Low')
                s = patron_exclusion_files.search(key_mayus)
                if not s:
			#try:
			#body = objeto.get()['Body'].read()
			#except:
			#       continue
			#body_mayus = body.upper()
			continue
        if((cont_sus == 0) and args.verbose):
                print('\t [+] Not suspicius name file detected')


def show_risks():
	print('[+] TOTAL risks found:\t\t' + str(inf_vuln+low_vuln+med_vuln+hig_vuln))
	print('\t[-] INFO risks found:\t' + str(inf_vuln))
	print('\t[-] LOW risks found:\t' + str(low_vuln))
	print('\t[-] MEDIUM risks found:\t' + str(med_vuln))
	print('\t[-] HIGH risks found:\t' + str(hig_vuln))
	print('[+] Detailed results:')
	print('\t[-] INFO risks found:\t' + str(inf_vuln))
	if(inf_vuln > 0):
        	for vulnerability in inf_list:
                	print('\t\t[-] ' + vulnerability)
	print('\t[-] LOW risks found:\t' + str(low_vuln))
	if(low_vuln > 0):
        	for vulnerability in low_list:
                	print('\t\t[-] ' + vulnerability)
	print('\t[-] MEDIUM risks found:\t' + str(med_vuln))
	if(med_vuln > 0):
        	for vulnerability in med_list:
                	print('\t\t[-] ' + vulnerability)
	print('\t[-] HIGH risks found:\t' + str(hig_vuln))
	if(hig_vuln > 0):
        	for vulnerability in hig_list:
                	print('\t\t[-] ' + vulnerability)
	print('')

## __MAIN__

response_all = client_s3.list_buckets()

print('')
print('[+] Sensitive Data Checker v0.1 (alpha) by Alvaro Trigo')
print('[+] Starting analysis at ' + time.strftime('%c'))
for bucket in response_all['Buckets']:
	print('[+] Analyzing bucket ' + bucket['Name'] + '...')
	s3_sensitive_checker(bucket['Name'])
print('[+] Analysis finished at ' + time.strftime('%c'))
show_risks()