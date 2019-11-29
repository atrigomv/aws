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
parser.add_argument('-l', '--logs', help='Analyze logs files', action='store_true')
parser.add_argument('-c', '--content', help='Analyze the content of bucket files', action='store_true')
args = parser.parse_args()

##	Creating AWS clients and resources

client_s3 = boto3.client('s3')
s3 = boto3.resource('s3')

##	Creating regex

patron_exclusion_files = re.compile(r'([\w](.ZIP|.RAR|.7Z|.TAR|.GZ|.DOC|.XLS|.PPT)$)')
patron_keystore = re.compile(r'([\w](.KDBX|.HC|.KDB|.WALLETX)$)')
patron_name_key = re.compile(r'(USUARIO|USER|PASSWORD|CLIENTE|NOMINA|CONTRASENA|CREDENCIAL|DNI|CONFIDENCIAL|SECRET|INTERNO|KEY|CONTRATO|CREDENTIAL)')
patron_noname_key = re.compile(r'(LOG|CLOUDTRAIL)')

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

cont_s3 = 0
cont_s3_key = 0
cont_s3_key_skip = 0
bucket_acl = ''

names = ['abel','adolfo','aida','alba','alberto','alejandro','alex','alfonso','alfredo','alicia', 'almudena','alvaro','amaya','amparo','angel','anton','araceli','armando','barbara','beatriz','belen','benjamin','bernardo','borja','bruno','carlos','carmen','cecilia','celia','clara','claudia','claudio','cristina','cristobal','damian','dario','david','diego','edgar','eduardo','elena','elisa','eloy','elvira','emilia','emilio','emma','enrique','ernesto','esteban','ester','esther','eugenia','eugenio','eusebio','ezequiel','fabian','fabio','federico','felipe','felix','fermin','fidel','fernanda','fernando','flavio','francisca','francisco','gabriel','gaspar','gema','gemma','genoveva','georgina','gerardo','german','gilberto','gisela','gonzalo','guadalupe','guillermo','gustavo','hector','helena','ignacio','isaac','isidro','ismael','ivan','jacinto','jacob','jaime','javier','jesus','joaquin','jose','julian','laura','laureano','lazaro','leandro','leticia','lorena','loreto','lourdes','luis','macarena','marcelo','marcos','margarita','mariano','maria','mario','mateo','mauricio','mauro','melania','mercedes', 'jorge','juan','lucas','manuel','marta','matias','pablo','patricia','rodrigo','sandra','sofia','antonio','diana','estefania','gines','lucia','martin','miriam','moises','nadia','natalia','nazaret','nestor','nicasio','nieves','noelia','noemi','paula','zaira','olga','omar','oscar','paloma','pamela','pammela','pedro','peter','jonh','pilar','quique','rafael','raimundo','ramiro','raquel','raul','rebeca','reyes','ricardo','roman','rosa','ruben','sabrina','sagrario','salvador','samuel','santi','sebastian','severino','simon','tania','valentin','vanesa','vanessa','veronica','vicenta','vicente','victor','virginia','ximena','jimena','yolanda','zacarias','zulema','william','noah','joshua','michael','liam','alice','isabel','manolo']


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
	global cont_s3
	global cont_s3_key
	global cont_s3_key_skip
	global sus_list
	
	# No analyze buckets name with logs
	s = patron_noname_key.search(bucket.upper())
	if((not s) or (args.logs)):
		bucket_s3 = s3.Bucket(bucket)
		for objeto in bucket_s3.objects.all():
			cont_s3_key = cont_s3_key + 1
			key = objeto.key
			key_mayus = key.upper()
		
			# No analyze logs files
			s = patron_noname_key.search(key_mayus)
			if((not s) or (args.logs)):
			# Check for key store files
				s = patron_keystore.search(key_mayus)
				if(s):
					write_vuln('s3',bucket,key,'VS2','Key Store file detected','HIGH - Key Store file detected:  BUCKET: ' + bucket + '  FILE: ' + key, 'HIGH','Medium')
					if(args.verbose):
						print('\t [-] Key Store file detected: ' + key)
				else:
			# Check for suspicius file names
					s = patron_name_key.search(key_mayus)
					if(s):
						if(args.verbose):
							print('\t [-] Suspicius name file: ' + key)
						write_vuln('s3',bucket,key,'VS1','Suspicius name file in S3','INFO - Suspicius name file detected:  BUCKET: ' + bucket + '  FILE: ' + key, 'INFO','Low')
			# Some type files will not be analyzed
                			s = patron_exclusion_files.search(key_mayus)
                			if((not s) and (args.content)):
						#try:
						body = objeto.get()['Body'].read()
						#except:
						#	continue
						body_mayus = body.upper()
					## Detecting personal data in the content
						for name in names:
							if body_mayus.find(name.upper()) !=  -1:
								write_vuln('s3',bucket,key,'VS4','Personal data detected','HIGH - Personal data detected:  BUCKET: ' + bucket + '  FILE: ' + key + '  DATA: ' + name, 'HIGH','Medium')
								break
						#continue
			else:
				cont_s3_key_skip = cont_s3_key_skip + 1


def show_risks():
	print('[+] TOTAL risks found:\t\t' + str(inf_vuln+low_vuln+med_vuln+hig_vuln))
	print('\t[-] INFO risks found:\t' + str(inf_vuln))
	print('\t[-] LOW risks found:\t\t' + str(low_vuln))
	print('\t[-] MEDIUM risks found:\t' + str(med_vuln))
	print('\t[-] HIGH risks found:\t' + str(hig_vuln))
	print('[+] Detailed results:')
	print('\t[-] INFO risks found:\t' + str(inf_vuln))
	if(inf_vuln > 0):
        	for vulnerability in inf_list:
                	print('\t\t[-] ' + vulnerability)
	print('\t[-] LOW risks found:\t\t' + str(low_vuln))
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
	bucket_acl = ''
	cont_s3 = cont_s3 + 1
	print('[+] Analyzing bucket ' + bucket['Name'] + '...')
	response_acl = client_s3.get_bucket_acl(Bucket=bucket['Name'])
	for grants in response_acl['Grants']:
		if(grants['Grantee']['Type']=='Group'):
			if(grants['Grantee']['URI']=='http://acs.amazonaws.com/groups/global/AllUsers'):
				bucket_acl = bucket_acl + grants['Permission'] + ','
	if(bucket_acl != ''):
		write_vuln('s3',bucket['Name'],'<no_key>','VS3','Bucket with public permissions','HIGH - Bucket with public permissions:  BUCKET: ' + bucket['Name'] + '  PERMISSIONS: ' + bucket_acl[:(len(bucket_acl)-1)], 'HIGH','High')
		if(args.verbose):
			print('\t [-] Bucket with public permissions:  BUCKET: ' + bucket['Name'] + '  PERMISSIONS: ' + bucket_acl[:(len(bucket_acl)-1)])
	s3_sensitive_checker(bucket['Name'])
print('[+] Analysis finished at ' + time.strftime('%c'))
print('[+] ' + str(cont_s3) + ' buckets and ' + str(cont_s3_key) + ' files analyzed (' + str(cont_s3_key_skip) + ' skipped)')
show_risks()