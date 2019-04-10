import logging
import boto3
import re

### Defining global variables

names = ['ABEL', 'ALVARO','BELEN','CARMEN','DAVID','FRANCISCO','MANOLO','MARIA','PABLO','SANTIAGO','UBALDO']
passwords = ['PASSWORD','CONTRASENA','SECRET']
log = logging.getLogger('DLP_Process')

def lambda_handler(event, context):
    bucket_key = event['Records'][0]['s3']['object']['key']
    file_etag = event['Records'][0]['s3']['object']['eTag']
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    log.info(bucket_key)
    
    find_sensitive_data(bucket_key, bucket_name, file_etag)

def find_sensitive_data(bucket_key,bucket_name, file_etag):
    
    ### Defining local variables
    
    cont_name = 'false'
    cont_pass = 'false'
    cont_dni = 'false'
    cont_mat = 'false'
    cont_nie = 'false'
    try:
        s3 = boto3.resource('s3')
        file = s3.Object(bucket_name, bucket_key)
        key = file.key
        body = file.get()['Body'].read().decode('utf-8')
        body_mayus = body.upper()
        print('   [+] ' + key)
    except:
        print('   [-] Something wrong with ' + key)
    

    try:
        # Checking personal names
        
        for name in names:
            if body_mayus.find(name) !=  -1:
                cont_name = 'true'
    
        # Checking presence of possible passwords
    
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
    
        #print(body)
    
        print('      [*] Names detected:             ' + cont_name)
        print('      [*] DNIs detected:              ' + cont_dni)
        print('      [*] NIEs detected:              ' + cont_nie)
        print('      [*] Car plates detected:        ' + cont_mat)
        print('      [*] Word \"password\" detected:   ' + cont_pass)
    
    except:
        print('      [-] Generic error')