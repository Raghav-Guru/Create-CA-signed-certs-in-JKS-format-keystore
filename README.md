# Create-CA-signed-certs-in-JKS-format-keystore
This script take the input from input.ini to create JKS keystore signed by rootCA

To use the script: 

#git clone https://github.com/Raghav-Guru/Create-CA-signed-certs-in-JKS-format-keystore.git
#cd Create-CA-signed-certs-in-JKS-format-keystore

-->Modify the input.ini as per the requirement.

-->Set the keytool path based on your environment: 
#export PATH=$PATH:/usr/jdk64/jdk1.8.0_112/bin/

-->Execute the python script to create host specific keystore and truststore with root ca. 
#python ca_keystore_create.py
