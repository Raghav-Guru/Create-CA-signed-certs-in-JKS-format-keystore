import ConfigParser
import os

config = ConfigParser.ConfigParser()
config.read("input.ini")
password = config.get('security','keystore_password')
ca_dn = config.get('security','ca_dn')
hostnames =  config.get('general','hostnames')
genkey_cmd="keytool -genkeypair -v -alias rootca -dname %s -keystore rootca.jks -keypass %s -storepass %s -keyalg RSA -keysize 4096 -ext KeyUsage:critical=\"keyCertSign\" -ext BasicConstraints:critical=\"ca:true\" -validity 9999" % (ca_dn, password, password)
os.popen(genkey_cmd)
export_ca="keytool -export -v -alias rootca -file rootca.crt -keypass %s -storepass %s -keystore rootca.jks -rfc" % (password,password)
os.popen(export_ca)
csv_hosts=config.get('general','hostnames')
csv_h=csv_hosts.split(",")
for i in range(len(csv_h)):
  host=csv_h[i]
  cmd_cert="keytool -genkeypair -v -alias %s -dname \"CN=%s, OU=Support, O=HWX, L=Durham, ST=North Carolina, C=US\" -keystore %s.jks -keypass %s -storepass %s -keyalg RSA -keysize 2048 -validity 385 "% (host,host,host,password,password)
  os.popen(cmd_cert)
  cmd_csr="keytool -certreq -v -alias %s -keypass %s -storepass %s -keystore %s.jks -file %s.csr" % (host,password,password,host,host)
  os.popen(cmd_csr)
  cmd_crt="keytool -gencert -v -alias rootca -keypass %s -storepass %s -keystore rootca.jks -infile %s.csr -outfile %s.crt -ext KeyUsage:critical=\"digitalSignature,keyEncipherment\" -ext EKU=\"serverAuth\" -ext SAN=\"DNS:%s\" -rfc" % (password,password,host,host,host)
  os.popen(cmd_crt)
  cmd_keystore_sign="keytool -import -v -alias %s -file %s.crt -keystore %s.jks -storetype JKS -storepass %s" % (host,host,host,password)
  cmd_trust="keytool -import -v -alias rootca -file rootca.crt -keystore %s.jks -storetype JKS -storepass %s -noprompt" % (host,password)
  os.popen(cmd_trust)
  os.popen(cmd_keystore_sign)
