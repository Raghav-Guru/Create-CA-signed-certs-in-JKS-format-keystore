import ConfigParser
import os

config = ConfigParser.ConfigParser()
config.read("input.ini")
password = config.get('ca','keystore_password')
ca_dn = config.get('ca','ca_dn')
hostnames =  config.get('server_certs','hostnames')

genkey_cmd="keytool -genkeypair -v -alias rootca -dname {0} -keystore rootca.jks -keypass {1} -storepass {1} -keyalg RSA -keysize 4096 -ext KeyUsage:critical=\"keyCertSign\" -ext BasicConstraints:critical=\"ca:true\" -validity 9999".format(ca_dn, password)

print("Creating RootCA with DN: %s"%(ca_dn))
os.popen(genkey_cmd)

export_ca="keytool -export -v -alias rootca -file rootca.crt -keypass {0} -storepass {0} -keystore rootca.jks -rfc".format(password)
os.popen(export_ca)
csv_hosts=config.get('server_certs','hostnames')
csv_h=csv_hosts.split(",")
for i in range(len(csv_h)):
  host=csv_h[i]
  print("Creating keystore for the host : %s" % (host))
  cmd_cert="keytool -genkeypair -v -alias {0} -dname \"CN={0}, OU=Support, O=HWX, L=Durham, ST=North Carolina, C=US\" -keystore {0}.jks -keypass {1} -storepass {1} -keyalg RSA -keysize 2048 -validity 385".format(host,password)
  cmd_csr="keytool -certreq -v -alias {0} -keypass {1} -storepass {1} -keystore {0}.jks -file {0}.csr".format(host,password)
  cmd_crt="keytool -gencert -v -alias rootca -keypass {1} -storepass {1} -keystore rootca.jks -infile {0}.csr -outfile {0}.crt -ext KeyUsage:critical=\"digitalSignature,keyEncipherment\" -ext EKU=\"serverAuth\" -ext SAN=\"DNS:{0}\" -rfc".format(host,password)
  cmd_keystore_sign="keytool -import -v -alias {0} -file {0}.crt -keystore {0}.jks -storetype JKS -storepass {1}".format(host,password)
  cmd_trust="keytool -import -v -alias rootca -file rootca.crt -keystore {0}.jks -storetype JKS -storepass {1} -noprompt".format(host,password)
  os.popen(cmd_cert)
  os.popen(cmd_csr)
  os.popen(cmd_crt)
  os.popen(cmd_trust)
  os.popen(cmd_keystore_sign)
