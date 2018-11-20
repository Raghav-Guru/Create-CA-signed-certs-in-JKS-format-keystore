import ConfigParser
import os

config = ConfigParser.ConfigParser()
config.read("input.ini")
password = config.get('ca','keystore_password')
ca_dn = config.get('ca','ca_dn')
hostnames =  config.get('server_certs','hostnames')
csv_hosts = config.get('server_certs', 'hostnames')
csv_h = csv_hosts.split(",")
format_pkcs12=config.get('cert_format','pkcs12')
format_pkcs7=config.get('cert_format','pkcs7')


'''def java(classname, args, classpath, jvm_opts_list, logdir=None):
  java_home = os.environ.get("JAVA_HOME", None)
  if java_home:
    prg = os.path.join(java_home, "bin", "java")
  else:
    prg = which("java")'''


def keystore_create(host):

  genkey_cmd="keytool -genkeypair -v -alias rootca -dname {0} -keystore rootca.jks -keypass {1} -storepass {1} -keyalg RSA -keysize 4096 -ext KeyUsage:critical=\"keyCertSign\" -ext BasicConstraints:critical=\"ca:true\" -validity 9999".format(ca_dn, password)

  print("====Creating RootCA with DN: %s===="%(ca_dn))
  os.popen(genkey_cmd)

  export_ca="keytool -export -v -alias rootca -file rootca.crt -keypass {0} -storepass {0} -keystore rootca.jks -rfc".format(password)
  os.popen(export_ca)

  #for i in range(len(csv_h)):
  #  host=csv_h[i]
  print("====Creating keystore for the host : %s====" % (host))
  cmd_cert="keytool -genkeypair -v -alias {0} -dname \"CN={0}, OU=Support, O=HWX, L=Durham, ST=North Carolina, C=US\" -keystore {0}.jks -keypass {1} -storepass {1} -keyalg RSA -keysize 2048 -validity 385".format(host,password)
  cmd_csr="keytool -certreq -v -alias {0} -keypass {1} -storepass {1} -keystore {0}.jks -file {0}.csr".format(host,password)
  cmd_crt="keytool -gencert -v -alias rootca -keypass {1} -storepass {1} -keystore rootca.jks -infile {0}.csr -outfile {0}.crt -ext KeyUsage:critical=\"digitalSignature,keyEncipherment\" -ext EKU=\"serverAuth,clientAuth\" -ext SAN=\"DNS:{0}\" -rfc".format(host,password)
  cmd_keystore_sign="keytool -import -v -alias {0} -file {0}.crt -keystore {0}.jks -storetype JKS -storepass {1}".format(host,password)
  cmd_trust="keytool -import -v -alias rootca -file rootca.crt -keystore {0}.jks -storetype JKS -storepass {1} -noprompt".format(host,password)
  os.popen(cmd_cert)
  os.popen(cmd_csr)
  os.popen(cmd_crt)
  os.popen(cmd_trust)
  os.popen(cmd_keystore_sign)

def convert_pkcs12(host):
  #for i in range(len(csv_h)):
  #  host=csv_h[i]
    print("====Converting to PKCS12 format====")
    convert_cmd_pkcs12="keytool -importkeystore -destkeystore {0}.p12 -deststoretype PKCS12 -destalias {0} -deststorepass tender12 -destkeypass tender12 -srcstoretype JKS  -srcalias {0}  -srckeystore {0}.jks -srcstorepass {1} -srckeypass {1}  -noprompt".format(host,password)
    os.popen(convert_cmd_pkcs12)

def convert_pem(host):
  print("===Converting to PEM format===")
  #for i in range(len(csv_h)):
  #  host=csv_h[i]
  convert_cmd_pem="openssl pkcs12 -in {0}.p12 -out {0}.pem -nodes -password pass:{1}".format(host,password)
  os.popen(convert_cmd_pem)

def convert_pkcs7(host):

    print("===Converting to PEM format===")
    #for i in range(len(csv_h)):
    #  host = csv_h[i]
    convert_cmd_pkcs7="openssl crl2pkcs7 -nocrl -certfile {0}.pem -out {0}.p7b".format(host)
    os.popen(convert_cmd_pkcs7)


def main():
  for i in range(len(csv_h)):
    host = csv_h[i]
    keystore_create(host)
    if format_pkcs12:
      convert_pkcs12(host)

    if format_pkcs7:
      convert_pkcs12(host)
      convert_pem(host)
      convert_pkcs7(host)



main()
