# decode Firefox passwords (https://github.com/lclevy/firepwd)
# lclevy@free.fr (28 Aug 2013: initial version, Oct 2016: support for logins.json, Feb 2018: support for key4.db)
# for educational purpose only, not production level
# now integrated into https://github.com/AlessandroZ/LaZagne
# tested with python 2.7
# key3.db is read directly, the 3rd party bsddb python module is NOT needed
# NSS library is NOT needed

from struct import unpack
import sys
from binascii import hexlify, unhexlify 
import sqlite3
from base64 import b64decode
#https://pypi.python.org/pypi/pyasn1/
from pyasn1.codec.der import decoder
from hashlib import sha1
import hmac
from Crypto.Cipher import DES3
from Crypto.Util.number import long_to_bytes   
from optparse import OptionParser
import json
   
def getShortLE(d, a):
   return unpack('<H',(d)[a:a+2])[0]

def getLongBE(d, a):
   return unpack('>L',(d)[a:a+4])[0]

#minimal 'ASN1 to string' function for displaying Key3.db contents
asn1Types = { 0x30: 'SEQUENCE',  4:'OCTETSTRING', 6:'OBJECTIDENTIFIER', 2: 'INTEGER', 5:'NULL' }   
oidValues = { '2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3',
              '2a864886f70d0307':'1.2.840.113549.3.7',
              '2a864886f70d010101':'1.2.840.113549.1.1.1' }   
              
def printASN1(d, l, rl):
   type = ord(d[0])
   length = ord(d[1])
   if length&0x80 > 0: #http://luca.ntop.org/Teaching/Appunti/asn1.html,
     nByteLength = length&0x7f
     length = ord(d[2])  
     #Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets. 
     skip=1
   else:
     skip=0    
   #print '%x:%x' % ( type, length )
   print '  '*rl, asn1Types[ type ],
   if type==0x30:
     print '{'
     seqLen = length
     readLen = 0
     while seqLen>0:
       #print seqLen, hexlify(d[2+readLen:])
       len2 = printASN1(d[2+skip+readLen:], seqLen, rl+1)
       #print 'l2=%x' % len2
       seqLen = seqLen - len2
       readLen = readLen + len2
     print '  '*rl,'}'
     return length+2
   elif type==6: #OID
     print oidValues[ hexlify(d[2:2+length]) ]
     return length+2
   elif type==4: #OCTETSTRING
     print hexlify( d[2:2+length] )
     return length+2
   elif type==5: #NULL
     print 0
     return length+2
   elif type==2: #INTEGER
     print hexlify( d[2:2+length] )
     return length+2
   else:
     if length==l-2:
       printASN1( d[2:], length, rl+1)
       return length   

#extract records from a BSD DB 1.85, hash mode  
#obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used     
def readBsddb(name):   
  f = open(name,'rb')
  #http://download.oracle.com/berkeley-db/db.1.85.tar.gz
  header = f.read(4*15)
  magic = getLongBE(header,0)
  if magic != 0x61561:
    print 'bad magic number'
    sys.exit()
  version = getLongBE(header,4)
  if version !=2:
    print 'bad version, !=2 (1.85)'
    sys.exit()
  pagesize = getLongBE(header,12)
  nkeys = getLongBE(header,0x38) 
  if options.verbose>1:
    print 'pagesize=0x%x' % pagesize
    print 'nkeys=%d' % nkeys

  readkeys = 0
  page = 1
  nval = 0
  val = 1
  db1 = []
  while (readkeys < nkeys):
    f.seek(pagesize*page)
    offsets = f.read((nkeys+1)* 4 +2)
    offsetVals = []
    i=0
    nval = 0
    val = 1
    keys = 0
    while nval != val :
      keys +=1
      key = getShortLE(offsets,2+i)
      val = getShortLE(offsets,4+i)
      nval = getShortLE(offsets,8+i)
      #print 'key=0x%x, val=0x%x' % (key, val)
      offsetVals.append(key+ pagesize*page)
      offsetVals.append(val+ pagesize*page)  
      readkeys += 1
      i += 4
    offsetVals.append(pagesize*(page+1))
    valKey = sorted(offsetVals)  
    for i in range( keys*2 ):
      #print '%x %x' % (valKey[i], valKey[i+1])
      f.seek(valKey[i])
      data = f.read(valKey[i+1] - valKey[i])
      db1.append(data)
    page += 1
    #print 'offset=0x%x' % (page*pagesize)
  f.close()
  db = {}

  for i in range( 0, len(db1), 2):
    db[ db1[i+1] ] = db1[ i ]
  if options.verbose>1:
    for i in db:
      print '%s: %s' % ( repr(i), hexlify(db[i]) )
  return db  

def decrypt3DES( globalSalt, masterPassword, entrySalt, encryptedData ):
  #see http://www.drh-consultancy.demon.co.uk/key3.html
  hp = sha1( globalSalt+masterPassword ).digest()
  pes = entrySalt + '\x00'*(20-len(entrySalt))
  chp = sha1( hp+entrySalt ).digest()
  k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
  tk = hmac.new(chp, pes, sha1).digest()
  k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
  k = k1+k2
  iv = k[-8:]
  key = k[:24]
  if options.verbose>0:
    print 'key='+hexlify(key), 'iv='+hexlify(iv)
  return DES3.new( key, DES3.MODE_CBC, iv).decrypt(encryptedData)

def decodeLoginData(data):
  asn1data = decoder.decode(b64decode(data)) #first base64 decoding, then ASN1DERdecode
  return asn1data[0][0].asOctets(), asn1data[0][1][1].asOctets(), asn1data[0][2].asOctets() #for login and password, keep :(key_id, iv, ciphertext)
  
def getLoginData():
  conn = sqlite3.connect(options.directory+'signons.sqlite')
  logins = []
  c = conn.cursor()
  try:
    c.execute("SELECT * FROM moz_logins;")
  except sqlite3.OperationalError: #since Firefox 32, json is used instead of sqlite3
    loginf = open(options.directory+'logins.json','r').read()
    jsonLogins = json.loads(loginf)
    if 'logins' not in jsonLogins:
      print 'error: no \'logins\' key in logins.json'
      return []
    for row in jsonLogins['logins']:
      encUsername = row['encryptedUsername']
      encPassword = row['encryptedPassword']
      logins.append( (decodeLoginData(encUsername), decodeLoginData(encPassword), row['hostname']) )
    return logins
  #using sqlite3 database
  for row in c:
    encUsername = row[6]
    encPassword = row[7]
    if options.verbose>1:
      print row[1], encUsername, encPassword
    logins.append( (decodeLoginData(encUsername), decodeLoginData(encPassword), row[1]) )
  return logins

def extractSecretKey(masterPassword, keyData):
  #see http://www.drh-consultancy.demon.co.uk/key3.html
  pwdCheck = keyData['password-check']
  if options.verbose>1:
    print 'password-check='+hexlify(pwdCheck)
  entrySaltLen = ord(pwdCheck[1])
  entrySalt = pwdCheck[3: 3+entrySaltLen]
  if options.verbose>1:
    print 'entrySalt=%s' % hexlify(entrySalt)
  encryptedPasswd = pwdCheck[-16:]
  globalSalt = keyData['global-salt']
  if options.verbose>1:
    print 'globalSalt=%s' % hexlify(globalSalt)
  cleartextData = decrypt3DES( globalSalt, masterPassword, entrySalt, encryptedPasswd )
  if cleartextData != 'password-check\x02\x02':
    print 'password check error, Master Password is certainly used, please provide it with -p option'
    sys.exit()

  if unhexlify('f8000000000000000000000000000001') not in keyData:
    return None
  privKeyEntry = keyData[ unhexlify('f8000000000000000000000000000001') ]
  saltLen = ord( privKeyEntry[1] )
  nameLen = ord( privKeyEntry[2] )
  #print 'saltLen=%d nameLen=%d' % (saltLen, nameLen)
  privKeyEntryASN1 = decoder.decode( privKeyEntry[3+saltLen+nameLen:] )
  data = privKeyEntry[3+saltLen+nameLen:]
  printASN1(data, len(data), 0)
  #see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
  entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
  if options.verbose>0:
    print 'entrySalt=%s' % hexlify(entrySalt)
  privKeyData = privKeyEntryASN1[0][1].asOctets()
  if options.verbose>0:
    print 'privKeyData=%s' % hexlify(privKeyData)
  privKey = decrypt3DES( globalSalt, masterPassword, entrySalt, privKeyData )
  print 'decrypting privKeyData'
  if options.verbose>0:
    print 'decrypted=%s' % hexlify(privKey)
  printASN1(privKey, len(privKey), 0)

  privKeyASN1 = decoder.decode( privKey )
  prKey= privKeyASN1[0][2].asOctets()
  print 'decoding %s' % hexlify(prKey)
  printASN1(prKey, len(prKey), 0)
  prKeyASN1 = decoder.decode( prKey )
  id = prKeyASN1[0][1]
  key = long_to_bytes( prKeyASN1[0][3] )
  if options.verbose>0:
    print 'key=%s' % ( hexlify(key) )
  return key

def getKey():  
  conn = sqlite3.connect(options.directory+'key4.db') #firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
  c = conn.cursor()
  try:
    #first check password
    c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
    row = c.next()
    globalSalt = row[0] #item1
    item2 = row[1]
    printASN1(item2, len(item2), 0)
    """
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
         SEQUENCE {
           OCTETSTRING entry_salt_for_passwd_check
           INTEGER 01
         }
       }
       OCTETSTRING encrypted_password_check
     }
    """
    decodedItem2 = decoder.decode( item2 ) 
    entrySalt = decodedItem2[0][0][1][0].asOctets()
    cipherT = decodedItem2[0][1].asOctets()
    clearText = decrypt3DES( globalSalt, options.masterPassword, entrySalt, cipherT ) #usual Mozilla PBE
    print 'password check?', clearText=='password-check\x02\x02'
    if clearText=='password-check\x02\x02': 
      #decrypt 3des key to decrypt "logins.json" content
      c.execute("SELECT a11,a102 FROM nssPrivate;")
      row = c.next()
      a11 = row[0] #CKA_VALUE
      a102 = row[1] #f8000000000000000000000000000001, CKA_ID
      printASN1( a11, len(a11), 0)
      """
       SEQUENCE {
         SEQUENCE {
           OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
           SEQUENCE {
             OCTETSTRING entry_salt_for_3des_key
             INTEGER 01
           }
         }
         OCTETSTRING encrypted_3des_key (with 8 bytes of PKCS#7 padding)
       }
      """
      decodedA11 = decoder.decode( a11 ) 
      entrySalt = decodedA11[0][0][1][0].asOctets()
      cipherT = decodedA11[0][1].asOctets()
      
      key = decrypt3DES( globalSalt, options.masterPassword, entrySalt, cipherT )
      print '3deskey', hexlify(key)
      print 'key_4', key
  except Exception as e:
    print 'get_key_4 e =', e
    try:
      keyData = readBsddb(options.directory+'key3.db')
      key = extractSecretKey(options.masterPassword, keyData)
    except Exception as ee:
      print 'get_key_3 ee =', ee
      sys.exit()
  if key is None:
    print 'key_3 is None'
    sys.exit()
  return key[:24]
  
parser = OptionParser(usage="usage: %prog [options]")
parser.add_option("-v", "--verbose", type="int", dest="verbose", help="verbose level", default=0)
parser.add_option("-p", "--password", type="string", dest="masterPassword", help="masterPassword", default='')
parser.add_option("-d", "--dir", type="string", dest="directory", help="directory", default='')
(options, args) = parser.parse_args()

key = getKey()
logins = getLoginData()
if len(logins)==0:
  print 'no stored passwords'
else:
  print 'decrypting login/password pairs'  
for i in logins:
  ii = i[2].strip().encode('utf-8')
  print 'site:    ', ii  #site URL
  iv = i[0][1]
  ciphertext = i[0][2] #login (PKCS#7 padding not removed)
  l = repr( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext) ), ',',
  ll = re.sub('x0[0-9]', '', (l[0]).encode('utf-8'))
  lll = re.sub(r'\\', '', ll)
  print 'login:   ', lll[1:-1]
  iv = i[1][1]
  ciphertext = i[1][2] #passwd (PKCS#7 padding not removed)
  p = repr( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext) )
  pp = re.sub('x0[0-9]', '', p.encode('utf-8'))
  ppp = re.sub(r'\\', '', pp)
  print 'password:', ppp[1:-1]
  print 'password_raw:', p

