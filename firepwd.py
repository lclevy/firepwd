'''
 decode Firefox passwords (https://github.com/lclevy/firepwd)
 
 lclevy@free.fr 
 28 Aug 2013: initial version, Oct 2016: support for logins.json, Feb 2018: support for key4.db, 
 Apr2020: support for NSS 3.49 / Firefox 75.0 : https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6
 
 for educational purpose only, not production level
 integrated into https://github.com/AlessandroZ/LaZagne
 tested with python 3.7.3, PyCryptodome 3.9.0 and pyasn 0.4.8

 key3.db is read directly, the 3rd party bsddb python module is NOT needed
 NSS library is NOT needed
 
 profile directory under Win10 is C:\\Users\\[user]\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\[profile_name]
 
''' 

from struct import unpack
import sys
from binascii import hexlify, unhexlify 
import sqlite3
from base64 import b64decode
#https://pypi.python.org/pypi/pyasn1/
from pyasn1.codec.der import decoder
from hashlib import sha1, pbkdf2_hmac
import hmac
from Crypto.Cipher import DES3, AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad   
from optparse import OptionParser
import json
from pathlib import Path

def getShortLE(d, a):
   return unpack('<H',(d)[a:a+2])[0]

def getLongBE(d, a):
   return unpack('>L',(d)[a:a+4])[0]

#minimal 'ASN1 to string' function for displaying Key3.db and key4.db contents
asn1Types = { 0x30: 'SEQUENCE',  4:'OCTETSTRING', 6:'OBJECTIDENTIFIER', 2: 'INTEGER', 5:'NULL' }  
#http://oid-info.com/get/1.2.840.113549.2.9
oidValues = { b'2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC',
              b'2a864886f70d0307':'1.2.840.113549.3.7 des-ede3-cbc',
              b'2a864886f70d010101':'1.2.840.113549.1.1.1 pkcs-1',
              b'2a864886f70d01050d':'1.2.840.113549.1.5.13 pkcs5 pbes2', 
              b'2a864886f70d01050c':'1.2.840.113549.1.5.12 pkcs5 PBKDF2',
              b'2a864886f70d0209':'1.2.840.113549.2.9 hmacWithSHA256',
              b'60864801650304012a':'2.16.840.1.101.3.4.1.42 aes256-CBC'
              }   
              
def printASN1(d, l, rl):
   type = d[0]
   length = d[1]
   if length&0x80 > 0: #http://luca.ntop.org/Teaching/Appunti/asn1.html,
     nByteLength = length&0x7f
     length = d[2]  
     #Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets. 
     skip=1
   else:
     skip=0    
   #print ('%x:%x' % ( type, length ))
   print ('  '*rl, asn1Types[ type ],end=' ')
   if type==0x30:
     print ('{')
     seqLen = length
     readLen = 0
     while seqLen>0:
       #print(seqLen, hexlify(d[2+readLen:]))
       len2 = printASN1(d[2+skip+readLen:], seqLen, rl+1)
       #print('l2=%x' % len2)
       seqLen = seqLen - len2
       readLen = readLen + len2
     print ('  '*rl,'}')
     return length+2
   elif type==6: #OID
     oidVal = hexlify(d[2:2+length])
     if oidVal in oidValues:
     #print ( hexlify(d[2:2+length]) )
       print (oidValues[ hexlify(d[2:2+length]) ])
     else:
       print('oid? ', oidVal)
     return length+2
   elif type==4: #OCTETSTRING
     print (hexlify( d[2:2+length] ))
     return length+2
   elif type==5: #NULL
     print (0)
     return length+2
   elif type==2: #INTEGER
     print (hexlify( d[2:2+length] ))
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
    print ('bad magic number')
    sys.exit()
  version = getLongBE(header,4)
  if version !=2:
    print ('bad version, !=2 (1.85)')
    sys.exit()
  pagesize = getLongBE(header,12)
  nkeys = getLongBE(header,0x38) 
  if options.verbose>1:
    print ('pagesize=0x%x' % pagesize)
    print ('nkeys=%d' % nkeys)

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
      print ('%s: %s' % ( repr(i), hexlify(db[i]) ))
  return db  

def decryptMoz3DES( globalSalt, masterPassword, entrySalt, encryptedData ):
  #see http://www.drh-consultancy.demon.co.uk/key3.html
  hp = sha1( globalSalt+masterPassword ).digest()
  pes = entrySalt + b'\x00'*(20-len(entrySalt))
  chp = sha1( hp+entrySalt ).digest()
  k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
  tk = hmac.new(chp, pes, sha1).digest()
  k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
  k = k1+k2
  iv = k[-8:]
  key = k[:24]
  if options.verbose>0:
    print ('key= %s, iv=%s' % ( hexlify(key), hexlify(iv) ) )
  return DES3.new( key, DES3.MODE_CBC, iv).decrypt(encryptedData)

def decodeLoginData(data):
  '''
  SEQUENCE {
    OCTETSTRING b'f8000000000000000000000000000001'
    SEQUENCE {
      OBJECTIDENTIFIER 1.2.840.113549.3.7 des-ede3-cbc
      OCTETSTRING iv 8 bytes
    }
    OCTETSTRING encrypted
  }
  '''
  asn1data = decoder.decode(b64decode(data)) #first base64 decoding, then ASN1DERdecode
  key_id = asn1data[0][0].asOctets()
  iv = asn1data[0][1][1].asOctets()
  ciphertext = asn1data[0][2].asOctets()
  return key_id, iv, ciphertext 
  
def getLoginData():
  logins = []
  sqlite_file = options.directory / 'signons.sqlite'
  json_file = options.directory / 'logins.json'
  if json_file.exists(): #since Firefox 32, json is used instead of sqlite3
    loginf = open( json_file, 'r').read()
    jsonLogins = json.loads(loginf)
    if 'logins' not in jsonLogins:
      print ('error: no \'logins\' key in logins.json')
      return []
    for row in jsonLogins['logins']:
      encUsername = row['encryptedUsername']
      encPassword = row['encryptedPassword']
      logins.append( (decodeLoginData(encUsername), decodeLoginData(encPassword), row['hostname']) )
    return logins  
  elif sqlite_file.exists(): #firefox < 32
    print('sqlite')
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()
    c.execute("SELECT * FROM moz_logins;")
    for row in c:
      encUsername = row[6]
      encPassword = row[7]
      if options.verbose>1:
        print (row[1], encUsername, encPassword)
      logins.append( (decodeLoginData(encUsername), decodeLoginData(encPassword), row[1]) )
    return logins
  else: 
    print('missing logins.json or signons.sqlite')

CKA_ID = unhexlify('f8000000000000000000000000000001')

def extractSecretKey(masterPassword, keyData): #3DES
  #see http://www.drh-consultancy.demon.co.uk/key3.html
  pwdCheck = keyData[b'password-check']
  entrySaltLen = pwdCheck[1]
  entrySalt = pwdCheck[3: 3+entrySaltLen]
  encryptedPasswd = pwdCheck[-16:]
  globalSalt = keyData[b'global-salt']
  if options.verbose>1:
    print ('password-check=%s'% hexlify(pwdCheck))
    print ('entrySalt=%s' % hexlify(entrySalt))
    print ('globalSalt=%s' % hexlify(globalSalt))
  cleartextData = decryptMoz3DES( globalSalt, masterPassword, entrySalt, encryptedPasswd )
  if cleartextData != b'password-check\x02\x02':
    print ('password check error, Master Password is certainly used, please provide it with -p option')
    sys.exit()

  if CKA_ID not in keyData:
    return None
  privKeyEntry = keyData[ CKA_ID ]
  saltLen = privKeyEntry[1]
  nameLen = privKeyEntry[2]
  #print 'saltLen=%d nameLen=%d' % (saltLen, nameLen)
  privKeyEntryASN1 = decoder.decode( privKeyEntry[3+saltLen+nameLen:] )
  data = privKeyEntry[3+saltLen+nameLen:]
  printASN1(data, len(data), 0)
  #see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
  '''
   SEQUENCE {
     SEQUENCE {
       OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
       SEQUENCE {
         OCTETSTRING entrySalt
         INTEGER 01
       }
     }
     OCTETSTRING privKeyData
   }
  '''
  entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
  privKeyData = privKeyEntryASN1[0][1].asOctets()
  privKey = decryptMoz3DES( globalSalt, masterPassword, entrySalt, privKeyData )
  print ('decrypting privKeyData')
  if options.verbose>0:
    print ('entrySalt=%s' % hexlify(entrySalt))
    print ('privKeyData=%s' % hexlify(privKeyData))
    print ('decrypted=%s' % hexlify(privKey))
  printASN1(privKey, len(privKey), 0)
  '''
   SEQUENCE {
     INTEGER 00
     SEQUENCE {
       OBJECTIDENTIFIER 1.2.840.113549.1.1.1 pkcs-1
       NULL 0
     }
     OCTETSTRING prKey seq
   }
  ''' 
  privKeyASN1 = decoder.decode( privKey )
  prKey= privKeyASN1[0][2].asOctets()
  print ('decoding %s' % hexlify(prKey))
  printASN1(prKey, len(prKey), 0)
  '''
   SEQUENCE {
     INTEGER 00
     INTEGER 00f8000000000000000000000000000001
     INTEGER 00
     INTEGER 3DES_private_key
     INTEGER 00
     INTEGER 00
     INTEGER 00
     INTEGER 00
     INTEGER 15
   }
  '''
  prKeyASN1 = decoder.decode( prKey )
  id = prKeyASN1[0][1]
  key = long_to_bytes( prKeyASN1[0][3] )
  if options.verbose>0:
    print ('key=%s' % ( hexlify(key) ))
  return key

def decryptPBE(decodedItem, masterPassword, globalSalt):
  pbeAlgo = str(decodedItem[0][0][0])
  if pbeAlgo == '1.2.840.113549.1.12.5.1.3': #pbeWithSha1AndTripleDES-CBC
    """
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
         SEQUENCE {
           OCTETSTRING entry_salt
           INTEGER 01
         }
       }
       OCTETSTRING encrypted
     }
    """
    entrySalt = decodedItem[0][0][1][0].asOctets()
    cipherT = decodedItem[0][1].asOctets()
    print('entrySalt:',hexlify(entrySalt))
    key = decryptMoz3DES( globalSalt, masterPassword, entrySalt, cipherT )
    print(hexlify(key))
    return key[:24], pbeAlgo
  elif pbeAlgo == '1.2.840.113549.1.5.13': #pkcs5 pbes2  
    #https://phabricator.services.mozilla.com/rNSSfc636973ad06392d11597620b602779b4af312f6
    '''
    SEQUENCE {
      SEQUENCE {
        OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
        SEQUENCE {
          SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
            SEQUENCE {
              OCTETSTRING 32 bytes, entrySalt
              INTEGER 01
              INTEGER 20
              SEQUENCE {
                OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
              }
            }
          }
          SEQUENCE {
            OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
            OCTETSTRING 14 bytes, iv 
          }
        }
      }
      OCTETSTRING encrypted
    }
    '''
    assert str(decodedItem[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
    assert str(decodedItem[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
    assert str(decodedItem[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
    # https://tools.ietf.org/html/rfc8018#page-23
    entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
    iterationCount = int(decodedItem[0][0][1][0][1][1])
    keyLength = int(decodedItem[0][0][1][0][1][2])
    assert keyLength == 32 

    k = sha1(globalSalt+masterPassword).digest()
    key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)    

    iv = b'\x04\x0e'+decodedItem[0][0][1][1][1].asOctets() #https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
    # 04 is OCTETSTRING, 0x0e is length == 14
    cipherT = decodedItem[0][1].asOctets()
    clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)
    
    print('clearText', hexlify(clearText))
    return clearText, pbeAlgo

def getKey( masterPassword, directory ):  
  if (directory / 'key4.db').exists():
    conn = sqlite3.connect(directory / 'key4.db') #firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
    c = conn.cursor()
    #first check password
    c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
    row = c.fetchone()
    globalSalt = row[0] #item1
    print('globalSalt:',hexlify(globalSalt))
    item2 = row[1]
    printASN1(item2, len(item2), 0)
    decodedItem2 = decoder.decode( item2 ) 
    clearText, algo = decryptPBE( decodedItem2, masterPassword, globalSalt )
   
    print ('password check?', clearText==b'password-check\x02\x02')
    if clearText == b'password-check\x02\x02': 
      c.execute("SELECT a11,a102 FROM nssPrivate;")
      for row in c:
        if row[0] != None:
            break
      a11 = row[0] #CKA_VALUE
      a102 = row[1] 
      if a102 == CKA_ID: 
        printASN1( a11, len(a11), 0)
        decoded_a11 = decoder.decode( a11 )
        #decrypt master key
        clearText, algo = decryptPBE( decoded_a11, masterPassword, globalSalt )
        return clearText[:24], algo
      else:
        print('no saved login/password')      
    return None, None
  elif (directory / 'key3.db').exists():
    keyData = readBsddb(directory / 'key3.db')
    key = extractSecretKey(masterPassword, keyData)
    return key, '1.2.840.113549.1.12.5.1.3'
  else:
    print('cannot find key4.db or key3.db')  
    return None, None


parser = OptionParser(usage="usage: %prog [options]")
parser.add_option("-v", "--verbose", type="int", dest="verbose", help="verbose level", default=0)
parser.add_option("-p", "--password", type="string", dest="masterPassword", help="masterPassword", default='')
parser.add_option("-d", "--dir", type="string", dest="directory", help="directory", default='')
(options, args) = parser.parse_args()
options.directory = Path(options.directory)

key, algo = getKey(  options.masterPassword.encode(), options.directory )
if key==None:
  sys.exit()
#print(hexlify(key))
logins = getLoginData()
if len(logins)==0:
  print ('no stored passwords')
else:
  print ('decrypting login/password pairs' ) 
if algo == '1.2.840.113549.1.12.5.1.3' or algo == '1.2.840.113549.1.5.13':  
  for i in logins:
    assert i[0][0] == CKA_ID
    print ('%20s:' % (i[2]),end='')  #site URL
    iv = i[0][1]
    ciphertext = i[0][2] 
    print ( unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 ), end=',')
    iv = i[1][1]
    ciphertext = i[1][2] 
    print ( unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 ) )
 
