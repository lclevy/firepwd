firepwd.py, an open source tool to decrypt Mozilla protected passwords 
----------------------------------------------------------------------


Introduction
************

This educational tool was written to illustrate how Mozilla passwords (Firefox, Thunderbird) are protected
using contents of files key3.db and signons.sqlite.

Reference documents are:
- Into the Black Box: A Case Study in Obtaining Visibility into Commercial Software, 
D. Plakosh, S. Hissam, K. Wallnau, March 1999, Carnegie Mellon University :
http://www.sei.cmu.edu/library/abstracts/reports/99tn010.cfm
- Dr. Stephen Henson, August 4th 1999 :
http://arc.info/?l=openssl-dev&m=93378860132031&w=2


This code is released under GPL license.

Now part of LaZagne project:
https://github.com/AlessandroZ/LaZagne


You can also read the related article, in french:
http://connect.ed-diamond.com/MISC/MISC-069/Protection-des-mots-de-passe-par-Firefox-et-Thunderbird-analyse-par-la-pratique



Usage
*****

By default, firepwd.py processes key3.db and signons.sqlite files in current directory, 
but an alternative directory can be provided using the -d option. Do not forget the '/' 
at the end.

If a master password has been set, provide it using the -p option.

Valid verbose levels (-v) are from 0 (default) to 2.

$ python firepwd.py -h
Usage: firepwd.py [options] 

Options:
  -h, --help            show this help message and exit
  -v VERBOSE, --verbose=VERBOSE
                        verbose level
  -p MASTERPASSWORD, --password=MASTERPASSWORD
                        masterPassword
  -d DIRECTORY, --dir=DIRECTORY
                        directory
						
$ python firepwd.py -d /c/Users/lclevy/AppData/Roaming/Mozilla/Firefox/Profiles/o8syoe2h.default/
no stored passwords

$ python firepwd.py -p 'MISC*' -d mozilla_db/
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
     SEQUENCE {
       OCTETSTRING a8db682ac51cfad8c06664fe9deb5283073b33ee
       INTEGER 01
     }
   }
   OCTETSTRING 72d5636049d4af9eeadaf7eb0dc1710a62d5362fe4086dcc0495e5ec8e96c23c56b72a552e17756141ae80854d6fd03ecdc2c8f83d2c02d4c3f36e7e2b906f2c70a8cf571a06666e53f241780f9e39815e7d840e97e434614ac20ec09002e861
 }
decrypting privKeyData
 SEQUENCE {
   INTEGER 00
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.1.1
     NULL 0
   }
   OCTETSTRING 3042020100021100f8000000000000000000000000000001020100021813c1e53d51a1e60bc79419f7d59107ef97976d075832a45b020100020100020100020100020115
 }
decoding 3042020100021100f8000000000000000000000000000001020100021813c1e53d51a1e60bc79419f7d59107ef97976d075832a45b020100020100020100020100020115
 SEQUENCE {
   INTEGER 00
   INTEGER 00f8000000000000000000000000000001
   INTEGER 00
   INTEGER 13c1e53d51a1e60bc79419f7d59107ef97976d075832a45b
   INTEGER 00
   INTEGER 00
   INTEGER 00
   INTEGER 00
   INTEGER 15
 }
decrypting login/password pairs
http://challenge01.root-me.org: 'login\x03\x03\x03' , 'password\x08\x08\x08\x08\x08\x08\x08\x08'

$ python firepwd.py -d /c/Users/laurent/AppData/Roaming/Thunderbird/Profiles/3luvewzm.default/
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
     SEQUENCE {
       OCTETSTRING 10540ef85fb7e198d41884c8c9c90cf3bc065482
       INTEGER 01
     }
   }
   OCTETSTRING 082fe34f23eae209334d53be2c85ea62d0242a722d452da5b0f27e39dd2733f177c0dc55dd22635d6c8e61fc3e7dc44fe2f1cccef58a8f3138b2822b5a1db3bc39ee8e57c5f4bf05aaed8073eeaf2cd7fddffd6fbc1f5d05ee870f353861c952
 }
decrypting privKeyData
 SEQUENCE {
   INTEGER 00
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.1.1
     NULL 0
   }
   OCTETSTRING 3042020100021100f8000000000000000000000000000001020100021875a873cdb39783ecf1fedcea3d010dd9732a01a8b30451e9020100020100020100020100020115
 }
decoding 3042020100021100f8000000000000000000000000000001020100021875a873cdb39783ecf1fedcea3d010dd9732a01a8b30451e9020100020100020100020100020115
 SEQUENCE {
   INTEGER 00
   INTEGER 00f8000000000000000000000000000001
   INTEGER 00
   INTEGER 75a873cdb39783ecf1fedcea3d010dd9732a01a8b30451e9
   INTEGER 00
   INTEGER 00
   INTEGER 00
   INTEGER 00
   INTEGER 15
 }
decrypting login/password pairs
[censored]


$ python firepwd.py -d /c/Users/laurent/AppData/Roaming/Mozilla/Firefox/Profiles/77l7qxfi.default/
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
     SEQUENCE {
       OCTETSTRING c6581e1fbdb50b4265ab11f54861fdbb62cb4abd
       INTEGER 01
     }
   }
   OCTETSTRING cecb819cb612dccfc2265121aa38ed5d4b7cfc6f06f92f4fb48305f1afb3234f02e25fcb8f3029c0d4aa8c9be7ef292fc3c7d2d446e33f7f80d03a1df35aecb72f843463907786777da8bf1fd47a955fad9eb23e65e0ddff6d1ed0463cc69ed4
 }
decrypting privKeyData
[...]


Installation
************

written for Python 2.7

modules required:
- pyasn1,  https://pypi.python.org/pypi/pyasn1/, for ASN1 decoding
- PyCrypto, https://www.dlitz.net/software/pycrypto/, for 3DES EDE decryption

key3.db is read directly, the 3rd party bsddb python module is NOT needed.


---end of transmission---