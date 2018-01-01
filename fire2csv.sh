#!/bin/bash
#
# fire2csv.sh
#
# simple shell script converting output of firepwd to CSV
# see https://github.com/fligtar/password-exporter/issues/80
#
# (c) https://github.com/gnadelwartz

# workaround for bad unicode translation in phyton
export PYTHONIOENCODING='utf-8'

# should work in most installations
CMD="python firepwd.py -d ./ "
PASSWD=""

# SED command to convert to pseudo CSV
#         protcol host:port  user       pass    url,username,password,extra,name,grouping,fav
CSV="s|^ *([^:]+)://(.*?): '([^']*)' , '([^']*)'\$|\1://\2,\3,\4,,\2,Firefox,0|"


# check for options:
# RAW output
if [ "$1" == "-r" ]
then
        #remove leading blanks only
        CSV="s/^ *//"
        shift
fi

# provide PASSWORD
if [ "$1" == "-p" ]
then
        PASSWD="-p $2"
        shift 2
fi

# unkown option / parameter left:
if [ "$1" != "" ]
then
        echo "usage: `basename $0` [-r] [-p PASS]"
        exit
fi

# do the magic ...
echo "url,username,password,extra,name,grouping,fav"

${CMD} ${PASSWD} | \
        sed -n -e '/^decrypting login/,$p' | \
        sed -e '/^decrypting login/d' -e 's/\\x0[0-9]//g' | \
        sed -r -e "${CSV}"

