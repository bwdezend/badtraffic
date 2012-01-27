#!/bin/bash

cd /tmp
if [ -d /tmp/badtraffic ]; then
  rm -rf /tmp/badtraffic
fi

git clone /afs/bp.ncsu.edu/project/realmlinux/git/badtraffic.git /tmp/badtraffic

VERSION=`grep VERSION /tmp/badtraffic/dist/BadTraffic/lib/BadTraffic.pm | awk '{print $4}' | sed s:\'::g | sed s:\;::g`

cp -r /tmp/badtraffic/dist/BadTraffic /tmp/BadTraffic-$VERSION

tar czvf BadTraffic-$VERSION.tar.gz BadTraffic-$VERSION

if [ -d /tmp/badtraffic ]; then
  rm -rf /tmp/badtraffic
fi

if [ -d /tmp/BadTraffic-$VERSION  ]; then
  rm -rf /tmp/BadTraffic-$VERSION
fi


cp /tmp/BadTraffic-$VERSION.tar.gz /afs/bp.ncsu.edu/adm/vision3/SOURCES/


