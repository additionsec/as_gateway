#!/bin/sh

#JAVA8=/opt/java8
VER=1.5
TF=target/ASGW-fat.jar
PF=target/ASGW-fat-pg.jar
FF=target/ASGW-${VER}.jar
FF2=target/asgw.jar

rm -f $TF $PF $FF

echo Building...
#JAVA_HOME=$JAVA8 mvn package
mvn package
[ -f $TF ] && echo "Build OK" || echo "Missing $TF"

#exit 1

zip -d $TF \*.rb
zip -d $TF \*.js
zip -d $TF \*.html
zip -d $TF \*/pom.xml
zip -d $TF \*/pom.properties
zip -d $TF vertx-java/template/\*

echo Proguarding...
proguard/bin/proguard.sh @proguard.pro

[ -f $PF ] && echo "Proguard OK" || echo "Missing $PF"

mv $PF $FF
cp $FF $FF2
echo "OK"

