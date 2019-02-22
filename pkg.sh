#!/bin/sh

R=2017082301
V=1.5

rm -rf pkg/
mkdir -p pkg/r$R
mkdir -p pkg/r$R/deploy_awsbeanstalk
mkdir -p pkg/r$R/deploy_docker

cp data/config.properties pkg/r$R/config.properties
cp target/asgw.jar pkg/r$R/
cp data/definitions.json pkg/r$R/
cp data/Dockerfile pkg/r$R/deploy_docker/

cp target/asgw.jar pkg/r$R/deploy_awsbeanstalk/
cp data/definitions.json pkg/r$R/deploy_awsbeanstalk/
cp data/Procfile pkg/r$R/deploy_awsbeanstalk/

cd pkg/r$R/deploy_awsbeanstalk
zip asgw_eb.zip asgw.jar definitions.json Procfile
rm asgw.jar definitions.json Procfile

cd ../../
zip ASGW_$V.zip -rD r$R


