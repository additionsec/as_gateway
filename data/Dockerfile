FROM java:8-jre-alpine
MAINTAINER support@additionsecurity.com
ADD asgw.jar config.properties definitions.json /
ENTRYPOINT java -jar asgw.jar config.properties
EXPOSE 5000
