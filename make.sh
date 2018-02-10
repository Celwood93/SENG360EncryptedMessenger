#! /bin/bash

mkdir classes 2> test.txt
rm test.txt

javac -d classes ReceiveCommunications.java
javac -d classes SendCommunications.java
javac -d classes ReceiveByteArray.java
javac -d classes SendByteArray.java
javac -d classes Client.java
javac -d classes Server.java