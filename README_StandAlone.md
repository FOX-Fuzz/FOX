# Prerequisites 
Install [Oracle Virtual Box](https://www.virtualbox.org/)  
Install Virtual Box Image \- Lubuntu 24.04

# Docker Installation
[Install using the apt respository](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)  
Follow Steps 1-3

# Image Procurement 
*Pull FOX image from dockerhub*

```
docker pull adamstorek/fox:latest
```

*Run* 

```
docker run --privileged --network='host' -d --name="optfuzz_eval" -it adamstorek/fox:latest

docker exec -it optfuzz_eval /bin/bash
```

# Compiling and Running Target 
### Step 1:
cd targets  
![Step1](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%201.png)

### Step 2:  
run: ./unzip\_seeds.sh  
![Step2](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%202.png)

### Step 3:  
cd zlibunc  
![Step3](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%203.png)

### Step 4: 
run: ./preinstall.sh  
![Step4](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%204.png)

### Step 5: 
run: ./build\_aflpp.sh optfuzz\_nogllvm  
![Step5](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%205.png)

### Step 6: 
cd binaries/optfuzz\_build  
![Step6](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%206.png)

### Step 7:  
Go to File \-\> New Tab

* This should open a new main terminal window  
* Note: the terminal should NOT be within the FOX terminal/image

![Step7](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%207.png)

### Step 8:  
Run command: sudo bash \-c "echo core \>/proc/sys/kernel/core\_pattern"  
Enter password if necessary  
Run command: sudo vim /proc/sys/kernel/core\_pattern  
![Step8](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%208.png)

### Step 9: 
Confirm that file core\_pattern has ONLY the word "core" inside  
![Step9](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%209.png)

then esc, :q to exit the vim file

### Step 10: 
Return to FOX terminal/image

run: /workspace/OptFuzzer/afl-fuzz \-k \-p wd\_scheduler \-i ../../seeds\_fuzzbench \-o out \-- ./zlib\_uncompress\_fuzzer  
![Step10](https://github.com/clz2116/FOX/blob/fc525afa75dc2d6276b7066a76b7a1956c681372/README_StandAlone%20Images/Step%2010.png)

### Finished:  
![Finished](https://github.com/clz2116/FOX/blob/b398526a6119c4d2df93528e4e13d7ba9a2ab199/README_StandAlone%20Images/Finished.png)
