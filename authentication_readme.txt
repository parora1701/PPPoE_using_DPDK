Steps to run the authentication_main.c:

step1: copy authentication_main.c and data.txt to some folder in your machine
step2: rename authentication_main.c to main.c
step3: open main.c and give the correct path location of stored data.txt file 
i.e change the following statement in main.c:
const char filename[] = "/home/govind/c_learn/authentication/data.txt";
step4: compile main.c using gcc
step5: run the generated a.out file

Note: always add a new user in data.txt in the format-> username:password

