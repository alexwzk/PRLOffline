/****

This program is released under the GPLv2 license with the additional exemption that compiling, linking, and/or using OpenSSL is allowed.

************
Prerequisite:
The latest OpenSSL needs to be installed. The version 1.0.1h is used in this project. Lower versions is not guaranteed to be fine. The source code is stored at http://www.openssl.org/source/openssl-1.0.1h.tar.gz.
The Compiler Standard of C++ is C++11. Please check the following tag is included in your makefile: -std=c++11

*******************
Rebuild the Project:
I used Eclipse on Linux as my IDE while developing this project. You may need to modify the compiler & linker configuration before you build the project. 

********
Reminder:
This project accepts enlgish alphabets and digital numbers only so far. You are able to extend the set at returnQuantumIndex function [Main.cpp: Line 311 - 333] and also remember to update the (to_clean_data) section [Main.cpp: Line 154 - 165] while getting line from the original dataset if the auto data formatting is needed.	

*******************
Run on Command Line:
(Linux Example) ./PRLOffline -a 10 -b 16 -f dataset1000.dat (if you are confident that the .dat file doesn't contain any illegal input, which saves running time).

-OR-

./PRLOffline -a 10 -b 16 -f dataset1000.dat -c

where,
-a means to set the values of Minhash alpha

-b means to set the values of Minhash beta

-f means to feed in the input file path

-c means to clean the illegal input characters before processing the file

*******
Outputs:
The data is stored in the "same-filename".lsh file under the same folder with the original's. You can then parse the lsh file and setup the Online Oblivious Bloom Intersection (https://personal.cis.strath.ac.uk/changyu.dong/PSI/PSI.html) process accordingly.

The result of the offline process is like this:
0 1d e5 dc 80 f7 ec d0 3c 86 50 97 26 f6 78 32 81 c4 88 fd

---------------------- Hash Digests ----------------------

2

number of records that share the same hash value

212 846

the ID of records in the dataset

If you receive the following error messages:

Error @ former char input is illegal.

Error @ Invalid inputs in returnQuantumIndex.

50 <<<<<-- check this line's record which contains illegal inputs.

****/
