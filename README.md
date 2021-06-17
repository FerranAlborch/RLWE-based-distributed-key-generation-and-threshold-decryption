# RLWE based distributed Key Generation and Threshold Decryption

This is a repository created to store all relevant codes deriving from the Master's Degree Thesis "RLWE based distributed Key Generation and Threshold Decryption" by Ferran Alborch Escobar and supervised by Ramiro Martínez Pinilla and Paz Morillo Bosch made within the Master in Advanced Mathematics and Mathematical Engineering in the Universitat Politècnica de Catalunya in the year 2021.

We will go through what each main simulation, how to use it and any perks or problems it may have.

## Protocol simulation (decryption_sim.c, functions.c, functions.h, keygen_sim.c)

These files contain the codes for the simulation of both protocols. The file decryption_sim.c contains the decryption simulation, keygen_sim.c contains the key generation simulation and functions.c contains functions used in both simulations.

### Libraries needed

For these simulations to be able to run in a computer it must have the following libraries installed:
- FLINT (Fast Library for Number Theory), found [here](https://www.flintlib.org/downloads.html). The version used is 2.7.1. FLINT requires two other libraries:
  - GMP, found [here](https://gmplib.org/). The version used is 6.2.1.
  - MPFR, found [here](https://www.mpfr.org/). The version used is 4.1.0.
- OpenSSL, found [here](https://www.openssl.org/). The version used is 1.1.1.

### Changeable parameters

The only changeable parameters in these codes are the modulo q found in line 228 in decryption_sim.c and in line 949 in keygen_sim.c and how many repetitions are made of every simulation inside one execution. This is found in line 231 in decryption_sim.c and in line 952 in keygen_sim.c

### Execution

To execute the Key Generation simulation the following commands are needed:
```
gcc keygen_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o keygen.out -O2
./keygen.out n u t
```
Where n, u, t are the non-negative integer values you want to give to these parameters.

To execute the Decryption simulation the following commands are needed
```
gcc decryption_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o decrypt.out -O2
./decrypt.out n u t
```
Where once again n, u, t are the non-negative integer values you want to give to these parameters.

### Issues and recommendations

There is a slight issue with some FLINT functions which we have not been able to clear completely yet, so there is a slight leak of storage when iterating within the .c code. Therefore we would highly recommend using small values for repetitions and using our python script as we have done.

## Simulation automatization (test.py)

Given the slight issues we had with memory storage and the fact that we needed to simulate a lot of different cases we created this pyhton script to help us.

### Changeable parameters

This script allows for any range of n and t and any relation between t and u. The most used by us are u = 3t+1, u = 2t+2 and u = t+1. Once again beware of using very big t or u since those values will probably require too much time or storage.

### Execution

To execute the automated simulation the following command is needed:
```
python test.py
```

## RLWE estimator (RLWE estimator.ipynb, estimator.py)

This is a short sagemath code we have written to use the LWE estimator given by Albrecht et al. [here](https://bitbucket.org/malb/lwe-estimator/src/master/).

### Changeable parameters

The code allows for any range of n, q and alpha.

### Execution

To execute it we used jupyter notebook.

## Result processing and graphics (graphics.R)

This R code is used to take the raw .csv data output by the simulations and then getting an average time and plotting graphics.

### Changeable parameters

The only thing changeable (and must be changed) is by making sure the .csv files imported are the ones you want at every moment.

### Execution

To execute it we used RStudio.



