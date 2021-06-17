# RLWE based distributed Key Generation and Threshold Decryption

This is a repository created to store all relevant codes deriving from the Master's Degree Thesis "RLWE based distributed Key Generation and Threshold Decryption" by Ferran Alborch Escobar and supervised by Ramiro Martínez Pinilla and Paz Morillo Bosch made within the Master in Advanced Mathematics and Mathematical Engineering in the Universitat Politècnica de Catalunya.

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

### Execution

### Issues and recommendations

## Simulation automatization (test.py)

### Changeable parameters

### Execution

## RLWE estimator (RLWE estimator.ipynb, estimator.py)

### Changeable parameters

### Execution

## Result processing and graphics (graphics.R)

### Changeable parameters

### Execution




