# Attack RC4

Assignment for CZ4024 Cryptography and Network Security. The report of this assignment can be found [here](https://docs.google.com/document/d/1vQMD8h7lGahnZ7W6Se7_FtSsDA4M-sgDOLC2A7Hoa8c/edit?usp=sharing).

# Problem Description:

Consider a scenario where the users use a proxy client (the proxy) to communicate with a central server (the server). All users send their messages through the proxy. The communication between the users and the proxy is beyond the purview of this project. The proxy and the server share a secret symmetric key, which is initially known only to them and no one else. They use this secret key to generate a stream cipher and encrypt the messages with it.

*Source: CZ4024 Cryptography and Network Security Assignment Manual*

# Getting Started

First, we will use `Simulation.jar` to generate two encrypted binary log files. `Simulation.jar` is only has a JavaFX UI, so open it by double clicking it. Two log files will be generated, namely `ClientLogEnc.dat` and `ServerLogEnc.dat`. 

*The content of Users.txt can be changed to simulate different behaviors.*

`decryptRC4.py` will reveal the content of log files. The following command will print the content of proxy log file and server log file in command line:

```Shell
$ python decryptRC4.py
```

# Solving Problem 1

Problem 1: Find out which users are actually logged in to the server, using only the two log files of encrypted messages between the proxy and the server.

Solution: the following command will generate `Problem1.txt` that has a list of username

```Shell
$ python Problem1.py
```

# Solving Problem 2

Problem 2: Reveal the passwords used per login trial, using only the two log files of encrypted messages between the proxy and the server.

Solution: the following command will generate `Problem2.txt` that has a list of login trial, with username and password

```Shell
$ python Problem2.py
```

# Generate submission files and compile to .exe files

```Shell
$ python generate_submission.py
$ cd submission
$ pip install py2exe
$ build_exe Problem1.py -c --bundle-files 0
$ build_exe Problem2.py -c --bundle-files 0
```
