# Honours Project 2022
---
## Blind Signatures In Identity Based Encryption

#### **Goal**
The goal of this project is to provide a Proof of Concept variation of Identity Based Encryption that implements a Certificate Authority as a middleman to dispense digital credentials to each user so that they may blind their attributes when passing them to the PKG to remove the security issue of the PKG being able to decrypt every user's ciphertext. The rough outline of the Proof of Concept for this implementation will be outlined below.

---

#### **Implementation**
The implementation will be done within a single project/application in Java, LTS version 11. The java project will be built via Maven to include dependencies from the Crytpid-Java Github repository. The project will be separated into classes largely based on use in the encryption scheme, but some helper and/or wrapper classes will be included also. The classes are roughly explained below.

##### CA
>A Certificate Authority class, it is used to issue certificates to users for digital credentials. In this use case it will only issue credentials for a point where the user's attribute exists on an elliptic curve. Along with this, for the sake of simplicity, the Certificate Authority will not require proof of identity for the proposed attributes. The CA class will implement several important functions for things such as: generating system parameters, a handshake function for establishing contact with the client, a function for calculating a client's digital credential, and several functions for communicating with the PKG and confirming a user's identity. The CA class will only interact with the PKG and Client classes directly, but will implement both the Key and Certificate classes.

##### PKG
>A Private Key Generator Class, it is used to communicate with clients for access to their private key to decrypt a message, and communicates with the CA class to verify the identity of a user requesting a private key. The PKG will largely be implemented via the Cryptid-Java library, but several conditional additions will be made via wrapper functions. One such example will be verifying a users identity via the CA class. This means that there will be very few implemented functions in our class. The PKG class will also implement the Key class, and will make use of the Certificate class very briefly.</div>

##### Client
>A Client class used for encrypted communication between users. Once more the client is largely implemented via the Cyrptid-Java library, but several conditional additions via wrapper functions. These will largely handle communication with the CA, and passing values to the PKG. The role of the user class is mostly for testing and proving conceptual ideals, so it is relatively important in terms of use.</div>

## **TODO**

- [x] Create High-Level Design diagram
- [ ] Define Key and Certificate classes
- [ ] Create UML diagrams for each class
- [ ] Begin implementation of CA and communication with user class
- [ ] Edit PKG source class to allow for proof of identity via digital credentials


## High-Level Architecture Diagram

The following diagram represents a High-Level overview of the goal of this project:
![h-level-design](./readme-images/h-proj-high-level-design.png)

## System-Wide Parameters

- q (prime number) = 123766290236648576999305319065597697947 (128 bit)
- Generator for cyclic group of prime order q can be made from a coprime/ number p that is less than q
  - A group of prime order is cyclic.
  - By the euler totient function, we have q-1 choices of generators.
- Java BigInt library for dealing with large numbers.
- SHA256 as Hash Function.
- All numbers will be handled in hexadecimal, most likely including predetermined prime numbers used as well

### Next Steps

1 thing at the time :)

- [x] Construct Alice and CA classes first!

### Issue Protocol Test

For the sake of testing, the initial iteration of the issue protocol will have the following parameters:

- q = 11
- g_0 = 3
- y_1 = 7 - used to generate g_1 
- x_0 = 8 - used to generate h_0

The issue protocol will be in accordance to Brand's paper.

![brands_issue](readme-images/brands_issue.png)