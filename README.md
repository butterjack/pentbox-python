# Pentbox-Python

## Introduction

Pentbox-Python is a Python library that offers many cryptology tools.

## Installation

To install this library, you need only to download the folder and do the following command: 

```bash
python setup.py develop
```

## Usage

To use this library: 

```bash
pentbox
```

To see the help page:

```bash
pentbox --help
```

To use one of the modules, you can add "--mode module_name", for exemple ( for encoding ): 

```bash
pentbox --mode encoding
```

## Requirements

- Click
- pyfiglet
- pyinputplus
- stdiomask
- pycryptodome
- python-secrets

***All the above requirements will be automatically downloaded after using python setup.py develop command*** 


## Modules

### Encoding, Decoding

This module offers the possibilities to encode or decode your message using UTF8, ASCII, BASE16, BASE32, BASE64.
You can also encode your message using the following custom algorithm:

browse the message from left to right, counting the number of successive occurrences of each character in the message,
then arrange them, this number followed by the character in question.

- For exemple, the message 'aaaFyBssssssssssssazz' will be encoded like : 

```bash
3a1F1y1B12s1a2z
```

To use this module : 

```bash
pentbox --mode encoding
```


### Hashing

This module offers the possibilities to hash your message using the following algorithms:

MD5, SHA1, SHA256, SHA384, SHA512, SHA3_256,
SHA3_384, SHAKE_128, SHA224, BLAKE2B, BLAKE2S, SHAKE_256, SHA3_512,
SHA3_224.

To use this module : 

```bash
pentbox --mode hashing
```

### Password cracking

This module helps to crack a hashed password using the above algorithms and a predefined dictionnary.

To use this module : 

```bash
pentbox --mode crack
```

### Symmetric Encryption

This module offers symmetric encryption or decryption using known algorithms like AES or SALSA20

#### AES

AES is based on a design principle known as a substitution–permutation network, 
and is efficient in both software and hardware.[9] Unlike its predecessor DES, 
AES does not use a Feistel network. AES is a variant of Rijndael, with a fixed block 
size of 128 bits, and a key size of 128, 192, or 256 bits. By contrast, Rijndael per se 
is specified with block and key sizes that may be any multiple of 32 bits, with a minimum 
of 128 and a maximum of 256 bits.

#### SALSA20

nternally, the cipher uses bitwise addition (exclusive OR), 32-bit addition mod 2^32, and constant-distance rotation operations 
(<<<) on an internal state of sixteen 32-bit words. Using only add-rotate-xor operations avoids the possibility of 
timing attacks in software implementations. The internal state is made of sixteen 32-bit words arranged as a 4×4 matrix.


To use this module : 

```bash
pentbox --mode symmetric
```

### Asymmetric Encryption

This module offers asymmetric encryption or decryption using known algorithms like ElGamal cryptosystem or RSA

#### RSA

RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem that is widely used for secure data transmission. 
It is also one of the oldest. The acronym RSA comes from the surnames of Ron Rivest, Adi Shamir, 
and Leonard Adleman, who publicly described the algorithm in 1977. An equivalent system was developed secretly, 
in 1973 at GCHQ (the British signals intelligence agency), by the English mathematician Clifford Cocks. 
That system was declassified in 1997.


#### ElGamal Cryptosystem

 the ElGamal encryption system is an asymmetric key encryption algorithm for public-key cryptography 
 which is based on the Diffie–Hellman key exchange. It was described by Taher Elgamal in 1985.
 ElGamal encryption is used in the free GNU Privacy Guard software, recent versions of PGP, and other cryptosystems. 
 The Digital Signature Algorithm (DSA) is a variant of the ElGamal signature scheme, which should not be confused with ElGamal encryption.


To use this module : 

```bash
pentbox --mode asymmetric
```


## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.



