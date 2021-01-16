import pyinputplus as pyip
import string
import pyfiglet
import stdiomask

import hashlib
import math
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from hashlib import sha512
import elgamal


class AsymmetricEncryption:

	elGamalKeys = elgamal.generate_keys()

	key = RSA.generate(2048)
	

	public_key = key.publickey().export_key()
	file_out = open("receiver.pem", "wb")
	file_out.write(public_key)
	file_out.close()

	private_key = key.export_key()
	file_out = open("private.pem", "wb")
	file_out.write(private_key)
	file_out.close()

	@classmethod
	def encrypt(cls, method='RSA'):
		plaintext = pyip.inputStr('enter data for encryption :  ')
		plaintext = str.encode(plaintext)

		if(method=='RSA'):
			choice = pyip.inputMenu(['Encrypt message', 'Sign message'])
			if(choice=='Encrypt message'):
				cipher = AsymmetricEncryption.rsaEncrypt(plaintext)
				return('encrypt',cipher)
			elif(choice=='Sign message'):
				signature = AsymmetricEncryption.rsaSign(plaintext)
				return('sign', signature)
		elif(method=='ElGamal'):
			cipher = AsymmetricEncryption.elgamalEncrypt(plaintext.decode())
			return('encrypt', cipher)

	@classmethod
	def decrypt(cls, method='RSA', choice='encrypt', signature=''):
		if(method=='RSA'):
			if(choice=='encrypt'):
				AsymmetricEncryption.rsaDecrypt()
			elif (choice=='sign'):
				msg = pyip.inputStr('Enter the original message :  ')
				AsymmetricEncryption.rsaVerifySignature(str.encode(msg), signature)
		elif (method == 'ElGamal'):
			AsymmetricEncryption.elgamaDecrypt(signature)



	############### RSA ####################
	@classmethod
	def rsaEncrypt(self, ch):
	
		file_encryption = open("encrypted_data.bin", "wb")


		recipient_key = self.public_key
		session_key = get_random_bytes(16)

		# Encrypt the session key with the public RSA key
		cipher_rsa = PKCS1_OAEP.new(self.key.publickey())
		enc_session_key = cipher_rsa.encrypt(session_key)

		# Encrypt the data with the AES session key
		cipher_aes = AES.new(session_key, AES.MODE_EAX)
		ciphertext, tag = cipher_aes.encrypt_and_digest(ch)
		[ file_encryption.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
		file_encryption.close()
		print(ciphertext)
		print(tag)
		print(cipher_aes.nonce)
		print(enc_session_key)
		return ciphertext

	@classmethod
	def rsaDecrypt(self):

		private_key = RSA.import_key(open("private.pem").read())

		file_decryption = open("encrypted_data.bin", "rb")


		enc_session_key, nonce, tag, ciphertext = \
			[ file_decryption.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

		# Decrypt the session key with the private RSA key
		cipher_rsa = PKCS1_OAEP.new(private_key)
		session_key = cipher_rsa.decrypt(enc_session_key)

		# Decrypt the data with the AES session key
		cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
		data = cipher_aes.decrypt_and_verify(ciphertext, tag)
		print(data.decode("utf-8"))

	@classmethod
	def rsaSign (self, msg):
		hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
		signature = pow(hash, self.key.d, self.key.n)
		print(signature)
		return signature

	@classmethod
	def rsaVerifySignature(self, msg, signature):
		hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
		hashFromSignature = pow(signature, self.key.e, self.key.n)
		print("Signature valid:", hash == hashFromSignature)


	############### ELGAMAL ####################

	@classmethod
	def elgamalEncrypt(self, msg):
		cipher = elgamal.encrypt(self.elGamalKeys['publicKey'], msg)
		print(cipher)
		return cipher

	@classmethod
	def elgamaDecrypt(self, cipher):
		plaintext = elgamal.decrypt(self.elGamalKeys['privateKey'], cipher)
		print (plaintext)
		
	@classmethod
	def menu(cls):
		ascii_banner = pyfiglet.figlet_format("ASYMMETRIC ENCRYPTION") 
		print(ascii_banner)

		while(True):
			choice = pyip.inputMenu(['encryption', 'quit'])
			if(choice=='encryption'):
				method = pyip.inputMenu(['RSA', 'ElGamal'])
				print(method)
				if(method=='RSA'):
					choice, signature = AsymmetricEncryption.encrypt(method=method)
				else: 
					choice, cipher = AsymmetricEncryption.encrypt(method=method)
				
				print('\nFor decryption: \n')
				decrypt = pyip.inputMenu(['yes','no'])
				if(decrypt=='no'):
					continue
				elif(method=='RSA'):
					AsymmetricEncryption.decrypt(method,choice, signature)
				elif(method=='ElGamal'):
					AsymmetricEncryption.decrypt(method,choice, cipher)
				

			else:
				return

asym = AsymmetricEncryption()
asym.menu()


		
		



		