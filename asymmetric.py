from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from hashlib import sha512
import elgamal


class Asymmetric:

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


	############### RSA ####################

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

	def rsaSign (self, msg):
		hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
		signature = pow(hash, self.key.d, self.key.n)
		return (signature)

	def rsaVerifySignature(self, msg, sig):
		hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
		hashFromSignature = pow(sig, self.key.e, self.key.n)
		print("Signature valid:", hash == hashFromSignature)


	############### ELGAMAL ####################

	def elgamalEncrypt(self, msg):
		cipher = elgamal.encrypt(self.elGamalKeys['publicKey'], msg)
		return cipher

	def elgamaDecrypt(self,cipher):
		plaintext = elgamal.decrypt(self.elGamalKeys['privateKey'], cipher)
		print (plaintext)
		
		

aasym = Asymmetric()
#aasym.rsaEncrypt('aaaaa'.encode("utf-8"))
#aasym.rsaDecrypt()
#aasym.rsaVerifySignature(str.encode('aaaaaaaa'), aasym.rsaSign(str.encode('aaaaaaaa')))
aasym.elgamaDecrypt(aasym.elgamalEncrypt('aaa'))

		
		



		