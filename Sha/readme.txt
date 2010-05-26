SHA implements secure hash functions that can be used for cryptography, data integrity and security purposes.

Sha covers the following standards:
	SHA-1 (FIPS 180-2)
	SHA-256 (FIPS 180-2)
	HMAC-SHA-1 (FIPS 198a)
	HMAC-SHA-256 (FIPS 198a)

What is a hash function?
	A hash function takes a message, and generates a number.
	A good hash function has the following properties:
		The number is large enough that you will never find two messages with the same number (a 'collision')
		It is computationally unfeasible to extract message information from its hash (without trying every possible combination)
		A small (1 bit) change in the message will produce a huge (approximately half of all bits) change in the hash.
		Fast to calculate

	SHA is slower than simple hashes (eg. parity), but has very high security - high enough to be used in currency transactions and confidential documents.
	SHA-1 is currently secure, but there is some suggestion it may not be for much longer.
	SHA-256 is slightly slower, but has higher security.

What is an HMAC?
	HMACs are Hashed Message Authentication Codes. Using them, it is possible to prove that you have a secret key without actually disclosing it.
