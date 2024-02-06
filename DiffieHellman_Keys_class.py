import hashlib
import sys
import secrets

class DiffieHellman:
    def init_function(self):
        # Intialize shared secret
        shared_secret = 0
        key_generator = 2
        # public (prime value) modulus, known to User 1 and 2
        prime_value = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        
        # According to python3 documentation, pow library - is used for generating pub_key, generate random 16 bytes value for private_key
        private_key = int.from_bytes(str(secrets.randbits(32)).encode('utf-8'), byteorder=sys.byteorder, signed=False)
        public_key = pow(key_generator, private_key, prime_value)
        return prime_value,private_key,public_key,shared_secret
    
    def public_key_validaiton(self,client_pub_key):
        prime_value,private_key,public_key,shared_secret= DiffieHellman().init_function()
		# Based on NIST SP800-56, it validates a public key received
        if client_pub_key == None:
            client_pub_key = client_pub_key
        if ( client_pub_key > 2 and client_pub_key < (prime_value - 1)):
            return pow(client_pub_key, (prime_value - 1) // 2, prime_value) == 1
        return False
    
    # Generating the Shared secret value after validating the pub key received from Client, which is a shared key (only known by server and client)
    def generating_diffiehellman_shared_secret(self,client_pub_key):
        prime_value,private_key,public_key,shared_secret= DiffieHellman().init_function()
        if not DiffieHellman().public_key_validaiton(client_pub_key):
            raise Exception("Bad public key provided by the other party")
        else:

            shared_secret_key = pow(client_pub_key, private_key, prime_value)
            shared_secret_key_bitlength = shared_secret_key.bit_length()

            if shared_secret_key_bitlength % 8 != 0:
                shared_secret_key_bitlength = (shared_secret_key_bitlength + 7) // 8 * 8

            shared_secret_key_bytes = shared_secret_key.to_bytes(shared_secret_key_bitlength // 8, sys.byteorder)
            shared_secret = int.from_bytes(hashlib.sha256(shared_secret_key_bytes).digest(), sys.byteorder)
            return shared_secret
