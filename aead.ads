with Common; use Common;
with ChaCha20; use ChaCha20;
with Poly1305; use Poly1305;

package AEAD is
	-- 2.6.  Generating the Poly1305 Key Using ChaCha20
	function Poly1305_Key_Gen(Key: ChaCha20_Key_8; Nonce: ChaCha20_Nonce_8) return Poly1305_Key;

	-- 2.8.  AEAD Construction
	procedure ChaCha20_Aead_Encrypt(
		Additional_Auth_Data : Byte_Array;
		Key : ChaCha20_Key_8;
		Nonce : ChaCha20_Nonce_8;
		Plain_Text : Byte_Array;
		Cipher_Text : out Byte_Array_Access;
		Tag: out Unsigned_8x16
	);
end AEAD;
