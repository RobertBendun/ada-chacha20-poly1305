with Interfaces; use Interfaces;
with Ada.Directories; use Ada.Directories;

package body AEAD is
	-- 2.6.  Generating the Poly1305 Key Using ChaCha20
	function Poly1305_Key_Gen(Key: ChaCha20_Key_8; Nonce: ChaCha20_Nonce_8) return Poly1305_Key is
	begin
		return Poly1305_Key(ChaCha20_Block(Key, 0, Nonce)(Poly1305_Key'Range));
	end Poly1305_Key_Gen;


	-- 2.8.  AEAD Construction
	procedure ChaCha20_Aead_Encrypt(
		Additional_Auth_Data : Byte_Array;
		Key : ChaCha20_Key_8;
		Nonce : ChaCha20_Nonce_8;
		Plain_Text : Byte_Array;
		Cipher_Text : out Byte_Array_Access;
		Tag: out Unsigned_8x16
	) is
		function Aligned_Size(N: Integer) return Integer is (16 * Ceil_Div(N, 16));

		One_Time_Key : Poly1305_Key;
		Mac_Data_Size, Offset : Integer := 0;
		Mac_Data : Byte_Array_Access;
	begin
		One_Time_Key := Poly1305_Key_Gen(Key, Nonce);
		Cipher_Text := ChaCha20_Encrypt(Key, 1, Nonce, Plain_Text);

		Mac_Data_Size := Aligned_Size(Additional_Auth_Data'Length)
			+ Aligned_Size(Cipher_Text'Length)
			+ 2 * 8;

		Mac_Data := new Byte_Array(1 .. File_Size(Mac_Data_Size));
		Mac_Data.all := (others => 0);

		Mac_Data.all(1 .. File_Size(Additional_Auth_Data'Length)) := Byte_Array(Additional_Auth_Data);
		Offset := Aligned_Size(Integer(Additional_Auth_Data'Last)) + 1;

		Mac_Data.all(File_Size(Offset) .. (File_Size(Offset) + Cipher_Text'Last - 1)) := Cipher_Text.all;
		Offset := Offset + Aligned_Size(Integer(Cipher_Text'Last));

		Mac_Data.all(File_Size(Offset) .. File_Size(Offset + 7)) := Byte_Array(Bytes(Unsigned_64(Additional_Auth_Data'Length)));
		Offset := Offset + 8;
		Mac_Data.all(File_Size(Offset) .. File_Size(Offset + 7)) := Byte_Array(Bytes(Unsigned_64(Cipher_Text'Length)));

		Tag := Poly1305_Mac(Mac_Data.all, One_Time_Key);

		Delete(Mac_Data);
	end ChaCha20_Aead_Encrypt;
end AEAD;
