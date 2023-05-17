with Interfaces; use Interfaces;
with Ada.Directories; use Ada.Directories;

package body AEAD is
	-- 2.6.  Generating the Poly1305 Key Using ChaCha20
	function Poly1305_Key_Gen(Key: ChaCha20.Key_8; Nonce: ChaCha20.Nonce_8) return Poly1305.Key is
	begin
		return Poly1305.Key(ChaCha20.Block(Key, 0, Nonce)(Poly1305.Key'Range));
	end Poly1305_Key_Gen;


	-- 2.8.  AEAD Construction
	procedure Encrypt(
		Additional_Auth_Data : Byte_Array;
		Key : ChaCha20.Key_8;
		Nonce : ChaCha20.Nonce_8;
		Plain_Text : Byte_Array;
		Cipher_Text : out Byte_Array_Access;
		Tag: out Unsigned_8x16
	) is
		function Aligned_Size(N: Integer) return Integer is (16 * Ceil_Div(N, 16));

		One_Time_Key : Poly1305.Key;
		Mac_Data_Size, Offset : Integer := 0;
		Mac_Data : Byte_Array_Access;
	begin
		One_Time_Key := Poly1305_Key_Gen(Key, Nonce);
		Cipher_Text := ChaCha20.Encrypt(Key, 1, Nonce, Plain_Text);

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

		Tag := Poly1305.Mac(Mac_Data.all, One_Time_Key);

		Delete(Mac_Data);
	end Encrypt;


	function Decrypt(
		Additional_Auth_Data: Byte_Array;
		Key: ChaCha20.Key_8;
		Nonce: ChaCha20.Nonce_8;
		Cipher_Text: Byte_Array;
		Expected_Tag: Unsigned_8x16;
		Plain_Text: out Byte_Array_Access
	) return Boolean is
		function Aligned_Size(N: Integer) return Integer is (16 * Ceil_Div(N, 16));

		One_Time_Key : Poly1305.Key;
		Mac_Data_Size, Offset : Integer := 0;
		Mac_Data : Byte_Array_Access;
		Tag: Unsigned_8x16;
	begin
		One_Time_Key := Poly1305_Key_Gen(Key, Nonce);

		Mac_Data_Size := Aligned_Size(Additional_Auth_Data'Length)
			+ Aligned_Size(Cipher_Text'Length)
			+ 2 * 8;

		Mac_Data := new Byte_Array(1 .. File_Size(Mac_Data_Size));
		Mac_Data.all := (others => 0);

		Mac_Data.all(1 .. File_Size(Additional_Auth_Data'Length)) := Byte_Array(Additional_Auth_Data);
		Offset := Aligned_Size(Integer(Additional_Auth_Data'Last)) + 1;

		Mac_Data.all(File_Size(Offset) .. (File_Size(Offset) + Cipher_Text'Last - 1)) := Cipher_Text;
		Offset := Offset + Aligned_Size(Integer(Cipher_Text'Last));

		Mac_Data.all(File_Size(Offset) .. File_Size(Offset + 7)) := Byte_Array(Bytes(Unsigned_64(Additional_Auth_Data'Length)));
		Offset := Offset + 8;
		Mac_Data.all(File_Size(Offset) .. File_Size(Offset + 7)) := Byte_Array(Bytes(Unsigned_64(Cipher_Text'Length)));

		Tag := Poly1305.Mac(Mac_Data.all, One_Time_Key);

		if Tag /= Expected_Tag then
			return False;
		end if;

		Plain_Text := ChaCha20.Encrypt(Key, 1, Nonce, Cipher_Text);
		Delete(Mac_Data);
		return True;
	end Decrypt;
end AEAD;
