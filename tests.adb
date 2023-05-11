with Ada.Assertions; use Ada.Assertions;
with Ada.Directories; use Ada.Directories;
with Common; use Common;
with Interfaces; use Interfaces;

with ChaCha20;
with Poly1305;
with AEAD;

use type ChaCha20.State;

package body Tests is
	procedure Run is
	begin
		QR_Test;
		Quarter_Round_Test;
		ChaCha20_Block_Test;
		ChaCha20_Encrypt_Test;
		Poly1305_Mac_Test;
		ChaCha20_Aead_Encrypt_Test;
	end Run;

	-- 2.1.1.  Test Vector for the ChaCha Quarter Round
	procedure QR_Test is
		A : Unsigned_32 := 16#11111111#;
		B : Unsigned_32 := 16#01020304#;
		C : Unsigned_32 := 16#9b8d6f43#;
		D : Unsigned_32 := 16#01234567#;
	begin
		ChaCha20.QR(A, B, C, D);
		Assert(A = 16#ea2a92f4#, "Failed QR_Test #1");
		Assert(B = 16#cb1cf8ce#, "Failed QR_Test #2");
		Assert(C = 16#4581472e#, "Failed QR_Test #3");
		Assert(D = 16#5881c4bb#, "Failed QR_Test #4");
	end QR_Test;

	-- 2.2.1.  Test Vector for the Quarter Round on the ChaCha State
	procedure Quarter_Round_Test is
		State : ChaCha20.State := (
			16#879531e0#, 16#c5ecf37d#, 16#516461b1#, 16#c9a62f8a#,
			16#44c20ef3#, 16#3390af7f#, 16#d9fc690b#, 16#2a5f714c#,
			16#53372767#, 16#b00a5631#, 16#974c541a#, 16#359e9963#,
			16#5c971061#, 16#3d631689#, 16#2098d9d6#, 16#91dbd320#
		);

		Expected_State : constant ChaCha20.State := (
			16#879531e0#, 16#c5ecf37d#, 16#bdb886dc#, 16#c9a62f8a#,
			16#44c20ef3#, 16#3390af7f#, 16#d9fc690b#, 16#cfacafd2#,
			16#e46bea80#, 16#b00a5631#, 16#974c541a#, 16#359e9963#,
			16#5c971061#, 16#ccc07c79#, 16#2098d9d6#, 16#91dbd320#
		);
	begin
		ChaCha20.Quarter_Round(State, 2, 7, 8, 13);
		Assert(State = Expected_State, "Failed Quarter_Round_Test");
	end Quarter_Round_Test;

	-- 2.3.2.  Test Vector for the ChaCha20 Block Function
	procedure ChaCha20_Block_Test is
		Key : constant ChaCha20.Key_8 := (
			16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
			16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#,
			16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
			16#18#, 16#19#, 16#1a#, 16#1b#, 16#1c#, 16#1d#, 16#1e#, 16#1f#
		);

		Nonce : constant ChaCha20.Nonce_8 := (
			16#00#, 16#00#, 16#00#, 16#09#,
			16#00#, 16#00#, 16#00#, 16#4a#,
			16#00#, 16#00#, 16#00#, 16#00#
		);

		Block_Count : constant Unsigned_32 := 1;

		Expected_Serialized_Block : constant Unsigned_8x64 := (
			16#10#, 16#f1#, 16#e7#, 16#e4#, 16#d1#, 16#3b#, 16#59#, 16#15#,
			16#50#, 16#0f#, 16#dd#, 16#1f#, 16#a3#, 16#20#, 16#71#, 16#c4#,
			16#c7#, 16#d1#, 16#f4#, 16#c7#, 16#33#, 16#c0#, 16#68#, 16#03#,
			16#04#, 16#22#, 16#aa#, 16#9a#, 16#c3#, 16#d4#, 16#6c#, 16#4e#,
			16#d2#, 16#82#, 16#64#, 16#46#, 16#07#, 16#9f#, 16#aa#, 16#09#,
			16#14#, 16#c2#, 16#d7#, 16#05#, 16#d9#, 16#8b#, 16#02#, 16#a2#,
			16#b5#, 16#12#, 16#9c#, 16#d1#, 16#de#, 16#16#, 16#4e#, 16#b9#,
			16#cb#, 16#d0#, 16#83#, 16#e8#, 16#a2#, 16#50#, 16#3c#, 16#4e#
		);
	begin
		Assert(ChaCha20.Block(Key, Block_Count, Nonce) = Expected_Serialized_Block, "Failed ChaCha20.Block_Test");
	end ChaCha20_Block_Test;

	-- 2.4.2.  Example and Test Vector for the ChaCha20 Cipher
	procedure ChaCha20_Encrypt_Test is
		Key : ChaCha20.Key_8;
		Initial_Counter : constant Unsigned_32 := 1;
		Nonce : constant ChaCha20.Nonce_8 := (
			16#00#, 16#00#, 16#00#, 16#00#,
			16#00#, 16#00#, 16#00#, 16#4a#,
			16#00#, 16#00#, 16#00#, 16#00#
		);

		Plain_Text_String : String := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		Plain_Text : Byte_Array_Access := Bytes(Plain_Text_String);
		Encrypted : Byte_Array_Access;

		Expected_Encrypted : Byte_Array := (
			16#6e#, 16#2e#, 16#35#, 16#9a#, 16#25#, 16#68#, 16#f9#, 16#80#, 16#41#, 16#ba#, 16#07#, 16#28#, 16#dd#, 16#0d#, 16#69#, 16#81#,
			16#e9#, 16#7e#, 16#7a#, 16#ec#, 16#1d#, 16#43#, 16#60#, 16#c2#, 16#0a#, 16#27#, 16#af#, 16#cc#, 16#fd#, 16#9f#, 16#ae#, 16#0b#,
			16#f9#, 16#1b#, 16#65#, 16#c5#, 16#52#, 16#47#, 16#33#, 16#ab#, 16#8f#, 16#59#, 16#3d#, 16#ab#, 16#cd#, 16#62#, 16#b3#, 16#57#,
			16#16#, 16#39#, 16#d6#, 16#24#, 16#e6#, 16#51#, 16#52#, 16#ab#, 16#8f#, 16#53#, 16#0c#, 16#35#, 16#9f#, 16#08#, 16#61#, 16#d8#,
			16#07#, 16#ca#, 16#0d#, 16#bf#, 16#50#, 16#0d#, 16#6a#, 16#61#, 16#56#, 16#a3#, 16#8e#, 16#08#, 16#8a#, 16#22#, 16#b6#, 16#5e#,
			16#52#, 16#bc#, 16#51#, 16#4d#, 16#16#, 16#cc#, 16#f8#, 16#06#, 16#81#, 16#8c#, 16#e9#, 16#1a#, 16#b7#, 16#79#, 16#37#, 16#36#,
			16#5a#, 16#f9#, 16#0b#, 16#bf#, 16#74#, 16#a3#, 16#5b#, 16#e6#, 16#b4#, 16#0b#, 16#8e#, 16#ed#, 16#f2#, 16#78#, 16#5e#, 16#42#,
			16#87#, 16#4d#
		);

	begin
		for I in ChaCha20.Key_8'Range loop Key(I) := Interfaces.Unsigned_8(I); end loop;
		Encrypted := ChaCha20.Encrypt(Key, Initial_Counter, Nonce, Plain_Text.all);

		Assert(Encrypted.all = Expected_Encrypted, "Failed ChaCha20.Encrypt_Test");

		Delete(Encrypted);
		Delete(Plain_Text);
	end ChaCha20_Encrypt_Test;

	procedure Poly1305_Mac_Test is
		Key : Poly1305.Key := (
			16#85#, 16#d6#, 16#be#, 16#78#, 16#57#, 16#55#, 16#6d#, 16#33#,
			16#7f#, 16#44#, 16#52#, 16#fe#, 16#42#, 16#d5#, 16#06#, 16#a8#,
			16#01#, 16#03#, 16#80#, 16#8a#, 16#fb#, 16#0d#, 16#b2#, 16#fd#,
			16#4a#, 16#bf#, 16#f6#, 16#af#, 16#41#, 16#49#, 16#f5#, 16#1b#
		);

		Message_String : String := "Cryptographic Forum Research Group";
		Message : Byte_Array_Access := Bytes(Message_String);

		Tag : Unsigned_8x16;

		Expected_Tag : constant Unsigned_8x16 := (
			16#a8#, 16#06#, 16#1d#, 16#c1#, 16#30#, 16#51#, 16#36#, 16#c6#,
			16#c2#, 16#2b#, 16#8b#, 16#af#, 16#0c#, 16#01#, 16#27#, 16#a9#
		);
	begin
		Tag := Poly1305.Mac(Message.all, Key);
		Assert(Tag = Expected_Tag, "Failed Poly1305_Mac_Test");

		Delete(Message);
	end Poly1305_Mac_Test;

	-- 2.6.2.  Poly1305 Key Generation Test Vector
	procedure Poly1305_Key_Gen_Test is
	begin
		null; -- TODO: Implement me
	end Poly1305_Key_Gen_Test;

	procedure ChaCha20_Aead_Encrypt_Test is
		Plain_Text_String : String := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		Plain_Text : Byte_Array_Access := Bytes(Plain_Text_String);

		AAD : Byte_Array_Access := Bytes("PQRS........");
		Key : ChaCha20.Key_8;
		Nonce : ChaCha20.Nonce_8 := (7, 0, 0, 0, 16#40#, 16#41#, 16#42#, 16#43#, 16#44#, 16#45#, 16#46#, 16#47#);
		Cipher_Text : Byte_Array_Access;
		Tag : Unsigned_8x16;

		Expected_Tag : constant Unsigned_8x16 := (
			16#1a#, 16#e1#, 16#0b#, 16#59#, 16#4f#, 16#09#, 16#e2#, 16#6a#, 16#7e#, 16#90#, 16#2e#, 16#cb#, 16#d0#, 16#60#, 16#06#, 16#91#
		);

		Expected_Ciphertext : constant Byte_Array := (
			16#d3#, 16#1a#, 16#8d#, 16#34#, 16#64#, 16#8e#, 16#60#, 16#db#, 16#7b#, 16#86#, 16#af#, 16#bc#, 16#53#, 16#ef#, 16#7e#, 16#c2#,
			16#a4#, 16#ad#, 16#ed#, 16#51#, 16#29#, 16#6e#, 16#08#, 16#fe#, 16#a9#, 16#e2#, 16#b5#, 16#a7#, 16#36#, 16#ee#, 16#62#, 16#d6#,
			16#3d#, 16#be#, 16#a4#, 16#5e#, 16#8c#, 16#a9#, 16#67#, 16#12#, 16#82#, 16#fa#, 16#fb#, 16#69#, 16#da#, 16#92#, 16#72#, 16#8b#,
			16#1a#, 16#71#, 16#de#, 16#0a#, 16#9e#, 16#06#, 16#0b#, 16#29#, 16#05#, 16#d6#, 16#a5#, 16#b6#, 16#7e#, 16#cd#, 16#3b#, 16#36#,
			16#92#, 16#dd#, 16#bd#, 16#7f#, 16#2d#, 16#77#, 16#8b#, 16#8c#, 16#98#, 16#03#, 16#ae#, 16#e3#, 16#28#, 16#09#, 16#1b#, 16#58#,
			16#fa#, 16#b3#, 16#24#, 16#e4#, 16#fa#, 16#d6#, 16#75#, 16#94#, 16#55#, 16#85#, 16#80#, 16#8b#, 16#48#, 16#31#, 16#d7#, 16#bc#,
			16#3f#, 16#f4#, 16#de#, 16#f0#, 16#8e#, 16#4b#, 16#7a#, 16#9d#, 16#e5#, 16#76#, 16#d2#, 16#65#, 16#86#, 16#ce#, 16#c6#, 16#4b#,
			16#61#, 16#16#
		);
	begin
		for I in 0..7 loop
			AAD.all(File_Size(5+I)) := Unsigned_8(16#c0# + I);
		end loop;

		for I in ChaCha20.Key_8'Range loop
			Key(I) := Unsigned_8(16#80# + (I - ChaCha20.Key_8'First));
		end loop;

		AEAD.Encrypt(AAD.all, Key, Nonce, Plain_Text.all, Cipher_Text, Tag);

		Assert(Cipher_Text.all = Expected_Ciphertext, "Failed in ChaCha20.Aead_Encrypt Cipher_Text");
		Assert(Tag = Expected_Tag, "Failed in ChaCha20.Aead_Encrypt Tag");

		Delete(Cipher_Text);
		Delete(AAD);
	end ChaCha20_Aead_Encrypt_Test;
end Tests;
