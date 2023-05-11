pragma Ada_2022;
with Common;

with Ada.Assertions;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Numerics.Big_Numbers.Big_Integers;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Ada.Unchecked_Conversion;

use Ada.Assertions;
use Ada.Directories;
use Ada.Numerics.Big_Numbers.Big_Integers;
use Ada.Text_IO;

with Common; use Common;
with Interfaces; use Interfaces;


-- Implementation of ChaCha20-Poly1305 as defined in RFC 7539
-- https://www.rfc-editor.org/rfc/rfc7539
procedure Chacha20_Poly1305 is
	-- 2.1.  The ChaCha Quarter Round
	procedure QR(A, B, C, D : in out Unsigned_32) is
	begin
		A := A + B; D := D xor A; D := Rotate_Left(D, 16);
		C := C + D; B := B xor C; B := Rotate_Left(B, 12);
		A := A + B; D := D xor A; D := Rotate_Left(D,  8);
		C := C + D; B := B xor C; B := Rotate_Left(B,  7);
	end QR;

	-- 2.1.1.  Test Vector for the ChaCha Quarter Round
	procedure QR_Test is
		A : Unsigned_32 := 16#11111111#;
		B : Unsigned_32 := 16#01020304#;
		C : Unsigned_32 := 16#9b8d6f43#;
		D : Unsigned_32 := 16#01234567#;
	begin
		QR(A, B, C, D);
		Assert(A = 16#ea2a92f4#, "Failed QR_Test #1");
		Assert(B = 16#cb1cf8ce#, "Failed QR_Test #2");
		Assert(C = 16#4581472e#, "Failed QR_Test #3");
		Assert(D = 16#5881c4bb#, "Failed QR_Test #4");
	end QR_Test;

	type ChaCha20_State_Index is range 0 .. 15;
	type ChaCha20_State is array (ChaCha20_State_Index) of Unsigned_32;

	function "+"(L, R: ChaCha20_State) return ChaCha20_State is
		Result: ChaCha20_State;
	begin
		for I in ChaCha20_State'Range loop Result(I) := L(I) + R(I); end loop;
		return Result;
	end;

	-- 2.2.  A Quarter Round on the ChaCha State
	procedure Quarter_Round(S: in out ChaCha20_State; A, B, C, D: ChaCha20_State_Index) is
	begin
		QR(S(A), S(B), S(C), S(D));
	end Quarter_Round;

	-- 2.2.1.  Test Vector for the Quarter Round on the ChaCha State
	procedure Quarter_Round_Test is
		State : ChaCha20_State := (
			16#879531e0#, 16#c5ecf37d#, 16#516461b1#, 16#c9a62f8a#,
			16#44c20ef3#, 16#3390af7f#, 16#d9fc690b#, 16#2a5f714c#,
			16#53372767#, 16#b00a5631#, 16#974c541a#, 16#359e9963#,
			16#5c971061#, 16#3d631689#, 16#2098d9d6#, 16#91dbd320#
		);

		Expected_State : constant ChaCha20_State := (
			16#879531e0#, 16#c5ecf37d#, 16#bdb886dc#, 16#c9a62f8a#,
			16#44c20ef3#, 16#3390af7f#, 16#d9fc690b#, 16#cfacafd2#,
			16#e46bea80#, 16#b00a5631#, 16#974c541a#, 16#359e9963#,
			16#5c971061#, 16#ccc07c79#, 16#2098d9d6#, 16#91dbd320#
		);
	begin
		Quarter_Round(State, 2, 7, 8, 13);
		Assert(State = Expected_State, "Failed Quarter_Round_Test");
	end Quarter_Round_Test;


	type ChaCha20_Key_32   is array (0..7)  of Unsigned_32;
	type ChaCha20_Key_8    is new Unsigned_8x32;
	type ChaCha20_Nonce_32 is array (0..2)  of Unsigned_32;
	type ChaCha20_Nonce_8  is array (0..11) of Unsigned_8;

	function Bytes is new Ada.Unchecked_Conversion(Source => ChaCha20_State,   Target => Unsigned_8x64);
	function Ints  is new Ada.Unchecked_Conversion(Source => ChaCha20_Key_8,   Target => ChaCha20_Key_32);
	function Ints  is new Ada.Unchecked_Conversion(Source => ChaCha20_Nonce_8, Target => ChaCha20_Nonce_32);

	-- 2.3.  The ChaCha20 Block Function
	function ChaCha20_Block(K: ChaCha20_Key_32; Counter: Unsigned_32; N: ChaCha20_Nonce_32) return Unsigned_8x64 is
		State : ChaCha20_State;
		Working_State : ChaCha20_State;
	begin
		State(0..3) := (16#61707865#, 16#3320646e#, 16#79622d32#, 16#6b206574#);
		for I in ChaCha20_Key_32'Range loop State(ChaCha20_State_Index(I+4)) := K(I); end loop;
		State(12) := Counter;
		for I in ChaCha20_Nonce_32'Range loop State(ChaCha20_State_Index(I+13)) := N(I); end loop;

		Working_State := State;

		for I in 1..10 loop
			Quarter_Round(Working_State, 0, 4,  8, 12);
			Quarter_Round(Working_State, 1, 5,  9, 13);
			Quarter_Round(Working_State, 2, 6, 10, 14);
			Quarter_Round(Working_State, 3, 7, 11, 15);

			Quarter_Round(Working_State, 0, 5, 10, 15);
			Quarter_Round(Working_State, 1, 6, 11, 12);
			Quarter_Round(Working_State, 2, 7,  8, 13);
			Quarter_Round(Working_State, 3, 4,  9, 14);
		end loop;

		State := State + Working_State;
		return Bytes(State);
	end ChaCha20_Block;

	function ChaCha20_Block(K: ChaCha20_Key_8; Counter: Unsigned_32; N: ChaCha20_Nonce_8) return Unsigned_8x64 is
	begin
		return ChaCha20_Block(Ints(K), Counter, Ints(N));
	end;

	-- 2.3.2.  Test Vector for the ChaCha20 Block Function
	procedure ChaCha20_Block_Test is
		Key : constant ChaCha20_Key_8 := (
			16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
			16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#,
			16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
			16#18#, 16#19#, 16#1a#, 16#1b#, 16#1c#, 16#1d#, 16#1e#, 16#1f#
		);

		Nonce : constant ChaCha20_Nonce_8 := (
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
		Assert(ChaCha20_Block(Key, Block_Count, Nonce) = Expected_Serialized_Block, "Failed ChaCha20_Block_Test");
	end ChaCha20_Block_Test;


	-- 2.4.  The ChaCha20 Encryption Algorithm
	function ChaCha20_Encrypt(
		Key: ChaCha20_Key_8;
		Initial_Counter: Unsigned_32;
		Nonce: ChaCha20_Nonce_8;
		Plain_Text: Byte_Array
	) return Byte_Array_Access is
		Full_Iterations : Unsigned_32;
		Key_Stream : Unsigned_8x64;
		Encrypted : Byte_Array_Access;
		Index : File_Size;
	begin
		Full_Iterations := Unsigned_32(Plain_Text'Length/64 - 1);

		Encrypted := new Byte_Array(1..Plain_Text'Length);

		for J in 0..Full_Iterations loop
			Key_Stream := ChaCha20_Block(Key, Initial_Counter+J, Nonce);

			for I in 0 .. 63 loop
				Index := File_Size(J * 64 + Unsigned_32(I) + 1);
				Encrypted(Index) := Plain_Text(Index) xor Key_Stream(I);
			end loop;
		end loop;

		if (Plain_Text'Length mod 64) /= 0 then
			Key_Stream := ChaCha20_Block(Key, Initial_Counter+Full_Iterations+1, Nonce);
			for I in 0 .. Integer((Plain_Text'Last mod 64) - 1) loop
				Index := File_Size((Full_Iterations+1)*64 + 1 + Unsigned_32(I));
				Encrypted(Index) := Key_Stream(I) xor Plain_Text(Index);
			end loop;
		end if;

		return Encrypted;
	end ChaCha20_Encrypt;

	-- 2.4.2.  Example and Test Vector for the ChaCha20 Cipher
	procedure ChaCha20_Encrypt_Test is
		Key : ChaCha20_Key_8;
		Initial_Counter : constant Unsigned_32 := 1;
		Nonce : constant ChaCha20_Nonce_8 := (
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
		for I in ChaCha20_Key_8'Range loop Key(I) := Interfaces.Unsigned_8(I); end loop;
		Encrypted := ChaCha20_Encrypt(Key, Initial_Counter, Nonce, Plain_Text.all);

		Assert(Encrypted.all = Expected_Encrypted, "Failed ChaCha20_Encrypt_Test");

		Delete(Encrypted);
		Delete(Plain_Text);
	end ChaCha20_Encrypt_Test;


	type Poly1305_Key is new Unsigned_8x32;

	function To_Big_Integer(B: Unsigned_8x16) return Big_Integer is
		Result : Big_Integer := 0;
		Index : File_Size;
	begin
		for J in reverse Unsigned_8x16'Range loop
				Result := Result * 256 + To_Big_Integer(Integer(B(J)));
		end loop;
		return Result;
	end To_Big_Integer;

	-- 2.5.  The Poly1305 Algorithm
	function Poly1305_Mac(Message: Byte_Array; Key: Poly1305_Key) return Unsigned_8x16 is
		package UC is new Ada.Numerics.Big_Numbers.Big_Integers.Unsigned_Conversions(Unsigned_8);

		function Clamp(R: Unsigned_8x16) return Unsigned_8x16 is
			Result : Unsigned_8x16 := R;
		begin
			Result(3)  := Result(3)  and 15;
			Result(7)  := Result(7)  and 15;
			Result(11) := Result(11) and 15;
			Result(15) := Result(15) and 15;
			Result(4)  := Result(4)  and 252;
			Result(8)  := Result(8)  and 252;
			Result(12) := Result(12) and 252;
			return Result;
		end Clamp;

		function Number_At(I: Integer) return Big_Integer is
			Result : Big_Integer := 1;
			Index : File_Size;
		begin
			for J in reverse 1 .. 16 loop
				Index := File_Size((I-1)*16 + J);
				if Index <= Message'Last then
					Result := Result * 256 + To_Big_Integer(Integer(Message(Index)));
				end if;
			end loop;
			return Result;
		end Number_At;

		R, S, Accumulator, N : Big_Integer := 0;
		P : constant Big_Integer := (2 ** 130) - 5;
		Result : Unsigned_8x16 := (others => 0);
	begin
		R := To_Big_Integer(Clamp(Unsigned_8x16(Key( 0 .. 15))));
		S := To_Big_Integer(Unsigned_8x16(Key(16 .. 31)));

		for I in 1 .. Ceil_Div(Message'Length, 16) loop
			N := (Accumulator + Number_At(I)) * R;
			Accumulator := N mod P;
		end loop;
		Accumulator := Accumulator + S;

		for I in Unsigned_8x16'Range loop
			Result(I) := UC.From_Big_Integer(Accumulator mod 256);
			Accumulator := Accumulator / 256;
		end loop;

		return Result;
	end Poly1305_Mac;

	procedure Poly1305_Mac_Test is
		Key : Poly1305_Key := (
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
		Tag := Poly1305_Mac(Message.all, Key);
		Assert(Tag = Expected_Tag, "Failed Poly1305_Mac_Test");

		Delete(Message);
	end Poly1305_Mac_Test;

	-- 2.6.  Generating the Poly1305 Key Using ChaCha20
	function Poly1305_Key_Gen(Key: ChaCha20_Key_8; Nonce: ChaCha20_Nonce_8) return Poly1305_Key is
	begin
		return Poly1305_Key(ChaCha20_Block(Key, 0, Nonce)(Poly1305_Key'Range));
	end Poly1305_Key_Gen;

	-- 2.6.2.  Poly1305 Key Generation Test Vector
	procedure Poly1305_Key_Gen_Test is
	begin
		null; -- TODO: Implement me
	end Poly1305_Key_Gen_Test;

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

	procedure ChaCha20_Aead_Encrypt_Test is
		Plain_Text_String : String := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		Plain_Text : Byte_Array_Access := Bytes(Plain_Text_String);

		AAD : Byte_Array_Access := Bytes("PQRS........");
		Key : ChaCha20_Key_8;
		Nonce : ChaCha20_Nonce_8 := (7, 0, 0, 0, 16#40#, 16#41#, 16#42#, 16#43#, 16#44#, 16#45#, 16#46#, 16#47#);
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

		for I in ChaCha20_Key_8'Range loop
			Key(I) := Unsigned_8(16#80# + (I - ChaCha20_Key_8'First));
		end loop;

		ChaCha20_Aead_Encrypt(AAD.all, Key, Nonce, Plain_Text.all, Cipher_Text, Tag);

		Assert(Cipher_Text.all = Expected_Ciphertext, "Failed in ChaCha20_Aead_Encrypt Cipher_Text");
		Assert(Tag = Expected_Tag, "Failed in ChaCha20_Aead_Encrypt Tag");

		Delete(Cipher_Text);
		Delete(AAD);
	end ChaCha20_Aead_Encrypt_Test;

	procedure Tests is
	begin
		QR_Test;
		Quarter_Round_Test;
		ChaCha20_Block_Test;
		ChaCha20_Encrypt_Test;
		Poly1305_Mac_Test;
		ChaCha20_Aead_Encrypt_Test;
	end Tests;

	procedure Usage is
	begin
		Put_Line("usage:");
		Put_Line("  chacha20_poly1305 <AAD file> <key file> <nonce file> <in file> <out file>");
	end Usage;

	Additional_Auth_Data, Key, Nonce, Input, Output : Byte_Array_Access;
	Tag : Unsigned_8x16;
begin
	Tests;

	if Ada.Command_Line.Argument_Count /= 5 then
		Usage;
		Ada.Command_Line.Set_Exit_Status(Ada.Command_Line.Failure);
		return;
	end if;

	Additional_Auth_Data := Read_Binary_File(Ada.Command_Line.Argument(1));
	Key                  := Read_Binary_File(Ada.Command_Line.Argument(2));
	Nonce                := Read_Binary_File(Ada.Command_Line.Argument(3));
	Input                := Read_Binary_File(Ada.Command_Line.Argument(4));

	ChaCha20_Aead_Encrypt(
		Additional_Auth_Data.all,
		ChaCha20_Key_8(Key.all),
		ChaCha20_Nonce_8(Nonce.all),
		Input.all,
		Output,
		Tag
	);

	Write_Binary_File(Ada.Command_Line.Argument(5), Output.all);

	Put("Tag: ");
	for I in reverse Tag'Range loop
		Put(Hex(Tag(I)));
	end loop;
	New_Line;

	Delete(Additional_Auth_Data);
	Delete(Input);
	Delete(Key);
	Delete(Nonce);
	Delete(Output);
end Chacha20_Poly1305;
