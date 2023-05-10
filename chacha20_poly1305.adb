pragma Ada_2022;
with Ada.Assertions;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Ada.Unchecked_Conversion;
with Ada.Unchecked_Deallocation;
with Interfaces;

use Ada.Assertions;
use Ada.Directories;
use Ada.Text_IO;
use Interfaces;


-- Implementation of ChaCha20-Poly1305 as defined in RFC7539
procedure Chacha20_Poly1305 is
	package SU renames Ada.Strings.Unbounded;

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
		Assert(A = 16#ea2a92f4#);
		Assert(B = 16#cb1cf8ce#);
		Assert(C = 16#4581472e#);
		Assert(D = 16#5881c4bb#);
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
		Assert(State = Expected_State);
	end Quarter_Round_Test;

	type Key_32   is array (0..7)  of Unsigned_32;
	type Key_8    is array (0..31) of Unsigned_8;
	type Nonce_32 is array (0..2)  of Unsigned_32;
	type Nonce_8  is array (0..11) of Unsigned_8;

	type Block is array (0..63) of Unsigned_8;

	function Bytes is new Ada.Unchecked_Conversion(Source => ChaCha20_State, Target => Block);
	function Ints  is new Ada.Unchecked_Conversion(Source => Key_8,   Target => Key_32);
	function Ints  is new Ada.Unchecked_Conversion(Source => Nonce_8, Target => Nonce_32);

	-- 2.3.  The ChaCha20 Block Function
	function ChaCha20_Block(K: Key_32; Counter: Unsigned_32; N: Nonce_32) return Block is
		State : ChaCha20_State;
		Working_State : ChaCha20_State;
	begin
		State(0..3) := (16#61707865#, 16#3320646e#, 16#79622d32#, 16#6b206574#);
		for I in Key_32'Range loop State(ChaCha20_State_Index(I+4)) := K(I); end loop;
		State(12) := Counter;
		for I in Nonce_32'Range loop State(ChaCha20_State_Index(I+13)) := N(I); end loop;

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

	function ChaCha20_Block(K: Key_8; Counter: Unsigned_32; N: Nonce_8) return Block is
	begin
		return ChaCha20_Block(Ints(K), Counter, Ints(N));
	end;

	-- 2.3.2.  Test Vector for the ChaCha20 Block Function
	procedure ChaCha20_Block_Test is
		Key : constant Key_8 := (
			16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
			16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#,
			16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
			16#18#, 16#19#, 16#1a#, 16#1b#, 16#1c#, 16#1d#, 16#1e#, 16#1f#
		);

		Nonce : constant Nonce_8 := (
			16#00#, 16#00#, 16#00#, 16#09#,
			16#00#, 16#00#, 16#00#, 16#4a#,
			16#00#, 16#00#, 16#00#, 16#00#
		);

		Block_Count : constant Unsigned_32 := 1;

		Expected_Serialized_Block : constant Block := (
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
		Assert(ChaCha20_Block(Key, Block_Count, Nonce) = Expected_Serialized_Block);
	end ChaCha20_Block_Test;

	type Byte_Array is array (File_Size range <>) of Unsigned_8;
	type Byte_Array_Access is access Byte_Array;
	procedure Delete is new Ada.Unchecked_Deallocation(Byte_Array, Byte_Array_Access);

	function Bytes(S: String) return Byte_Array_Access is
		Result : Byte_Array_Access;
	begin
		Result := new Byte_Array(1 .. File_Size(S'Length));
		for I in S'Range loop Result(File_Size(I)) := Unsigned_8(Character'Pos(S(I))); end loop;
		return Result;
	end Bytes;

	function Read_Binary_File(Filename: String) return Byte_Array_Access is
		package SIO renames Ada.Streams.Stream_IO;

		Binary_File_Size : File_Size := Ada.Directories.Size(Filename);
		Binary_File_Data : Byte_Array_Access;
		S : SIO.Stream_Access;
		File : SIO.File_Type;
	begin
		Binary_File_Data := new Byte_Array(1..Binary_File_Size);

		SIO.Open(File, SIO.In_File, Filename);
		S := SIO.Stream(File);
		Byte_Array'Read(S, Binary_File_Data.all);

		SIO.Close(File);

		return Binary_File_Data;
	end Read_Binary_File;

	-- 2.4.  The ChaCha20 Encryption Algorithm
	function ChaCha20_Encrypt(
		Key: Key_8;
		Initial_Counter: Unsigned_32;
		Nonce: Nonce_8;
		Plain_Text: Byte_Array
	) return Byte_Array_Access is
		Full_Iterations : Unsigned_32;
		Key_Stream : Block;
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
		Key : Key_8;
		Initial_Counter : constant Unsigned_32 := 1;
		Nonce : constant Nonce_8 := (
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
		for I in Key_8'Range loop Key(I) := Interfaces.Unsigned_8(I); end loop;
		Encrypted := ChaCha20_Encrypt(Key, Initial_Counter, Nonce, Plain_Text.all);

		Assert(Encrypted.all = Expected_Encrypted);
		Delete(Encrypted);
		Delete(Plain_Text);
	end ChaCha20_Encrypt_Test;

	procedure Tests is
	begin
		QR_Test;
		Quarter_Round_Test;
		ChaCha20_Block_Test;
		ChaCha20_Encrypt_Test;
	end Tests;
begin
	Tests;
end Chacha20_Poly1305;
