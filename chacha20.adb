with Ada.Directories; use Ada.Directories;

package body ChaCha20 is

	-- 2.1.  The ChaCha Quarter Round
	procedure QR(A, B, C, D : in out Unsigned_32) is
	begin
		A := A + B; D := D xor A; D := Rotate_Left(D, 16);
		C := C + D; B := B xor C; B := Rotate_Left(B, 12);
		A := A + B; D := D xor A; D := Rotate_Left(D,  8);
		C := C + D; B := B xor C; B := Rotate_Left(B,  7);
	end QR;

	-- 2.2.  A Quarter Round on the ChaCha State
	procedure Quarter_Round(S: in out ChaCha20_State; A, B, C, D: ChaCha20_State_Index) is
	begin
		QR(S(A), S(B), S(C), S(D));
	end Quarter_Round;


	-- 2.3.  The ChaCha20 Block Function
	function ChaCha20_Block(K: ChaCha20_Key_8; Counter: Unsigned_32; N: ChaCha20_Nonce_8) return Unsigned_8x64 is
	begin
		return ChaCha20_Block(Ints(K), Counter, Ints(N));
	end;

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

	function "+"(L, R: ChaCha20_State) return ChaCha20_State is
		Result: ChaCha20_State;
	begin
		for I in ChaCha20_State'Range loop Result(I) := L(I) + R(I); end loop;
		return Result;
	end;
end ChaCha20;
