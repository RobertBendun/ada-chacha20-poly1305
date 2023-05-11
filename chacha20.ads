with Interfaces; use Interfaces;
with Common; use Common;
with Ada.Unchecked_Conversion;

package ChaCha20 is

	type ChaCha20_State_Index is range 0 .. 15;
	type ChaCha20_State is array (ChaCha20_State_Index) of Unsigned_32;
	type ChaCha20_Key_8    is new Unsigned_8x32;
	type ChaCha20_Nonce_8  is array (0..11) of Unsigned_8;

	-- 2.1.  The ChaCha Quarter Round
	procedure QR(A, B, C, D : in out Unsigned_32);

	-- 2.2.  A Quarter Round on the ChaCha State
	procedure Quarter_Round(S: in out ChaCha20_State; A, B, C, D: ChaCha20_State_Index);

	-- 2.3.  The ChaCha20 Block Function
	function ChaCha20_Block(K: ChaCha20_Key_8; Counter: Unsigned_32; N: ChaCha20_Nonce_8) return Unsigned_8x64;

	-- 2.4.  The ChaCha20 Encryption Algorithm
	function ChaCha20_Encrypt(Key: ChaCha20_Key_8; Initial_Counter: Unsigned_32; Nonce: ChaCha20_Nonce_8; Plain_Text: Byte_Array) return Byte_Array_Access;

private
	type ChaCha20_Key_32   is array (0..7)  of Unsigned_32;
	type ChaCha20_Nonce_32 is array (0..2)  of Unsigned_32;


	function "+"(L, R: ChaCha20_State) return ChaCha20_State;
	function Bytes is new Ada.Unchecked_Conversion(Source => ChaCha20_State,   Target => Unsigned_8x64);
	function Ints  is new Ada.Unchecked_Conversion(Source => ChaCha20_Key_8,   Target => ChaCha20_Key_32);
	function Ints  is new Ada.Unchecked_Conversion(Source => ChaCha20_Nonce_8, Target => ChaCha20_Nonce_32);

	-- 2.3.  The ChaCha20 Block Function
	function ChaCha20_Block(K: ChaCha20_Key_32; Counter: Unsigned_32; N: ChaCha20_Nonce_32) return Unsigned_8x64;

end ChaCha20;
