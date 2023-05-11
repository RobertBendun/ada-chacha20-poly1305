with Interfaces; use Interfaces;
with Common; use Common;
with Ada.Unchecked_Conversion;

package ChaCha20 is
	type State_Index is range 0 .. 15;
	type State       is array (State_Index) of Unsigned_32;
	type Key_8       is new Unsigned_8x32;
	type Nonce_8     is array (0..11) of Unsigned_8;

	-- 2.1.  The ChaCha Quarter Round
	procedure QR(A, B, C, D : in out Unsigned_32);

	-- 2.2.  A Quarter Round on the ChaCha State
	procedure Quarter_Round(S: in out State; A, B, C, D: State_Index);

	-- 2.3.  The ChaCha20 Block Function
	function Block(K: Key_8; Counter: Unsigned_32; N: Nonce_8) return Unsigned_8x64;

	-- 2.4.  The ChaCha20 Encryption Algorithm
	function Encrypt(Key: Key_8; Initial_Counter: Unsigned_32; Nonce: Nonce_8; Plain_Text: Byte_Array) return Byte_Array_Access;

private
	type Key_32   is array (0..7)  of Unsigned_32;
	type Nonce_32 is array (0..2)  of Unsigned_32;


	function "+"(L, R: State) return State;
	function Bytes is new Ada.Unchecked_Conversion(Source => State,   Target => Unsigned_8x64);
	function Ints  is new Ada.Unchecked_Conversion(Source => Key_8,   Target => Key_32);
	function Ints  is new Ada.Unchecked_Conversion(Source => Nonce_8, Target => Nonce_32);

	-- 2.3.  The ChaCha20 Block Function
	function Block(K: Key_32; Counter: Unsigned_32; N: Nonce_32) return Unsigned_8x64;

end ChaCha20;
