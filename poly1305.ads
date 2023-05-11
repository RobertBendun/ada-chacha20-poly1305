pragma Ada_2022;

with Common; use Common;
with Ada.Numerics.Big_Numbers.Big_Integers; use Ada.Numerics.Big_Numbers.Big_Integers;

package Poly1305 is
	type Key is new Unsigned_8x32;

	-- 2.5.  The Poly1305 Algorithm
	function Mac(Message: Byte_Array; K: Key) return Unsigned_8x16;

private
	function To_Big_Integer(B: Unsigned_8x16) return Big_Integer;
end Poly1305;
