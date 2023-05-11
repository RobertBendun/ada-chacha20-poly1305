with Interfaces; use Interfaces;
with Ada.Directories; use Ada.Directories;

package body Poly1305 is
	-- 2.5.  The Poly1305 Algorithm
	function Mac(Message: Byte_Array; K: Key) return Unsigned_8x16 is
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
		R := To_Big_Integer(Clamp(Unsigned_8x16(K( 0 .. 15))));
		S := To_Big_Integer(Unsigned_8x16(K(16 .. 31)));

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
	end Mac;

	function To_Big_Integer(B: Unsigned_8x16) return Big_Integer is
		Result : Big_Integer := 0;
		Index : File_Size;
	begin
		for J in reverse Unsigned_8x16'Range loop
				Result := Result * 256 + To_Big_Integer(Integer(B(J)));
		end loop;
		return Result;
	end To_Big_Integer;
end Poly1305;
