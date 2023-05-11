with Ada.Unchecked_Conversion;
with Interfaces; use Interfaces;
with Ada.Directories; use Ada.Directories;
with Ada.Unchecked_Deallocation;

package Common is
	type Unsigned_8x4  is array (0..3)  of Unsigned_8;
	type Unsigned_8x8  is array (0..7)  of Unsigned_8;
	type Unsigned_8x16 is array (0..15) of Unsigned_8;
	type Unsigned_8x32 is array (0..31) of Unsigned_8;
	type Unsigned_8x64 is array (0..63) of Unsigned_8;

	function Bytes is new Ada.Unchecked_Conversion(Source => Unsigned_32, Target => Unsigned_8x4);
	function Bytes is new Ada.Unchecked_Conversion(Source => Unsigned_64, Target => Unsigned_8x8);

	function Ceil_Div(X, Y: Integer) return Integer;
	function Hex(Byte: Unsigned_8) return String;

	type Byte_Array is array (File_Size range <>) of Unsigned_8;
	type Byte_Array_Access is access Byte_Array;
	procedure Delete is new Ada.Unchecked_Deallocation(Byte_Array, Byte_Array_Access);

	function  Bytes(S: String) return Byte_Array_Access;
	function  Read_Binary_File(Filename: String) return Byte_Array_Access;
	procedure Write_Binary_File(Filename: String; Data: Byte_Array);
end Common;
