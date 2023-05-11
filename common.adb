with Ada.Streams.Stream_IO;

package body Common is
	function Hex(Byte: Unsigned_8) return String is
		Hex_Chars : constant array (Unsigned_8 range 0 .. 15) of Character := (
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
		);
	begin
		return Hex_Chars(Byte / 16) & Hex_Chars(Byte mod 16);
	end Hex;

	function Ceil_Div(X, Y: Integer) return Integer is ((X + Y - 1) / Y);

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

	procedure Write_Binary_File(Filename: String; Data: Byte_Array)  is
		package SIO renames Ada.Streams.Stream_IO;

		S : SIO.Stream_Access;
		File : SIO.File_Type;
	begin
		SIO.Create(File, SIO.Out_File, Filename);
		S := SIO.Stream(File);
		Byte_Array'Write(S, Data);
		SIO.Close(File);
	end Write_Binary_File;
end Common;
