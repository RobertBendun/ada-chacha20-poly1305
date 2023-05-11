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
with ChaCha20; use ChaCha20;
with Poly1305; use Poly1305;
with AEAD; use AEAD;
with Tests;

-- Implementation of ChaCha20-Poly1305 as defined in RFC 7539
-- https://www.rfc-editor.org/rfc/rfc7539
procedure Main is
	procedure Usage is
	begin
		Put_Line("usage:");
		Put_Line("  chacha20_poly1305 <AAD file> <key file> <nonce file> <in file> <out file>");
	end Usage;

	Additional_Auth_Data, Key, Nonce, Input, Output : Byte_Array_Access;
	Tag : Unsigned_8x16;
begin
	Tests.Run;

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
end Main;
