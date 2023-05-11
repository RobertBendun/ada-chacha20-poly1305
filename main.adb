pragma Ada_2022;

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Command_Line;
with Common; use Common;
with Tests;

with AEAD;
with ChaCha20;

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

	AEAD.Encrypt(
		Additional_Auth_Data.all,
		ChaCha20.Key_8(Key.all),
		ChaCha20.Nonce_8(Nonce.all),
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
