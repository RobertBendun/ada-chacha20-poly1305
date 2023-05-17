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
		Put_Line("  chacha20_poly1305 <encrypt|decrypt> <AAD file> <key file> <nonce file> <in file> <out file>");
	end Usage;

	Additional_Auth_Data, Key, Nonce, Input, Output : Byte_Array_Access;
	Tag : Unsigned_8x16;
begin
	Tests.Run;

	if Ada.Command_Line.Argument_Count /= 7 then
		Usage;
		Ada.Command_Line.Set_Exit_Status(Ada.Command_Line.Failure);
		return;
	end if;

	Read_Binary_File(Ada.Command_Line.Argument(2), Additional_Auth_Data);
	Read_Binary_File(Ada.Command_Line.Argument(3), Key);
	Read_Binary_File(Ada.Command_Line.Argument(4), Nonce);
	Read_Binary_File(Ada.Command_Line.Argument(5), Input);

	if Ada.Command_Line.Argument(1) = "encrypt" then
			AEAD.Encrypt(
				Additional_Auth_Data.all,
				ChaCha20.Key_8(Key.all),
				ChaCha20.Nonce_8(Nonce.all),
				Input.all,
				Output,
				Tag
			);

			Write_Binary_File(Ada.Command_Line.Argument(6), Output.all);
			Write_Binary_File(Ada.Command_Line.Argument(7), Tag);
	elsif Ada.Command_Line.Argument(1) = "decrypt" then
		Read_Binary_File(Ada.Command_Line.Argument(7), Tag);
		if AEAD.Decrypt(
			Additional_Auth_Data.all,
			ChaCha20.Key_8(Key.all),
			ChaCha20.Nonce_8(Nonce.all),
			Input.all,
			Tag,
			Output
		) then
			Write_Binary_File(Ada.Command_Line.Argument(6), Output.all);
		else
			Put_Line("Tag verification failed");
		end if;
	else
		Put_Line("Unrecognized mode: " & Ada.Command_Line.Argument(1));
		Ada.Command_Line.Set_Exit_Status(Ada.Command_Line.Failure);
	end if;


	Delete(Additional_Auth_Data);
	Delete(Input);
	Delete(Key);
	Delete(Nonce);
	Delete(Output);
end Main;
