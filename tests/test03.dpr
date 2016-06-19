program test03;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  SeAES256 in '..\SeCrypt\SeAES256.pas',
  SeBase64 in '..\SeCrypt\SeBase64.pas',
  SeEasyAES in '..\SeCrypt\SeEasyAES.pas',
  SeSHA256 in '..\SeCrypt\SeSHA256.pas',
  SeStreams in '..\SeCrypt\SeStreams.pas';

var
  i: Integer;
  Src, Cifrado: WideString;
begin
  try
    Randomize;
    for i:= 1 to 1000 do
      Src:= Src + Chr(Random(1 + Ord('z') - Ord('A')) + Ord('A'));
    Writeln('=== Texto sin cifrar ===');
    Writeln(Src);
    Writeln;
    Cifrado:= EasyAESEnc(Src,'Clave');
    Writeln('=== Texto cifrado ===');
    Writeln(Cifrado);
    Writeln;
    Cifrado:= EasyAESDec(Cifrado,'Clave');
    Writeln('=== Texto descifrado ===');
    Writeln(Cifrado);
    Writeln;
    Writeln('Resultado = ' + BoolToStr(Src = Cifrado,TRUE)); 
  except
    On E: Exception do
      Writeln(E.Message);
  end;
  Readln;
end.
