program test01;

{$IFDEF FPC}
  {$MODE delphi}
{$ENDIF}
{$APPTYPE CONSOLE}

uses
  SysUtils,
  Classes,
  windows,
  SeAES256 in '..\SeCrypt\SeAES256.pas',
  SeBase64 in '..\SeCrypt\SeBase64.pas',
  SeMD5 in '..\SeCrypt\SeMD5.pas',
  SeStreams in '..\SeCrypt\SeStreams.pas',
  SeSHA256 in '..\SeCrypt\SeSHA256.pas';

function TestAESVector(Key, PlainText, CipherText: AnsiString; Size: Integer): Boolean;
var
  AESKey: TAESKey;
  ExpandedKey: TAESExpandedKey;
  State: TAESState;
begin
  AESCopyKey(AESKey,PAnsiChar(Key));
  AESExpandKey(ExpandedKey,AESKey,Size);
  move(PAnsiChar(PlainText)^,State,Sizeof(State));
  AESEncrypt(State,ExpandedKey);
  Result:= StrLComp(PAnsiChar(@State),PAnsiChar(CipherText),Sizeof(State)) = 0;
end;

function TestBase64Vector(InData, OutData: AnsiString): Boolean;
begin
  Result:= BinToStr(PByteArray(PAnsiChar(InData)),Length(InData))=OutData
end;

var
  i,j: Integer;
  b: Byte;
  Datos: TMemoryStream;
  Cifr: TMemoryStream;
  Desc: TMemoryStream;
  Key: TAESKey;
  AEnc: TAESEnc;
  ADec: TAESDec;
  BEnc: TBase64Enc;
  BDec: TBase64Dec;
begin
  Randomize;
  Writeln;
  Writeln('=== SeCrypt Test ===');
  Writeln;
  Writeln('Comprobando AES256 ...');
  Writeln('Vector 1: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$6b#$c1#$be#$e2#$2e#$40#$9f#$96#$e9#$3d#$7e#$11#$73#$93#$17#$2a,
    #$f3#$ee#$d1#$bd#$b5#$d2#$a0#$3c#$06#$4b#$5a#$7e#$3d#$b1#$81#$f8,256)),TRUE));
  Writeln('Vector 2: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$ae#$2d#$8a#$57#$1e#$03#$ac#$9c#$9e#$b7#$6f#$ac#$45#$af#$8e#$51,
    #$59#$1c#$cb#$10#$d4#$10#$ed#$26#$dc#$5b#$a7#$4a#$31#$36#$28#$70,256)),TRUE));
  Writeln('Vector 3: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$30#$c8#$1c#$46#$a3#$5c#$e4#$11#$e5#$fb#$c1#$19#$1a#$0a#$52#$ef,
    #$b6#$ed#$21#$b9#$9c#$a6#$f4#$f9#$f1#$53#$e7#$b1#$be#$af#$ed#$1d,256)),TRUE));
  Writeln('Vector 4: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$f6#$9f#$24#$45#$df#$4f#$9b#$17#$ad#$2b#$41#$7b#$e6#$6c#$37#$10,
    #$23#$30#$4b#$7a#$39#$f9#$f3#$ff#$06#$7d#$8d#$8f#$9e#$24#$ec#$c7,256)),TRUE));
  Writeln;
  Writeln('Comprobando AES192 ...');
  Writeln('Vector 1: ' + BoolToStr(( TestAESVector(
    #$8e#$73#$b0#$f7#$da#$0e#$64#$52#$c8#$10#$f3#$2b#$80#$90#$79#$e5#$62#$f8#$ea#$d2#$52#$2c#$6b#$7b,
    #$6b#$c1#$be#$e2#$2e#$40#$9f#$96#$e9#$3d#$7e#$11#$73#$93#$17#$2a,
    #$bd#$33#$4f#$1d#$6e#$45#$f2#$5f#$f7#$12#$a2#$14#$57#$1f#$a5#$cc,192)),TRUE));
  Writeln('Vector 2: ' + BoolToStr(( TestAESVector(
    #$8e#$73#$b0#$f7#$da#$0e#$64#$52#$c8#$10#$f3#$2b#$80#$90#$79#$e5#$62#$f8#$ea#$d2#$52#$2c#$6b#$7b,
    #$ae#$2d#$8a#$57#$1e#$03#$ac#$9c#$9e#$b7#$6f#$ac#$45#$af#$8e#$51,
    #$97#$41#$04#$84#$6d#$0a#$d3#$ad#$77#$34#$ec#$b3#$ec#$ee#$4e#$ef,192)),TRUE));
  Writeln('Vector 3: ' + BoolToStr(( TestAESVector(
    #$8e#$73#$b0#$f7#$da#$0e#$64#$52#$c8#$10#$f3#$2b#$80#$90#$79#$e5#$62#$f8#$ea#$d2#$52#$2c#$6b#$7b,
    #$30#$c8#$1c#$46#$a3#$5c#$e4#$11#$e5#$fb#$c1#$19#$1a#$0a#$52#$ef,
    #$ef#$7a#$fd#$22#$70#$e2#$e6#$0a#$dc#$e0#$ba#$2f#$ac#$e6#$44#$4e,192)),TRUE));
  Writeln('Vector 4: ' + BoolToStr(( TestAESVector(
    #$8e#$73#$b0#$f7#$da#$0e#$64#$52#$c8#$10#$f3#$2b#$80#$90#$79#$e5#$62#$f8#$ea#$d2#$52#$2c#$6b#$7b,
    #$f6#$9f#$24#$45#$df#$4f#$9b#$17#$ad#$2b#$41#$7b#$e6#$6c#$37#$10,
    #$9a#$4b#$41#$ba#$73#$8d#$6c#$72#$fb#$16#$69#$16#$03#$c1#$8e#$0e,192)),TRUE));
  Writeln;
  Writeln('Comprobando AES128 ...');
  Writeln('Vector 1: ' + BoolToStr(( TestAESVector(
    #$2b#$7e#$15#$16#$28#$ae#$d2#$a6#$ab#$f7#$15#$88#$09#$cf#$4f#$3c,
    #$6b#$c1#$be#$e2#$2e#$40#$9f#$96#$e9#$3d#$7e#$11#$73#$93#$17#$2a,
    #$3a#$d7#$7b#$b4#$0d#$7a#$36#$60#$a8#$9e#$ca#$f3#$24#$66#$ef#$97,128)),TRUE));
  Writeln('Vector 2: ' + BoolToStr(( TestAESVector(
    #$2b#$7e#$15#$16#$28#$ae#$d2#$a6#$ab#$f7#$15#$88#$09#$cf#$4f#$3c,
    #$ae#$2d#$8a#$57#$1e#$03#$ac#$9c#$9e#$b7#$6f#$ac#$45#$af#$8e#$51,
    #$f5#$d3#$d5#$85#$03#$b9#$69#$9d#$e7#$85#$89#$5a#$96#$fd#$ba#$af,128)),TRUE));
  Writeln('Vector 3: ' + BoolToStr(( TestAESVector(
    #$2b#$7e#$15#$16#$28#$ae#$d2#$a6#$ab#$f7#$15#$88#$09#$cf#$4f#$3c,
    #$30#$c8#$1c#$46#$a3#$5c#$e4#$11#$e5#$fb#$c1#$19#$1a#$0a#$52#$ef,
    #$43#$b1#$cd#$7f#$59#$8e#$ce#$23#$88#$1b#$00#$e3#$ed#$03#$06#$88,128)),TRUE));
  Writeln('Vector 4: ' + BoolToStr(( TestAESVector(
    #$2b#$7e#$15#$16#$28#$ae#$d2#$a6#$ab#$f7#$15#$88#$09#$cf#$4f#$3c,
    #$f6#$9f#$24#$45#$df#$4f#$9b#$17#$ad#$2b#$41#$7b#$e6#$6c#$37#$10,
    #$7b#$0c#$78#$5e#$27#$e8#$ad#$3f#$82#$23#$20#$71#$04#$72#$5d#$d4,128)),TRUE));
  Writeln;
  Writeln('Comprobando SHA256 ...');
  Writeln('Vector 1: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('')))
      = 'e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855')),TRUE));
  Writeln('Vector 2: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('abc')))
      = 'ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad')),TRUE));
  Writeln('Vector 3: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))
      = '248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1')),TRUE));
  Writeln('Vector 4: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256('The quick brown fox jumps over the lazy dog')))
      = 'd7a8fbb3 07d78094 69ca9abc b0082e4f 8d5651e4 6d3cdb76 2d02d0bf 37c9e592')),TRUE));
  Writeln('Vector 5: ' + BoolToStr((
    (LowerCase(SHA256ToStr(CalcSHA256(StringOfChar('a',1000000))))
      = 'cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0')),TRUE));
  Writeln;
  Writeln('Comprobando md5 ...');
  Writeln('Vector 1: ' + BoolToStr((
    (LowerCase(MD5ToStr(CalcMD5('')))
      = 'd41d8cd98f00b204e9800998ecf8427e')),TRUE));  
  Writeln('Vector 2: ' + BoolToStr((
    (LowerCase(MD5ToStr(CalcMD5('abc')))
      = '900150983cd24fb0d6963f7d28e17f72')),TRUE));
  Writeln('Vector 3: ' + BoolToStr((
    (LowerCase(MD5ToStr(CalcMD5('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))
      = '8215ef0796a20bcaaae116d3876c664a')),TRUE));
  Writeln('Vector 4: ' + BoolToStr((
    (LowerCase(MD5ToStr(CalcMD5(StringOfChar('a',1000000))))
      = '7707d6ae4e027c70eea2a935c2296f21')),TRUE));
  Writeln;
  Writeln('Comprobando BASE64 ...');
  Writeln('Vector 1: ' + BoolToStr(TestBase64Vector('',''),TRUE));
  Writeln('Vector 2: ' + BoolToStr(TestBase64Vector('f','Zg=='),TRUE));
  Writeln('Vector 3: ' + BoolToStr(TestBase64Vector('fo','Zm8='),TRUE));
  Writeln('Vector 4: ' + BoolToStr(TestBase64Vector('foo','Zm9v'),TRUE));
  Writeln('Vector 5: ' + BoolToStr(TestBase64Vector('foob','Zm9vYg=='),TRUE));
  Writeln('Vector 6: ' + BoolToStr(TestBase64Vector('fooba','Zm9vYmE='),TRUE));
  Writeln('Vector 7: ' + BoolToStr(TestBase64Vector('foobar','Zm9vYmFy'),TRUE));
  Writeln;
  Writeln('Probando datos aleatorios ...');
  Datos:= TMemoryStream.Create;
  Cifr:= TMemoryStream.Create;
  Desc:= TMemoryStream.Create;
  try
    // Repetimos el test para distintos tamaños de buffer
    for i:= 0 to 15 do
    begin
      Datos.Clear;
      Cifr.Clear;
      Desc.Clear;
      // Llenamos un buffer con numeros aleatorios
      for j:= 1 to (32*1024) + i do
      begin
        b:= Random(256);
        Datos.WriteBuffer(b,1);
      end;
      // Generamos una clave aleatoria
      for j:= 0 to 7 do
        Key[j]:= Random(MAXINT);
      Write(Format('%d bytes: ',[Datos.Size]));
      // Ciframos usando AES y Base64
      BEnc:= TBase64Enc.Create(Cifr);
      AEnc:= TAESEnc.Create(BEnc,Key);
      try
        AEnc.CopyFrom(Datos,0);
      finally
        AEnc.Free;
        BEnc.Free;
      end;
      // Desciframos usando Base64 y AES
      ADec:= TAESDec.Create(Desc,Key);
      BDec:= TBase64Dec.Create(ADec);
      try
        BDec.CopyFrom(Cifr,0);
      finally
        BDec.Free;
        ADec.Free;
      end;
      // Comparamos los datos originales con los descifrados
      Writeln(BoolToStr((Datos.Size <= Desc.Size) and
        CompareMem(Datos.Memory,Desc.Memory,Datos.Size), TRUE));
    end;
  finally
    Datos.Free;
    Cifr.Free;
    Desc.Free;
  end;
  Writeln;
  Writeln('Pulsa "Enter" para terminar ...');
  Readln;
end.
