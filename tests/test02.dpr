program test02;

{$IFDEF FPC}
  {$MODE delphi}
{$ENDIF}
{$APPTYPE CONSOLE}


uses
  SysUtils,
  Windows,
  Classes,
  SeAES256 in '..\SeCrypt\SeAES256.pas';

function TestAESVector(Key, PlainText, CipherText: AnsiString): Boolean;
var
  AESKey: TAESKey;
  ExpandedKey: TAESExpandedKey;
  State: TAESState;
begin
  AESCopyKey(AESKey,PAnsiChar(Key));
  AESExpandKey(ExpandedKey,AESKey);
  move(PAnsiChar(PlainText)^,State,Sizeof(State));
  AESEncrypt(State,ExpandedKey);
  Result:= StrLComp(PAnsiChar(@State),PAnsiChar(CipherText),Sizeof(State)) = 0;
end;

const
  Bloques = 256*1024;

var
  i: Integer;
  Key: TAESKey;
  ExpandedKey: TAESExpandedKey;
  State: TAESState;
  Ticks: Cardinal;
begin
  Writeln('Comprobando AES256 ...');
  Writeln('Vector 1: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$6b#$c1#$be#$e2#$2e#$40#$9f#$96#$e9#$3d#$7e#$11#$73#$93#$17#$2a,
    #$f3#$ee#$d1#$bd#$b5#$d2#$a0#$3c#$06#$4b#$5a#$7e#$3d#$b1#$81#$f8)),TRUE));
  Writeln('Vector 2: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$ae#$2d#$8a#$57#$1e#$03#$ac#$9c#$9e#$b7#$6f#$ac#$45#$af#$8e#$51,
    #$59#$1c#$cb#$10#$d4#$10#$ed#$26#$dc#$5b#$a7#$4a#$31#$36#$28#$70)),TRUE));
  Writeln('Vector 3: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$30#$c8#$1c#$46#$a3#$5c#$e4#$11#$e5#$fb#$c1#$19#$1a#$0a#$52#$ef,
    #$b6#$ed#$21#$b9#$9c#$a6#$f4#$f9#$f1#$53#$e7#$b1#$be#$af#$ed#$1d)),TRUE));
  Writeln('Vector 4: ' + BoolToStr(( TestAESVector(
    #$60#$3d#$eb#$10#$15#$ca#$71#$be#$2b#$73#$ae#$f0#$85#$7d#$77#$81 +
    #$1f#$35#$2c#$07#$3b#$61#$08#$d7#$2d#$98#$10#$a3#$09#$14#$df#$f4,
    #$f6#$9f#$24#$45#$df#$4f#$9b#$17#$ad#$2b#$41#$7b#$e6#$6c#$37#$10,
    #$23#$30#$4b#$7a#$39#$f9#$f3#$ff#$06#$7d#$8d#$8f#$9e#$24#$ec#$c7)),TRUE));
  Writeln;
  FillChar(Key,Sizeof(Key),'A');
  AESExpandKey(ExpandedKey,Key);
  FillChar(State,Sizeof(State),'A');
  Write('Cifrando y descifrando ' + IntToStr((Bloques*16) div (1024*1024))
    + ' Megabytes ... ');
  Ticks:= GetTickCount;
  for i:= 1 to Bloques do
  begin
    AESEncrypt(State,ExpandedKey);
    AESDecrypt(State,ExpandedKey);
  end;
  Writeln(FormatFloat('0.000',(GetTickCount - Ticks)/1000) + ' sg');
  Writeln('State = ' + Copy(PAnsiChar(@State),1,Sizeof(State)));
  Writeln;
  Writeln('Pulsa enter para salir ...');
  Readln;
end.
