unit SeBase64;

{$IFDEF FPC}
  {$MODE delphi}
{$ENDIF}

interface

uses SysUtils;

// Convierte datos binarios a texto (base64)
function BinToStr(Data: PByteArray; Len: Integer): AnsiString;
// Convierte texto a datos binarios
function StrToBin(Str: AnsiString; var Len: Integer; Dirty: Boolean): PByteArray; overload;
function StrToBin(Str: AnsiString; var Len: Integer): PByteArray; overload;
// Limpia una cadena elimnando los caracteres que sobran
function Base64CleanStr(Str: PAnsiChar; Count: Integer): Integer;

implementation

var
  Table: array[0..255] of AnsiChar;
  invTable: array[#0..#255] of Byte;

// Rellenamos la tablas auxiliares
procedure InitTables;
var
  i: Integer;
  c: AnsiChar;
begin
  FillChar(Table,Sizeof(Table),#0);
  FillChar(invTable,Sizeof(Table),#$FF);
  i:= 0;
  for c:= 'A' to 'Z' do
  begin
    Table[i]:= c;
    invTable[c]:= i;
    inc(i);
  end;
  for c:= 'a' to 'z' do
  begin
    Table[i]:= c;
    invTable[c]:= i;
    inc(i);
  end;
  for c:= '0' to '9' do
  begin
    Table[i]:= c;
    invTable[c]:= i;
    inc(i);
  end;
  Table[62]:= '+';
  Table[63]:= '/';
  invTable['+']:= 62;
  invTable['/']:= 63;
end;

function BinToStr(Data: PByteArray; Len: Integer): AnsiString;
begin
  Result:= EmptyStr;
  while Len > 2 do
  begin
    Result:= Result + Table[Data[0] shr 2];
    Result:= Result + Table[((Data[0] and $03) shl 4) + (Data[1] shr 4)];
    Result:= Result + Table[((Data[1] and $0F) shl 2) + (Data[2] shr 6)];
    Result:= Result + Table[Data[2] and $3F];
    inc(PByte(Data),3);
    dec(Len,3);
  end;
  case Len of
    2: begin
         Result:= Result + Table[Data[0] shr 2];
         Result:= Result + Table[((Data[0] and $03) shl 4) + (Data[1] shr 4)];
         Result:= Result + Table[((Data[1] and $0F) shl 2)];
         Result:= Result + '=';
       end;
    1: begin
         Result:= Result + Table[Data[0] shr 2];
         Result:= Result + Table[((Data[0] and $03) shl 4)];
         Result:= Result + '==';
       end;
  end;
end;

// Limpia una cadena elimnando los caracteres que sobran
function Base64CleanStr(Str: PAnsiChar; Count: Integer): Integer;
var
  P: PAnsiChar;
begin
  Result:= 0;
  P:= Str;
  while Count > 0 do
  begin
    if invTable[Str^] <> $FF then
    begin
      P^:= Str^;
      inc(P);
      inc(Result);
    end;
    inc(Str);
    dec(Count);
  end;
end;

function StrToBin(Str: AnsiString; var Len: Integer; Dirty: Boolean): PByteArray;
var
  i: Integer;
begin
  Result:= nil;
  // Si no esta limpia, limpiamos la cadena
  if Dirty then
    SetLength(Str,Base64CleanStr(PAnsiChar(Str),Length(Str)));
  // Reservamos memoria para el resultado
  Len:= (Length(Str) div 4) * 3;
  case Length(Str) mod 4 of
    0: ;
    3: inc(Len,2);
    2: inc(Len);
    else Exit;
  end;
  GetMem(Result, Len);
  for i:= 0 to (Len div 3) - 1 do
  begin
    Result[3*i]:=      (invTable[Str[(4*i)+1]] shl 2)
      + (invTable[Str[(4*i)+2]] shr 4);
    Result[(3*i)+1]:= ((invTable[Str[(4*i)+2]] and $0F) shl 4)
      + (invTable[Str[(4*i)+3]] shr 2);
    Result[(3*i)+2]:= ((invTable[Str[(4*i)+3]] and $03) shl 6)
      + invTable[Str[(4*i)+4]];
  end;
  i:= (Len div 3);
  case Length(Str) mod 4 of
    3: begin
         Result[3*i]:=      (invTable[Str[(4*i)+1]] shl 2)
           + (invTable[Str[(4*i)+2]] shr 4);
         Result[(3*i)+1]:= ((invTable[Str[(4*i)+2]] and $0F) shl 4)
           + (invTable[Str[(4*i)+3]] shr 2);
       end;
    2: begin
         Result[3*i]:=      (invTable[Str[(4*i)+1]] shl 2)
           + (invTable[Str[(4*i)+2]] shr 4);
       end;
  end;
end;

function StrToBin(Str: AnsiString; var Len: Integer): PByteArray;
begin
  Result:= StrToBin(Str,Len,TRUE);
end;

initialization
  InitTables;
end.
