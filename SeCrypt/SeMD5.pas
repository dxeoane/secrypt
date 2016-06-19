unit SeMD5;

{$IFDEF FPC}
  {$MODE delphi}
{$ENDIF}
 
interface
 
uses Sysutils, Classes;

type
  TMD5HASH = array['A'..'D'] of Cardinal;
  PMD5HASH = ^TMD5HASH;

  // Calcula el hash MD5 de una cadena de texto
  function CalcMD5(Msg: AnsiString): TMD5HASH; overload;
  // Calcula el hash MD5 de un stream
  function CalcMD5(Stream: TStream): TMD5HASH; overload;
  // Convierte el hash en una cadena de texto
  function MD5ToStr(Hash: TMD5HASH): String;
 
implementation
 
type
  // Un bloque de datos de 64 bytes de longitud
  TChunk = array[0..15] of Cardinal;
  PChunk = ^TChunk;
 
const
  s: array[0..63] of Byte = (
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21);

  k: array[0..63] of Cardinal = (
   $d76aa478, $e8c7b756, $242070db, $c1bdceee,
   $f57c0faf, $4787c62a, $a8304613, $fd469501,
   $698098d8, $8b44f7af, $ffff5bb1, $895cd7be,
   $6b901122, $fd987193, $a679438e, $49b40821,
   $f61e2562, $c040b340, $265e5a51, $e9b6c7aa,
   $d62f105d, $02441453, $d8a1e681, $e7d3fbc8,
   $21e1cde6, $c33707d6, $f4d50d87, $455a14ed,
   $a9e3e905, $fcefa3f8, $676f02d9, $8d2a4c8a,
   $fffa3942, $8771f681, $6d9d6122, $fde5380c,
   $a4beea44, $4bdecfa9, $f6bb4b60, $bebfbc70,
   $289b7ec6, $eaa127fa, $d4ef3085, $04881d05,
   $d9d4d039, $e6db99e5, $1fa27cf8, $c4ac5665,
   $f4292244, $432aff97, $ab9423a7, $fc93a039,
   $655b59c3, $8f0ccc92, $ffeff47d, $85845dd1,
   $6fa87e4f, $fe2ce6e0, $a3014314, $4e0811a1,
   $f7537e82, $bd3af235, $2ad7d2bb, $eb86d391);

{$Include asm.inc}

// Calcula el hash de un bloque
function CalcChunk(Hash: TMD5HASH; var Chunk: TChunk): TMD5HASH;
var
  i: Integer;
  f,g,t: Cardinal;
begin
  for i:= 0 to 63 do
  begin
    if i < 16 then
    begin
      f:= (Hash['B'] and Hash['C']) or ((not Hash['B']) and Hash['D']);
      g:= i;
    end else if i < 32 then
    begin
      f:= (Hash['D'] and Hash['B']) or ((not Hash['D']) and Hash['C']);
      g:= (5*i + 1) mod 16;
    end else if i < 48 then
    begin
      f:= Hash['B'] xor Hash['C'] xor Hash['D'];
      g:= (3*+i + 5) mod 16;
    end else
    begin
      f:= Hash['C']  xor (Hash['B'] or (not Hash['D']));
      g:= (7*i) mod 16;
    end;
    t:= Hash['D'];
    Hash['D']:= Hash['C'];
    Hash['C']:= Hash['B'];
    Hash['B']:= Hash['B'] +  Rol(Hash['A'] + f + k[i] + Chunk[g],s[i]);
    Hash['A']:= t;
  end;

  // Devolvemos el hash de este bloque
  Result:= Hash;
end;
 
// Calcula el hash MD5 de una cadena de texto
function CalcMD5(Msg: AnsiString): TMD5HASH; overload;
var
  Stream: TMemoryStream;
begin
  Stream:= TMemoryStream.Create;
  try
    // Guardamos el texto en un stream
    Stream.WriteBuffer(PAnsiChar(Msg)^,Length(Msg));
    Stream.Position:= 0;
    // Calculamos el hash del stream
    Result:= CalcMD5(Stream);
  finally
    Stream.Free;
  end;
end;
 
// Calcula el hash MD5 de un stream
function CalcMD5(Stream: TStream): TMD5HASH; overload;
var
  i,j: Integer;
  C: AnsiChar;
  Size: int64;
  P: PAnsiChar;
  Chunk: PChunk;
  H: TMD5HASH;
begin
  // Colocamos los valores iniciales
  Result['A']:= $67452301;   //A
  Result['B']:= $efcdab89;   //B
  Result['C']:= $98badcfe;   //C
  Result['D']:= $10325476;   //D

  Size:= 0;

  // Reservamos espacio para 2 bloques
  GetMem(P,64*2);
  try
    // Apuntamos al principio del buffer
    Chunk:= PChunk(P);
    // Rellenamos el buffer con ceros
    FillChar(P^,64*2,#0);
    // Leemos un bloque
    i:= Stream.Read(P^,64);
    // Mientras leemos bloques completos
    while i = 64 do
    begin
      // Calculamos el hash de este bloque
      H:= CalcChunk(Result,Chunk^);
      // Y lo sumamos al hash anterior
      for C:= 'A' to 'D' do
        Result[C]:= Result[C] + H[C];
      // Calculamos el tamaño del stream
      inc(Size,i);
      // Rellenamos el buffer con ceros
      FillChar(P^,64*2,#0);
      // Leemos el siguiente bloque
      i:= Stream.Read(P^,64);
    end;
    // Calculamos el tamaño del stream
    inc(Size,i);
    // Le añadimos un bit 1 al final
    P[i]:= #$80;
    // Calculamos el tamaño de los datos que faltan
    j:= i + 9;
    // Ajustamos el tamaño a un multiplo de 64
    if j mod 64 > 0 then
     inc(j,64 - (j mod 64));
    // Guardamos el tamaño original
    Size:= Size * 8;
    move(Size,P[j-8],8);
    // Procesamos cada uno de los bloques de 64 bytes que faltan
    for i:= 1 to j div 64 do
    begin
      // Calculamos el hash de este bloque
      H:= CalcChunk(Result,Chunk^);
      // Y lo sumamos al hash anterior
      for C:= 'A' to 'D' do
        Result[C]:= Result[C] + H[C];
      // Apuntamos al siguiente bloque
      inc(Chunk);
    end;
  finally
    FreeMem(P);
  end;
end;
 
function MD5ToStr(Hash: TMD5HASH): String;
var
  C: AnsiChar;
begin
  Result:= EmptyStr;
  for C:= 'A' to 'D' do
    Result:= Result + Lowercase(IntToHex(bswap(Hash[C]),8));
end;
 
end.