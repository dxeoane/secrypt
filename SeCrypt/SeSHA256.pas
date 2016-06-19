unit SeSHA256;

{$IFDEF FPC}
  {$MODE delphi}
{$ENDIF}
 
interface
 
uses Sysutils, Classes;
 
type
  TSHA256HASH = array[0..7] of Cardinal;
  PSHA256HASH = ^TSHA256HASH;
 
  // Calcula el hash SHA256 de una cadena de texto
  function CalcSHA256(Msg: AnsiString): TSHA256HASH; overload;
  // Calcula el hash SHA256 de un stream
  function CalcSHA256(Stream: TStream): TSHA256HASH; overload;
  // Convierte el hash en una cadena de texto
  function SHA256ToStr(Hash: TSHA256HASH): String;
 
implementation
 
type
  // Un bloque de datos de 64 bytes de longitud
  TChunk = array[0..15] of Cardinal;
  PChunk = ^TChunk;
 
const
  k: array[0..63] of Cardinal = (
   $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5, $3956c25b, $59f111f1, $923f82a4, $ab1c5ed5,
   $d807aa98, $12835b01, $243185be, $550c7dc3, $72be5d74, $80deb1fe, $9bdc06a7, $c19bf174,
   $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc, $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da,
   $983e5152, $a831c66d, $b00327c8, $bf597fc7, $c6e00bf3, $d5a79147, $06ca6351, $14292967,
   $27b70a85, $2e1b2138, $4d2c6dfc, $53380d13, $650a7354, $766a0abb, $81c2c92e, $92722c85,
   $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3, $d192e819, $d6990624, $f40e3585, $106aa070,
   $19a4c116, $1e376c08, $2748774c, $34b0bcb5, $391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3,
   $748f82ee, $78a5636f, $84c87814, $8cc70208, $90befffa, $a4506ceb, $bef9a3f7, $c67178f2);

{$Include asm.inc}

// Calcula el hash de un bloque
function CalcChunk(Hash: TSHA256HASH; var Chunk: TChunk): TSHA256HASH;
var
  i: Integer;
  s0, s1, maj, t1, t2, ch: Cardinal;
  w: array[0..63] of Cardinal;
begin
  // Copiamos el bloque al comienzo de array "W"
  for i:=0 to 15 do
    w[i]:= bswap(Chunk[i]);
  // Calculamos el resto de valores del array "W"
  for i:= 16 to 63 do
  begin
    s0:=   ror(w[i-15],7) xor ror(w[i-15],18) xor (w[i-15] shr 3);
    s1:=   ror(w[i-2],17) xor ror(w[i-2],19) xor (w[i-2] shr 10);
    w[i]:= w[i-16] + s0 + w[i-7] + s1;
  end;
  // Ahora hacemos las 64 "pasadas" sobre "W" para calcular el hash
  for i:= 0 to 63 do
  begin
    s0:=  ror(Hash[0],2) xor ror(Hash[0],13) xor ror(Hash[0],22);
    maj:= (Hash[0] and Hash[1]) xor (Hash[0] and Hash[2]) xor (Hash[1] and Hash[2]);
    t2:=  s0 + maj;
    s1:=  ror(Hash[4],6) xor ror(Hash[4],11) xor ror(Hash[4],25);
    ch:=  (Hash[4] and Hash[5]) xor ((not Hash[4]) and Hash[6]);
    t1:=  Hash[7] + s1 + ch + k[i] + w[i];
    Hash[7]:= Hash[6];
    Hash[6]:= Hash[5];
    Hash[5]:= Hash[4];
    Hash[4]:= Hash[3] + t1;
    Hash[3]:= Hash[2];
    Hash[2]:= Hash[1];
    Hash[1]:= Hash[0];
    Hash[0]:= t1 + t2;
  end;
  // Devolvemos el hash de este bloque
  Result:= Hash;
end;
 
// Calcula el hash SHA256 de una cadena de texto
function CalcSHA256(Msg: AnsiString): TSHA256HASH; overload;
var
  Stream: TMemoryStream;
begin
  Stream:= TMemoryStream.Create;
  try
    // Guardamos el texto en un stream
    Stream.WriteBuffer(PAnsiChar(Msg)^,Length(Msg));
    Stream.Position:= 0;
    // Calculamos el hash del stream
    Result:= CalcSHA256(Stream);
  finally
    Stream.Free;
  end;
end;
 
// Calcula el hash SHA256 de un stream
function CalcSHA256(Stream: TStream): TSHA256HASH; overload;
var
  i,j,k: Integer;
  Size: int64;
  P: PAnsiChar;
  Chunk: PChunk;
  H: TSHA256HASH;
begin
  // Colocamos los valores iniciales
  Result[0]:= $6a09e667;
  Result[1]:= $bb67ae85;
  Result[2]:= $3c6ef372;
  Result[3]:= $a54ff53a;
  Result[4]:= $510e527f;
  Result[5]:= $9b05688c;
  Result[6]:= $1f83d9ab;
  Result[7]:= $5be0cd19;
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
      for k:= 0 to 7 do
        Result[k]:= Result[k] + H[k];
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
    // Guardmos el tamaño original en formato "big-endian"
    Size:= swap64(Size*8);
    move(Size,P[j-8],8);
    // Procesamos cada uno de los bloques de 64 bytes que faltan
    for i:= 1 to j div 64 do
    begin
      // Calculamos el hash de este bloque
      H:= CalcChunk(Result,Chunk^);
      // Y lo sumamos al hash anterior
      for k:= 0 to 7 do
        Result[k]:= Result[k] + H[k];
      // Apuntamos al siguiente bloque
      inc(Chunk);
    end;
  finally
    FreeMem(P);
  end;
end;
 
function SHA256ToStr(Hash: TSHA256HASH): String;
var
  i: Integer;
begin
  Result:= EmptyStr;
  for i:= 0 to 6 do
    Result:= Result + IntToHex(Hash[i],8) + #32;
  Result:= Result + IntToHex(Hash[7],8);
end;
 
end.