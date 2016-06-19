unit SeStreams;

{$IFDEF FPC}
  {$MODE delphi}
{$ENDIF}

interface

uses Sysutils, Classes, SeAES256, SeBase64;

type
  // AES256 (Rijndael)
  EAESError = class(Exception);

  TAESEnc = class(TStream)
  private
    FBuffer: array[1..Sizeof(TAESState)] of Byte;
    FBufferSize: Integer;
    FDest: TStream;
    FExpandedKey: TAESExpandedKey;
    FIV: TAESState;
  public
    constructor Create(Dest: TStream; Key: TAESKey); overload;
    constructor Create(Dest: TStream; Key: TAESKey; IV: TAESState); overload;
    constructor Create(Dest: TStream; Key: TAESExpandedKey); overload;
    constructor Create(Dest: TStream; Key: TAESExpandedKey; IV: TAESState); overload;
    destructor Destroy; override;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
  end;

  TAESDec = class(TStream)
  private
    FBuffer: array[1..Sizeof(TAESState)] of Byte;
    FBufferSize: Integer;
    FDest: TStream;
    FExpandedKey: TAESExpandedKey;
    FIV: TAESState;
  public
    constructor Create(Dest: TStream; Key: TAESKey); overload;
    constructor Create(Dest: TStream; Key: TAESKey; IV: TAESState); overload;
    constructor Create(Dest: TStream; Key: TAESExpandedKey); overload;
    constructor Create(Dest: TStream; Key: TAESExpandedKey; IV: TAESState); overload;
    destructor Destroy; override;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
  end;

  // Base64
  Ebase64 = class(Exception);

  TBase64Enc = class(TStream)
  private
    FBuffer: array[1..3] of Byte;
    FBufferSize: Integer;
    FDest: TStream;
  public
    constructor Create(Dest: TStream);
    destructor Destroy; override;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
  end;

  TBase64Dec = class(TStream)
  private
    FBuffer: array[1..4] of Byte;
    FBufferSize: Integer;
    FDest: TStream;
  public
    constructor Create(Dest: TStream);
    destructor Destroy; override;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
  end;

  procedure StrToStream(Str: String; Dirty: Boolean; Stream: TStream); overload;
  procedure StrToStream(Str: String; Stream: TStream); overload;

implementation

{ TAESEnc }

constructor TAESEnc.Create(Dest: TStream; Key: TAESKey);
begin
  AESExpandKey(FExpandedKey,Key);
  Create(Dest,FExpandedKey);
end;

constructor TAESEnc.Create(Dest: TStream; Key: TAESKey; IV: TAESState);
begin
  Create(Dest,Key);
  FIV:= IV;
end;

constructor TAESEnc.Create(Dest: TStream; Key: TAESExpandedKey);
begin
  inherited Create;
  FBufferSize:= 0;
  FDest:= Dest;
  FExpandedKey:= Key;
  FillChar(FIV,SizeOf(FIV),#0);
end;

constructor TAESEnc.Create(Dest: TStream; Key: TAESExpandedKey; IV: TAESState);
begin
  Create(Dest,Key);
  FIV:= IV;
end;

destructor TAESEnc.Destroy;
var
  i: Integer;
begin
  if FBufferSize > 0 then
  begin
    for i:= FBufferSize + 1 to Sizeof(FBuffer) do
      FBuffer[i]:= 0;
    AESXORState(PAESState(@FBuffer)^,FIV);
    AESEncrypt(PAESState(@FBuffer)^,FExpandedKey);
    FDest.WriteBuffer(FBuffer,SizeOf(TAESState));
  end;
  inherited;
end;

function TAESEnc.Read(var Buffer; Count: Integer): Longint;
begin
  raise EAESError.Create('Invalid stream operation');
end;

function TAESEnc.Seek(Offset: Integer; Origin: Word): Longint;
begin
  raise EAESError.Create('Invalid stream operation');
end;

function TAESEnc.Write(const Buffer; Count: Integer): Longint;
var
  i: Integer;
  P: PByte;
  State: PAESState;
begin
  Result:= Count;
  P:= PByte(@Buffer);
  // Si hay bytes pendientes ...
  while (FBufferSize in [1..SizeOf(TAESState)-1]) and (Count > 0) do
  begin
    // ... intentamos crear un bloque completo
    inc(FBufferSize);
    FBuffer[FBufferSize]:= P^;
    inc(P);
    dec(Count);
  end;
  // Si tenemos un bloque completo lo codificamos
  if FBufferSize = SizeOf(TAESState) then
  begin
    AESXORState(PAESState(@FBuffer)^,FIV);
    AESEncrypt(PAESState(@FBuffer)^,FExpandedKey);
    FIV:= PAESState(@FBuffer)^;
    FDest.WriteBuffer(FBuffer,SizeOf(TAESState));
    FBufferSize:= 0;
  end;
  i:= 0;
  State:= PAESState(P);
  // Ciframos bloque a bloque
  while Count >= SizeOf(TAESState) do
  begin
    AESXORState(State^,FIV);
    AESEncrypt(State^,FExpandedKey);
    FIV:= State^;
    inc(State);
    dec(Count,SizeOf(TAESState));
    inc(i);
  end;
  // Escribimos los bloques descifrados
  FDest.WriteBuffer(P^,i*Sizeof(TAESState));
  inc(P,i*Sizeof(TAESState));
  // Guardamos los bytes del final en el buffer
  while (Count > 0) do
  begin
    inc(FBufferSize);
    FBuffer[FBufferSize]:= P^;
    inc(P);
    dec(Count);
  end;
end;

{ TAESDec }

constructor TAESDec.Create(Dest: TStream; Key: TAESKey);
begin
  AESExpandKey(FExpandedKey,Key);
  Create(Dest,FExpandedKey);
end;

constructor TAESDec.Create(Dest: TStream; Key: TAESKey; IV: TAESState);
begin
  Create(Dest,Key);
  FIV:= IV;
end;

constructor TAESDec.Create(Dest: TStream; Key: TAESExpandedKey);
begin
  inherited Create;
  FBufferSize:= 0;
  FDest:= Dest;
  FExpandedKey:= Key;
  FillChar(FIV,SizeOf(FIV),#0);
end;

constructor TAESDec.Create(Dest: TStream; Key: TAESExpandedKey; IV: TAESState);
begin
  Create(Dest,Key);
  FIV:= IV;
end;

destructor TAESDec.Destroy;
begin
  if FBufferSize > 0 then
    raise EAESError.Create('Invalid block size');
  inherited;
end;

function TAESDec.Read(var Buffer; Count: Integer): Longint;
begin
  raise EAESError.Create('Invalid stream operation');
end;

function TAESDec.Seek(Offset: Integer; Origin: Word): Longint;
begin
  raise EAESError.Create('Invalid stream operation');
end;

function TAESDec.Write(const Buffer; Count: Integer): Longint;
var
  i: Integer;
  P: PByte;
  State: PAESState;
  Temp: TAESState;
begin
  Result:= Count;
  P:= PByte(@Buffer);
  // Si hay bytes pendientes ...
  while (FBufferSize in [1..SizeOf(TAESState)-1]) and (Count > 0) do
  begin
    // ... intentamos crear un bloque completo
    inc(FBufferSize);
    FBuffer[FBufferSize]:= P^;
    inc(P);
    dec(Count);
  end;
  // Si tenemos un bloque completo lo descodificamos
  if FBufferSize = SizeOf(TAESState) then
  begin
    Temp:= PAESState(@FBuffer)^;
    AESDecrypt(PAESState(@FBuffer)^,FExpandedKey);
    AESXORState(PAESState(@FBuffer)^,FIV);
    FIV:= Temp;
    FDest.WriteBuffer(FBuffer,SizeOf(TAESState));
    FBufferSize:= 0;
  end;
  i:= 0;
  State:= PAESState(P);
  // Ciframos bloque a bloque
  while Count >= SizeOf(TAESState) do
  begin    
    Temp:= State^;
    AESDecrypt(State^,FExpandedKey);
    AESXORState(State^,FIV);
    FIV:= Temp;
    inc(State);
    dec(Count,SizeOf(TAESState));
    inc(i);
  end;
  // Escribimos los bloques cifrados
  FDest.WriteBuffer(P^,i*Sizeof(TAESState));
  inc(P,i*Sizeof(TAESState));
  // Guardamos los bytes del final en el buffer
  while (Count > 0) do
  begin
    inc(FBufferSize);
    FBuffer[FBufferSize]:= P^;
    inc(P);
    dec(Count);
  end;
end;

{ TBase64Enc }

constructor TBase64Enc.Create(Dest: TStream);
begin
  inherited Create;
  FBufferSize:= 0;
  FDest:= Dest;
end;

destructor TBase64Enc.Destroy;
var
  Str: AnsiString;
begin
  // Aqui vacío el buffer
  if FBufferSize > 0 then
  begin
    // Codificamos el buffer
    Str:= BinToStr(PByteArray(@FBuffer),FBufferSize);
    // Escribimos el resultado
    FDest.WriteBuffer(PAnsiChar(Str)^,Length(Str));
  end;
  inherited;
end;

function TBase64Enc.Read(var Buffer; Count: Integer): Longint;
begin
  raise Ebase64.Create('Invalid stream operation');
end;

function TBase64Enc.Seek(Offset: Integer; Origin: Word): Longint;
begin
  raise Ebase64.Create('Invalid stream operation');
end;

function TBase64Enc.Write(const Buffer; Count: Integer): Longint;
var
  i: Integer;
  P: PByte;
  Str: AnsiString;
begin
  Result:= Count;
  P:= PByte(@Buffer);
  // Si hay bytes pendientes ...
  while (FBufferSize in [1..2]) and (Count > 0) do
  begin
    // ... intentamos crear un grupo de 3 bytes
    inc(FBufferSize);
    FBuffer[FBufferSize]:= P^;
    inc(P);
    dec(Count);
  end;
  // Si tenemos un grupo completo lo codificamos
  if FBufferSize = 3 then
  begin
    Str:= BinToStr(@FBuffer,3);
    FDest.WriteBuffer(PAnsiChar(Str)^,Length(Str));
    FBufferSize:= 0;
  end;
  if Count > 0 then
  begin
    // Ajustamos a un multiplo de 3
    i:= (Count div 3) * 3;
    // Codificamos el buffer
    Str:= BinToStr(PByteArray(P),i);
    // Escribimos el resultado
    FDest.WriteBuffer(PAnsiChar(Str)^,Length(Str));
    // Nos colocamos en los ultimos bytes
    dec(Count,i);
    inc(P,i);
    // Guardamos los bytes del final en el buffer
    while (Count > 0) do
    begin
      inc(FBufferSize);
      FBuffer[FBufferSize]:= P^;
      inc(P);
      dec(Count);
    end;
  end;
end;

{ TBase64Dec }

constructor TBase64Dec.Create(Dest: TStream);
begin
  inherited Create;
  FBufferSize:= 0;
  FDest:= Dest;
end;

destructor TBase64Dec.Destroy;
begin
  // Aqui vacío el buffer
  if FBufferSize > 0 then
    StrToStream(Copy(PAnsiChar(@FBuffer),1,FBufferSize),FALSE,FDest);
  inherited;
end;

function TBase64Dec.Read(var Buffer; Count: Integer): Longint;
begin
  raise Ebase64.Create('Invalid stream operation');
end;

function TBase64Dec.Seek(Offset: Integer; Origin: Word): Longint;
begin
  raise Ebase64.Create('Invalid stream operation');
end;

function TBase64Dec.Write(const Buffer; Count: Integer): Longint;
var
  i: Integer;
  P: PByte;
begin
  Result:= Count;
  P:= PByte(@Buffer);
  // Limpiamos el buffer
  Count:= Base64CleanStr(@Buffer,Count);
  // Si hay bytes pendientes ...
  while (FBufferSize in [1..3]) and (Count > 0) do
  begin
    // ... intentamos crear un grupo de 4 bytes
    inc(FBufferSize);
    FBuffer[FBufferSize]:= P^;
    inc(P);
    dec(Count);
  end;
  // Si tenemos un grupo completo lo codificamos
  if FBufferSize = 4 then
  begin
    StrToStream(Copy(PAnsiChar(@FBuffer),1,4),FALSE,FDest);
    FBufferSize:= 0;
  end;
  if Count > 0 then
  begin
    // Ajustamos a un multiplo de 4
    i:= (Count div 4) * 4;
    // Codificamos el buffer
    StrToStream(Copy(PAnsiChar(P),1,i),FALSE,FDest);
    // Nos colocamos en los ultimos bytes
    dec(Count,i);
    inc(P,i);
    // Guardamos los bytes del final en el buffer
    while (Count > 0) do
    begin
      inc(FBufferSize);
      FBuffer[FBufferSize]:= P^;
      inc(P);
      dec(Count);
    end;
  end;
end;

procedure StrToStream(Str: String; Dirty: Boolean; Stream: TStream);
var
  Len: Integer;
  Buffer: PByteArray;
begin
  Buffer:= StrToBin(Str,Len,Dirty);
  if Buffer <> nil then
  try
    Stream.WriteBuffer(Buffer^,Len);
  finally
    // No hay que olvidar liberar la memoria reservada por StrToBin
    FreeMem(Buffer);
  end;
end;

procedure StrToStream(Str: String; Stream: TStream);
begin
  StrToStream(Str, TRUE, Stream);
end;

end.
