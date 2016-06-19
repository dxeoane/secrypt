unit SeEasyAES;

interface

uses Sysutils, Classes, SeAES256, SeStreams, seBase64, SeSHA256;

type
  // Cabecera que anteponemos a los datos cifrados
  TEasyAESHeader = packed record
    Version: Byte;              // Numero de version
    HeaderSize: Word;           // Tamaño de la cabecera, nos permite añadir informacion extra
    OriginalDataSize: int64;    // Tamaño, en bytes, de los datos antes de cifrarlos
    IV: TAESState;              // Vector de inicialización.
  end;

// Genera una "key" de 256 bits a partir de una cadena de texto
procedure EasyGenKey(var Key: TAESKey; Password: WideString);
// Streams
procedure EasyAESEnc(Src, Dst: TStream; Password: WideString); overload;
procedure EasyAESDec(Src, Dst: TStream; Password: WideString); overload;
// Strings
function EasyAESEnc(Str, Password: WideString): WideString; overload;
function EasyAESDec(Str, Password: WideString): WideString; overload;
// Ficheros
procedure EasyAESEnc(SrcFile, DstFile, Password: WideString); overload;
procedure EasyAESDec(SrcFile, DstFile, Password: WideString); overload;

implementation

procedure EasyGenKey(var Key: TAESKey; Password: WideString);
var
  Temp: TMemoryStream;
begin
  Temp:= TMemoryStream.Create;
  try
    Temp.WriteBuffer(PWideChar(Password)^,Length(Password)*SizeOf(WideChar));
    Temp.Position:= 0;
    // Usamos como key el hash SHA256 del password
    Key:= TAESKey(CalcSHA256(Temp));
  finally
    Temp.Free;
  end;
end;

procedure EasyAESEnc(Src, Dst: TStream; Password: WideString);  overload;
var
  Header: TEasyAESHeader;
  AESKey: TAESKey;
  AESEnc: TAESEnc;
begin
  // Inicializamos la cebecera
  FillChar(Header,Sizeof(Header),0);
  with Header do
  begin
    Version:= 1;
    HeaderSize:= Sizeof(TEasyAESHeader);
    OriginalDataSize:= Src.Size;
    // Generamos un IV aleatorio
    AESGenRandomIV(IV);
  end;
  // Escribimos la cabecera
  Dst.WriteBuffer(Header,Sizeof(Header));
  // Generamos la clave
  EasyGenKey(AESKey,Password);
  AESEnc:= TAESEnc.Create(Dst,AESKey,Header.IV);
  try
    // Ciframos el stream
    AESEnc.CopyFrom(Src,Src.Size);
  finally
    AESEnc.Free;
  end;
end;

procedure EasyAESDec(Src, Dst: TStream; Password: WideString);  overload;
var
  Header: TEasyAESHeader;
  AESKey: TAESKey;
  AESDec: TAESDec;
begin
  Src.Position:= 0;
  // Leemos la cabecera
  Src.ReadBuffer(Header,Sizeof(Header));
  // Comprobamos la version y el tamaño
  if (Header.Version <> 1) or (Header.HeaderSize < Sizeof(Header)) or
     (Header.HeaderSize > Src.Size) or (Header.OriginalDataSize < 0) then
    raise Exception.Create('Invalid header');
  // No saltamos la informacion "extra" si la hubiese
  Src.Position:= Header.HeaderSize;
  // Generamos la clave
  EasyGenKey(AESKey,Password);
  AESDec:= TAESDec.Create(Dst,AESKey,Header.IV);
  try
    // Desciframos el stream
    AESDec.CopyFrom(Src,Src.Size - Header.HeaderSize);
    // Restauramos su tamaño original
    if (Header.OriginalDataSize <= Dst.Size) then
      Dst.Size:= Header.OriginalDataSize
    else
     raise Exception.Create('Invalid data size');
  finally
    AESDec.Free;
  end;
end;

function EasyAESEnc(Str, Password: WideString): WideString; overload;
var
  Src, Dst: TMemoryStream;
begin
  Src:= TMemoryStream.Create;
  Dst:= TMemoryStream.Create;
  try
    // Guardamos el texto a cifrar en un stream temporal
    Src.WriteBuffer(PWideChar(Str)^,Length(Str)*SizeOf(WideChar));
    Src.Position:= 0;
    // Ciframos el stream
    EasyAESEnc(Src,Dst,Password);
    // Codificamos el resultado en base64
    Result:= BinToStr(PByteArray(Dst.Memory),Dst.Size);
  finally
    Src.Free;
    Dst.Free;
  end;
end;

function EasyAESDec(Str, Password: WideString): WideString; overload;
var
  Src, Dst: TMemoryStream;
begin
  Src:= TMemoryStream.Create;
  Dst:= TMemoryStream.Create;
  try
    // Metemos los datos cifrados en un stream:  base64 -> binario
    StrToStream(Str,Src);
    Src.Position:= 0;
    // Desciframos el stream
    EasyAESDec(Src,Dst,Password);
    // Devolvemos el texto descifrado
    Result:= Copy(WideString(PWideChar(Dst.Memory)),1,Dst.Size div Sizeof(WideChar));
  finally
    Src.Free;
    Dst.Free;
  end;
end;

procedure EasyAESEnc(SrcFile, DstFile, Password: WideString); overload;
var
  Src, Dst: TFileStream;
begin
  Src:= TFileStream.Create(SrcFile,fmOpenRead or fmShareDenyWrite);
  try
    Dst:= TFileStream.Create(DstFile,fmCreate);
    try
      EasyAESEnc(Src,Dst,Password);
    finally
      Dst.Free;
    end;
  finally
    Src.Free;
  end;
end;

procedure EasyAESDec(SrcFile, DstFile, Password: WideString); overload;
var
  Src, Dst: TFileStream;
begin
  Src:= TFileStream.Create(SrcFile,fmOpenRead or fmShareDenyWrite);
  try
    Dst:= TFileStream.Create(DstFile,fmCreate);
    try
      EasyAESDec(Src,Dst,Password);
    finally
      Dst.Free;
    end;
  finally
    Src.Free;
  end;
end;


end.
