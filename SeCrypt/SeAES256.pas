unit SeAES256;

{$IFDEF FPC}
  {$MODE delphi}
{$ENDIF}

interface

type
  TAESState = array[0..3,0..3] of Byte;
  TAESKey = array[0..7] of Cardinal;
  TAESExpandedKey = record
    Key: TAESKey;
    Size: Integer;
    ExpandedKey: array[0..59] of Cardinal; 
  end;
  PAESState = ^TAESState;

procedure AESExpandKey(var ExpandedKey: TAESExpandedKey;
  Key: TAESKey);  overload;
procedure AESExpandKey(var ExpandedKey: TAESExpandedKey; Key: TAESKey;
  Size: Integer);  overload;
procedure AESEncrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
procedure AESDecrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
procedure AESXORState(var S1: TAESState; S2: TAESState);
procedure AESSwapKey(var Key: TAESKey);
procedure AESCopyKey(var Key: TAESKey; Buffer: Pointer); overload;
procedure AESCopyKey(var Key: TAESKey; Buffer: Pointer;
  Size: Integer); overload;
procedure AESGenRandomIV(var IV: TAESState);


implementation

const
  Sbox: Array[0..255] of Byte = (
    $63,$7c,$77,$7b,$f2,$6b,$6f,$c5,$30,$01,$67,$2b,$fe,$d7,$ab,$76,
    $ca,$82,$c9,$7d,$fa,$59,$47,$f0,$ad,$d4,$a2,$af,$9c,$a4,$72,$c0,
    $b7,$fd,$93,$26,$36,$3f,$f7,$cc,$34,$a5,$e5,$f1,$71,$d8,$31,$15,
    $04,$c7,$23,$c3,$18,$96,$05,$9a,$07,$12,$80,$e2,$eb,$27,$b2,$75,
    $09,$83,$2c,$1a,$1b,$6e,$5a,$a0,$52,$3b,$d6,$b3,$29,$e3,$2f,$84,
    $53,$d1,$00,$ed,$20,$fc,$b1,$5b,$6a,$cb,$be,$39,$4a,$4c,$58,$cf,
    $d0,$ef,$aa,$fb,$43,$4d,$33,$85,$45,$f9,$02,$7f,$50,$3c,$9f,$a8,
    $51,$a3,$40,$8f,$92,$9d,$38,$f5,$bc,$b6,$da,$21,$10,$ff,$f3,$d2,
    $cd,$0c,$13,$ec,$5f,$97,$44,$17,$c4,$a7,$7e,$3d,$64,$5d,$19,$73,
    $60,$81,$4f,$dc,$22,$2a,$90,$88,$46,$ee,$b8,$14,$de,$5e,$0b,$db,
    $e0,$32,$3a,$0a,$49,$06,$24,$5c,$c2,$d3,$ac,$62,$91,$95,$e4,$79,
    $e7,$c8,$37,$6d,$8d,$d5,$4e,$a9,$6c,$56,$f4,$ea,$65,$7a,$ae,$08,
    $ba,$78,$25,$2e,$1c,$a6,$b4,$c6,$e8,$dd,$74,$1f,$4b,$bd,$8b,$8a,
    $70,$3e,$b5,$66,$48,$03,$f6,$0e,$61,$35,$57,$b9,$86,$c1,$1d,$9e,
    $e1,$f8,$98,$11,$69,$d9,$8e,$94,$9b,$1e,$87,$e9,$ce,$55,$28,$df,
    $8c,$a1,$89,$0d,$bf,$e6,$42,$68,$41,$99,$2d,$0f,$b0,$54,$bb,$16
  );

  LogTable: Array[0..255] of Byte = (
    $00,$ff,$c8,$08,$91,$10,$d0,$36,$5a,$3e,$d8,$43,$99,$77,$fe,$18,
    $23,$20,$07,$70,$a1,$6c,$0c,$7f,$62,$8b,$40,$46,$c7,$4b,$e0,$0e,
    $eb,$16,$e8,$ad,$cf,$cd,$39,$53,$6a,$27,$35,$93,$d4,$4e,$48,$c3,
    $2b,$79,$54,$28,$09,$78,$0f,$21,$90,$87,$14,$2a,$a9,$9c,$d6,$74,
    $b4,$7c,$de,$ed,$b1,$86,$76,$a4,$98,$e2,$96,$8f,$02,$32,$1c,$c1,
    $33,$ee,$ef,$81,$fd,$30,$5c,$13,$9d,$29,$17,$c4,$11,$44,$8c,$80,
    $f3,$73,$42,$1e,$1d,$b5,$f0,$12,$d1,$5b,$41,$a2,$d7,$2c,$e9,$d5,
    $59,$cb,$50,$a8,$dc,$fc,$f2,$56,$72,$a6,$65,$2f,$9f,$9b,$3d,$ba,
    $7d,$c2,$45,$82,$a7,$57,$b6,$a3,$7a,$75,$4f,$ae,$3f,$37,$6d,$47,
    $61,$be,$ab,$d3,$5f,$b0,$58,$af,$ca,$5e,$fa,$85,$e4,$4d,$8a,$05,
    $fb,$60,$b7,$7b,$b8,$26,$4a,$67,$c6,$1a,$f8,$69,$25,$b3,$db,$bd,
    $66,$dd,$f1,$d2,$df,$03,$8d,$34,$d9,$92,$0d,$63,$55,$aa,$49,$ec,
    $bc,$95,$3c,$84,$0b,$f5,$e6,$e7,$e5,$ac,$7e,$6e,$b9,$f9,$da,$8e,
    $9a,$c9,$24,$e1,$0a,$15,$6b,$3a,$a0,$51,$f4,$ea,$b2,$97,$9e,$5d,
    $22,$88,$94,$ce,$19,$01,$71,$4c,$a5,$e3,$c5,$31,$bb,$cc,$1f,$2d,
    $3b,$52,$6f,$f6,$2e,$89,$f7,$c0,$68,$1b,$64,$04,$06,$bf,$83,$38
  );

type
  MultNum = (m2,m3,m9,mB,mD,mE);

var
  InvSbox: Array[0..255] of Byte;
  Mult: Array[MultNum,0..255] of Byte;

procedure SubBytes(var State: TAESState);
var
  i,j: Integer;
begin
  for i:= 0 to 3 do
    for j:= 0 to 3 do
      State[i,j]:= Sbox[State[i,j]];
end;

procedure InvSubBytes(var State: TAESState);
var
  i,j: Integer;
begin
  for i:= 0 to 3 do
    for j:= 0 to 3 do
      State[i,j]:= InvSbox[State[i,j]];
end;

procedure ShiftRows(var State: TAESState);
var
  i,j,k: Integer;
begin
  for j:= 1 to 3 do
    for i:= j downto 1 do
    begin
      k:= State[0,j];
      State[0,j]:= State[1,j];
      State[1,j]:= State[2,j];
      State[2,j]:= State[3,j];
      State[3,j]:= k;
    end;
end;

procedure InvShiftRows(var State: TAESState);
var
  i,j,k: Integer;
begin
  for j:= 1 to 3 do
    for i:= j downto 1 do
    begin
      k:= State[3,j];
      State[3,j]:= State[2,j];
      State[2,j]:= State[1,j];
      State[1,j]:= State[0,j];
      State[0,j]:= k;
    end;
end;

procedure MixColumns(var State: TAESState);
var
  i,j: Integer;
  m: Array[0..3] of Byte;
begin
  for i:= 0 to 3 do
  begin
    for j:= 0 to 3 do
      m[j]:= State[i,j];
    State[i,0]:= Mult[m2,m[0]] XOR Mult[m3,m[1]] XOR m[2]          XOR m[3];
    State[i,1]:=          m[0] XOR Mult[m2,m[1]] XOR Mult[m3,m[2]] XOR m[3];
    State[i,2]:=          m[0] XOR m[1]          XOR Mult[m2,m[2]] XOR Mult[m3,m[3]];
    State[i,3]:= Mult[m3,m[0]] XOR m[1]          XOR m[2]          XOR Mult[m2,m[3]];
  end;
end;

procedure InvMixColumns(var State: TAESState);
var
  i,j: Integer;
  m: Array[0..3] of Byte;
begin
  for i:= 0 to 3 do
  begin
    for j:= 0 to 3 do
      m[j]:= State[i,j];
    State[i,0]:=
      Mult[mE,m[0]] XOR Mult[mB,m[1]] XOR Mult[mD,m[2]] XOR Mult[m9,m[3]];
    State[i,1]:=
      Mult[m9,m[0]] XOR Mult[mE,m[1]] XOR Mult[mB,m[2]] XOR Mult[mD,m[3]];
    State[i,2]:=
      Mult[mD,m[0]] XOR Mult[m9,m[1]] XOR Mult[mE,m[2]] XOR Mult[mB,m[3]];
    State[i,3]:=
      Mult[mB,m[0]] XOR Mult[mD,m[1]] XOR Mult[m9,m[2]] XOR Mult[mE,m[3]];
  end;
end;

procedure AddRoundKey(var State: TAESState; ExpandedKey: TAESExpandedKey;
  Round: Integer);
var
  i: Integer;
  W: Cardinal;
begin
  for i:= 0 to 3 do
  begin
    W:= ExpandedKey.ExpandedKey[(Round * 4) + i];
    State[i,0]:= State[i,0] XOR ((W shr 24) and $FF);
    State[i,1]:= State[i,1] XOR ((W shr 16) and $FF);
    State[i,2]:= State[i,2] XOR ((W shr 8) and $FF);
    State[i,3]:= State[i,3] XOR  (W and $FF);
  end;
end;

function SubWord(W: Cardinal): Cardinal;
begin
  Result:= (Sbox[W shr 24] shl 24) or
           (Sbox[(W shr 16) and $FF] shl 16) or
           (Sbox[(W shr 8) and $FF] shl 8) or
            Sbox[W and $FF];                         
end;

function RotWord(W: Cardinal): Cardinal;
begin
  Result:= (W shl 8) or (W shr 24);
end;

function RCon(n: Integer): Cardinal;
begin
  Result:= 1;
  if n = 0 then
    Result:= 0
  else while n > 1 do
  begin
    Result:= Mult[m2,Result];
    dec(n);
  end;
  Result:= Result shl 24;
end;

procedure AESExpandKey(var ExpandedKey: TAESExpandedKey; Key: TAESKey;
  Size: Integer);  overload;
var
  i: Integer;
  Temp: Cardinal;
begin
  FillChar(ExpandedKey,Sizeof(ExpandedKey),#0);
  ExpandedKey.Key:= Key;
  if Size >= 256 then
    ExpandedKey.Size:= 256
  else if Size >= 192 then
    ExpandedKey.Size:= 192
  else if Size >= 128 then
    ExpandedKey.Size:= 128
  else ExpandedKey.Size:= 256;
  case ExpandedKey.Size of
    256: begin
      for i:= 0 to 7 do
        ExpandedKey.ExpandedKey[i]:= Key[i];
      for i:= 8 to 59 do
      begin
        Temp:= ExpandedKey.ExpandedKey[i-1];
        if (i mod 8 = 0) then
          Temp:= SubWord(RotWord(Temp)) XOR Rcon(i div 8)
        else if (i mod 8 = 4) then
          Temp:= SubWord(temp);
        ExpandedKey.ExpandedKey[i]:= ExpandedKey.ExpandedKey[i-8] XOR Temp;
      end;
    end;
    192: begin
      for i:= 0 to 5 do
        ExpandedKey.ExpandedKey[i]:= Key[i];
      for i:= 6 to 51 do
      begin
        Temp:= ExpandedKey.ExpandedKey[i-1];
        if (i mod 6 = 0) then
          Temp:= SubWord(RotWord(Temp)) XOR Rcon(i div 6);
        ExpandedKey.ExpandedKey[i]:= ExpandedKey.ExpandedKey[i-6] XOR Temp;
      end;
    end;
    128: begin
      for i:= 0 to 3 do
        ExpandedKey.ExpandedKey[i]:= Key[i];
      for i:= 4 to 43 do
      begin
        Temp:= ExpandedKey.ExpandedKey[i-1];
        if (i mod 4 = 0) then
          Temp:= SubWord(RotWord(Temp)) XOR Rcon(i div 4);
        ExpandedKey.ExpandedKey[i]:= ExpandedKey.ExpandedKey[i-4] XOR Temp;
      end;
    end;
  end;
end;

procedure AESExpandKey(var ExpandedKey: TAESExpandedKey; Key: TAESKey);
begin
  AESExpandKey(ExpandedKey,Key,256);
end;

procedure AESEncrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
var
  i, Round: Integer;
begin
  case ExpandedKey.Size of
    192: i:= 11;
    128: i:= 9;
    else i:= 13;
  end;
  AddRoundKey(State,ExpandedKey,0);
  for Round:= 1 to i do
  begin
    SubBytes(State);
    ShiftRows(State);
    MixColumns(State);
    AddRoundKey(State,ExpandedKey,Round);
  end;
  SubBytes(State);
  ShiftRows(State);
  AddRoundKey(State,ExpandedKey,i+1); 
end;

procedure AESDecrypt(var State: TAESState; ExpandedKey: TAESExpandedKey);
var
  i, Round: Integer;
begin
  case ExpandedKey.Size of
    192: i:= 11;
    128: i:= 9;
    else i:= 13;
  end;
  AddRoundKey(State,ExpandedKey,i+1);
  for Round:= i downto 1 do
  begin
    InvShiftRows(State);
    InvSubBytes(State);
    AddRoundKey(State,ExpandedKey,Round);
    InvMixColumns(State);
  end;
  InvShiftRows(State);
  InvSubBytes(State);
  AddRoundKey(state,ExpandedKey,0);
end;

procedure AESXORState(var S1: TAESState; S2: TAESState);
var
  i,j: Integer;
begin
  for i:= 0 to 3 do
    for j:= 0 to 3 do
      S1[i,j]:= S1[i,j] XOR S2[i,j];
end;

procedure AESSwapKey(var Key: TAESKey);
var
  i: Integer;
begin
  for i:= 0 to 7 do
  begin
    Key[i]:=
      ((Key[i] and $000000FF) shl 24) or
      ((Key[i] and $0000FF00) shl 8) or
      ((Key[i] and $00FF0000) shr 8) or
      ((Key[i] and $FF000000) shr 24);
  end;
end;

procedure AESCopyKey(var Key: TAESKey; Buffer: Pointer;
  Size: Integer); overload;
begin
  if Size >= 256 then
    Size:= 32
  else if Size >= 192 then
    Size:= 24
  else if Size >= 128 then
    Size:= 16
  else Size:= 32;
  FillChar(Key,Sizeof(Key),0);
  move(Buffer^,Key,Size);
  AESSwapKey(Key);
end;

procedure AESCopyKey(var Key: TAESKey; Buffer: Pointer);
begin
  AESCopyKey(Key,Buffer,256);
end;

procedure AESGenRandomIV(var IV: TAESState);
var
  i, j: Integer;
begin
  Randomize;
  for i:= 0 to 3 do
    for j:= 0 to 3 do
      IV[i,j]:= Byte(Random(256));      
end;

// Crea las tablas InvSbox y Mult
procedure InitTables;
var
  i: Integer;
  // Solo la necesitamos para crear la tabla Mult
  InvLogTable: Array[0..255] of Byte;
begin
  // InvSbox
  for i:= 0 to 255 do
    InvSbox[SBox[i]]:= i;
  // InvLogTable
  InvLogTable[0]:= $01;
  for i:= 1 to 255 do
    InvLogTable[LogTable[i]]:= i;
  // Mult
  Mult[m2,0]:= 0;
  Mult[m3,0]:= 0;
  Mult[m9,0]:= 0;
  Mult[mB,0]:= 0;
  Mult[mD,0]:= 0;
  Mult[mE,0]:= 0;
  for i:= 1 to 255 do
  begin
    Mult[m2,i]:= InvLogTable[(LogTable[$2] + LogTable[i]) mod $FF];
    Mult[m3,i]:= InvLogTable[(LogTable[$3] + LogTable[i]) mod $FF];
    Mult[m9,i]:= InvLogTable[(LogTable[$9] + LogTable[i]) mod $FF];
    Mult[mB,i]:= InvLogTable[(LogTable[$B] + LogTable[i]) mod $FF];
    Mult[mD,i]:= InvLogTable[(LogTable[$D] + LogTable[i]) mod $FF];
    Mult[mE,i]:= InvLogTable[(LogTable[$E] + LogTable[i]) mod $FF];
  end;
end;

initialization
  InitTables;
finalization

end.
