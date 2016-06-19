# SeCrypt
Colección de funciones criptográficas para Pascal (Delphi, freepascal, etc ...).

Incluye, por ahora, los algoritmos AES256 (Rijndael), SHA256 y base64.

El objetivo principal es tener unas funciones sencillas, que puedan ser utilizadas con diferentes compiladores (delphi, freepascal, ...) y en diferentes sistemas operativos (windows, linux, android, etc ...)

### Estructura

SeAES256.pas

    AESExpandKey
        Prepara la clave para ser utilizada
    AESEncrypt
        Cifra un bloque de 16 bytes
    AESDecrypt
        Descifra un bloque de 16 bytes
    AESXORState
        Realiza la operación XOR sobre dos bloques
    AESSwapKey
        Intercambia el orden de los bytes de la clave
    AESCopyKey
        Copia el contenido de una porción de memoria para ser utilizada como clave

SeBase64.pas

    BinToStr
        Convierte un conjunto de datos binarios en una cadena de texto (base64)
    StrToBin
        Convierte una cadena de texto (base64) en un conjunto de datos binarios
    Base64CleanStr
        Limpia una cadena de texto de todos los caracteres que no pertenecen a base64

SeSha256.pas

    CalcSHA256
        Calcula el hash SHA256 de un conjunto de datos binarios, o de una cadena de texto
    SHA256ToStr
        Presenta el hash en formato hexadecimal para que pueda ser leído

SeMD5.pas

    CalcMD5
        Calcula el hash MD5 de un conjunto de datos binarios, o de una cadena de texto
    MD5ToStr
        Presenta el hash en formato hexadecimal para que pueda ser leído

SeStreams.pas

    TAESEnc
        Stream para cifrar datos usando AES256 con el metdodo CBC (Cipher-block chaining)
    TAESDec
        Stream para descifrar datos usando AES256 con el metdodo CBC (Cipher-block chaining)
    TBase64Enc
        Stream para codificar en base64 un conjunto de datos binarios
    TBase64Dec
        Stream para descodificar un conjunto de datos codificados en base64
    StrToStream
        Decodifica un conjunto de datos codificados en base64 y los guarda en un stream

SeEasyAES.pas (NUEVO!)

    EasyGenKey
        Genera una clave de cifrado de 256 bits a partir de un texto
    EasyAESEnc
        Cifra utilizando AES 256 CBC con un un IV aleatorio.
    EasyAESDec
        Descifra datos cifrados con la funcion EasyAESEnc.
