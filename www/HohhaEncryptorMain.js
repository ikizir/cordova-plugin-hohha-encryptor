/*global cordova, module*/

module.exports = {
  Init : function(ServerRSAPubKeyDerAsUint8Arr, UserRSAPubKeyDerAsUint8Arr, UserRSAPrvKeyDerAsUint8Arr, fncCallback) { 
    cordova.exec(
      function(ResAsNum) { fncCallback(null,ResAsNum); }, 
      fncCallback, 
      "HohhaEncryptor", "Init", [ServerRSAPubKeyDerAsUint8Arr.buffer, UserRSAPubKeyDerAsUint8Arr.buffer, UserRSAPrvKeyDerAsUint8Arr.buffer]
    );
  },
  CreateRSAPrvKey : function(KeyBitSize, fncCallback) { 
    cordova.exec(
      function(PrvKeyDERAsArrayBuf) { 
        // If there is no error, binary der data will be copied to buffers
        fncCallback(null, new Uint8Array(PrvKeyDERAsArrayBuf)); 
      }, 
      fncCallback, 
      "HohhaEncryptor", "CreateRSAPrvKey", [KeyBitSize]
    );
  },
  xorGetKey : function(NumJumps, BodyLen, fncCallback) { // Returns ArrayBuffer key. In our callback we convert it to Uint8Array and call the original callback
    cordova.exec(
      function(KeyAsArrayBuf) { fncCallback(null, new Uint8Array(KeyAsArrayBuf)); }, 
      fncCallback, 
      "HohhaEncryptor", "xorGetKey", [NumJumps, BodyLen]
    );
  },
  Encrypt : function(Key, KeyCheckSum, InBuf, DataAlignment, UseThread, fncCallback) { // Key KeyCheckSum InBuf DataAlignment UseThread[1 or 0]
    cordova.exec(
      function(ABuf) { fncCallback(null, new Uint8Array(ABuf)); }, // Returns ArrayBuffer. In our callback we convert it to Uint8Array and call the original callback
      fncCallback, 
      "HohhaEncryptor", "Encrypt", [Key.buffer, KeyCheckSum, InBuf.buffer, DataAlignment, UseThread]
    );
  },
  Decrypt : function(Key, KeyCheckSum, InBuf, UseThread, fncCallback) { // Key KeyCheckSum InBuf UseThread[1 or 0]
    cordova.exec(
      function(ABuf) { fncCallback(null, new Uint8Array(ABuf)); }, // Returns ArrayBuffer. In our callback we convert it to Uint8Array and call the original callback
      fncCallback, 
      "HohhaEncryptor", "Decrypt", [Key.buffer, KeyCheckSum, InBuf.buffer, UseThread]
    );
  },
  EncryptForServer : function(DataBufToEncrypt, fncCallback) { // Encrypts data with server rsa public key
    cordova.exec(
      function(ABuf) { fncCallback(null, new Uint8Array(ABuf)); }, // Returns ArrayBuffer. In our callback we convert it to Uint8Array and call the original callback
      fncCallback, 
      "HohhaEncryptor", "EncryptForServer", [DataBufToEncrypt.buffer]
    );
  },
  EncryptWithUserRSAPubKey : function(DataBufToEncrypt, fncCallback) { // Encrypts data with server rsa public key
    cordova.exec(
      function(ABuf) { fncCallback(null, new Uint8Array(ABuf)); }, // Returns ArrayBuffer. In our callback we convert it to Uint8Array and call the original callback
      fncCallback, 
      "HohhaEncryptor", "EncryptWithUserRSAPubKey", [DataBufToEncrypt.buffer]
    );
  },
  DecryptWithUserRSAPrvKey : function(DataBufToDecrypt, fncCallback) { // Encrypts data with server rsa public key
    cordova.exec(
      function(ABuf) { fncCallback(null, new Uint8Array(ABuf)); }, // Returns ArrayBuffer. In our callback we convert it to Uint8Array and call the original callback
      fncCallback, 
      "HohhaEncryptor", "DecryptWithUserRSAPrvKey", [DataBufToDecrypt.buffer]
    );
  },
  EncryptWithGivenRSAPubKey : function(BinaryRSAPubKeyInDerEncoding, DataBufToEncrypt, fncCallback) { // Encrypts data with rsa public key in BinaryRSAPubKeyInDerEncoding
    cordova.exec(
      function(ABuf) { fncCallback(null, new Uint8Array(ABuf)); }, // Returns ArrayBuffer. In our callback we convert it to Uint8Array and call the original callback
      fncCallback, 
      "HohhaEncryptor", "EncryptWithGivenRSAPubKey", [BinaryRSAPubKeyInDerEncoding.buffer, DataBufToEncrypt.buffer]
    );
  },
  DecryptWithGivenRSAPrvKey : function(BinaryRSAPrvKeyInDerEncoding, DataBuf, fncCallback) { // USE ONLY FOR TESTING PURPOSES! IT PROBABLY HAS MEMORY LEAKS!
    cordova.exec(
      function(ABuf) { fncCallback(null, new Uint8Array(ABuf)); }, // Returns ArrayBuffer. In our callback we convert it to Uint8Array and call the original callback
      fncCallback, 
      "HohhaEncryptor", "DecryptWithGivenRSAPrvKey", [BinaryRSAPrvKeyInDerEncoding.buffer, DataBuf.buffer]
    );
  },
  TestHohhaXOREncryption : function ()
  {
      var fncGetKeyCallback = function(err, KeyAsUint8Array) {
        if (err)
          return console.error("Error creating key: "+errStr);
        //MyLog("Hohha XOR Key is created by C function: ", KeyAsUint8Array);
        xorAnalyzeKey(KeyAsUint8Array);
        var OriginalText = "Selamlar İsmail, nasılsın?";
        var OriginalBuf = StrToUTF8Arr(OriginalText);
        var KC = xorComputeKeyCheckSum(KeyAsUint8Array);
        this.Encrypt(KeyAsUint8Array, KC, OriginalBuf, 16, 1, function(err, A) {
          if (err)    
            return console.error("Encryption Error: "+errStr);
          console.log("Hohha encryption successful. The same packet decrypted back with Javascript function: ");//+DecryptCommPackToUTF8(KeyAsUint8Array, KC, A));
          this.Decrypt(KeyAsUint8Array, KC, A, 1, function(err, Dc) {
            if (err)    
              return console.error("Decryption Error: "+errStr);
            console.log("Hohha decryption successfull. A: "+Dc);
            var DcText = UTF8ArrToStr(Dc);
            console.log("Converted to text: "+DcText);
          });
        });
      };  
      this.xorGetKey(3, 256, fncGetKeyCallback);
  }

};
