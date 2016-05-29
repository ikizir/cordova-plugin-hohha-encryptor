#import <Cordova/CDV.h>

@interface HohhaEncryptor : CDVPlugin

- (void) Init:(CDVInvokedUrlCommand*)command; 
- (void) CreateRSAPrvKey:(CDVInvokedUrlCommand*)command;
- (void) xorGetKey:(CDVInvokedUrlCommand*)command;
- (void) Encrypt:(CDVInvokedUrlCommand*)command; // Calls uint8_t *CreateHohhaCommunicationPacket(uint8_t *K, uint32_t KeyCheckSum, size_t InDataLen, uint8_t *InBuf, uint32_t DataAlignment)
- (void) Decrypt:(CDVInvokedUrlCommand*)command; 
- (void) EncryptForServer:(CDVInvokedUrlCommand*)command; 
- (void) EncryptWithUserRSAPubKey:(CDVInvokedUrlCommand*)command; 
- (void) DecryptWithUserRSAPrvKey:(CDVInvokedUrlCommand*)command; 
- (void) EncryptWithGivenRSAPubKey:(CDVInvokedUrlCommand*)command;
- (void) DecryptWithGivenRSAPrvKey:(CDVInvokedUrlCommand*)command;

@end