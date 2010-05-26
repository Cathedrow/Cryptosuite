#ifndef Sha1_h
#define Sha1_h

#include <inttypes.h>
#include "Print.h"

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

union _buffer {
  uint8_t b[BLOCK_LENGTH];
  uint32_t w[BLOCK_LENGTH/4];
};
union _state {
  uint8_t b[HASH_LENGTH];
  uint32_t w[HASH_LENGTH/4];
};

class Sha1Class : public Print
{
  public:
    void init(void);
    void initHmac(const uint8_t* secret, int secretLength);
    uint8_t* result(void);
    uint8_t* resultHmac(void);
    virtual void write(uint8_t);
    using Print::write;
  private:
    void pad();
    void addUncounted(uint8_t data);
    void hashBlock();
    uint32_t rol32(uint32_t number, uint8_t bits);
    _buffer buffer;
    uint8_t bufferOffset;
    _state state;
    uint32_t byteCount;
    uint8_t keyBuffer[BLOCK_LENGTH];
    uint8_t innerHash[HASH_LENGTH];
    
};
extern Sha1Class Sha1;

#endif
