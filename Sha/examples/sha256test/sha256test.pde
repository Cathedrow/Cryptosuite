#include "sha256.h"

uint8_t hmacKey1[]={
  0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
};
uint8_t hmacKey2[]={
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,
  0x15,0x16,0x17,0x18,0x19
};
uint8_t hmacKey3[]={
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
};
uint8_t hmacKey4[]={
  0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c
};
uint8_t hmacKey5[]={
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
  0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
};

void printHash(uint8_t* hash) {
  int i;
  for (i=0; i<32; i++) {
    Serial.print("0123456789abcdef"[hash[i]>>4]);
    Serial.print("0123456789abcdef"[hash[i]&0xf]);
  }
  Serial.println();
}

void setup() {
  uint8_t* hash;
  uint32_t a;
  
  Serial.begin(9600);

  // SHA tests
  Serial.println("Test: FIPS 180-2 B.1");
  Serial.println("Expect:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  Serial.print("Result:");
  Sha256.init();
  Sha256.print("abc");
  printHash(Sha256.result());
  Serial.println();

  Serial.println("Test: FIPS 180-2 B.2");
  Serial.println("Expect:248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  Serial.print("Result:");
  Sha256.init();
  Sha256.print("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  printHash(Sha256.result());
  Serial.println();

  // HMAC tests
  Serial.println("Test: RFC4231 4.2");
  Serial.println("Expect:b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  Serial.print("Result:");
  Sha256.initHmac(hmacKey1,20);
  Sha256.print("Hi There");
  printHash(Sha256.resultHmac());
  Serial.println();
  
  Serial.println("Test: RFC4231 4.3");
  Serial.println("Expect:5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  Serial.print("Result:");
  Sha256.initHmac((uint8_t*)"Jefe",4);
  Sha256.print("what do ya want for nothing?");
  printHash(Sha256.resultHmac());
  Serial.println();
  
  Serial.println("Test: RFC4231 4.4");
  Serial.println("Expect:773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
  Serial.print("Result:");
  Sha256.initHmac(hmacKey3,20);
  for (a=0; a<50; a++) Sha256.write(0xdd);
  printHash(Sha256.resultHmac());
  Serial.println();

  Serial.println("Test: RFC4231 4.5");
  Serial.println("Expect:82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
  Serial.print("Result:");
  Sha256.initHmac(hmacKey2,25);
  for (a=0; a<50; a++) Sha256.write(0xcd);
  printHash(Sha256.resultHmac());
  Serial.println();
  
  Serial.println("Test: RFC4231 4.6");
  Serial.println("Expect:a3b6167473100ee06e0c796c2955552b-------------------------------");
  Serial.print("Result:");
  Sha256.initHmac(hmacKey4,20);
  Sha256.print("Test With Truncation");
  printHash(Sha256.resultHmac());
  Serial.println();
  
  Serial.println("Test: RFC4231 4.7");
  Serial.println("Expect:60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  Serial.print("Result:");
  Sha256.initHmac(hmacKey5,131);
  Sha256.print("Test Using Larger Than Block-Size Key - Hash Key First");
  printHash(Sha256.resultHmac());
  Serial.println();

  Serial.println("Test: RFC4231 4.8");
  Serial.println("Expect:9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
  Serial.print("Result:");
  Sha256.initHmac(hmacKey5,131);
//  Sha256.print("This is a test using a larger than block-size key and a larger than "
//  "block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
  printHash(Sha256.resultHmac());
  Serial.println();
  
  // Long tests 
  Serial.println("Test: FIPS 180-2 B.3 (Processing 1000000 characters. This will take a while.)");
  Serial.println("Expect:cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  Serial.print("Result:");
  Sha256.init();
  for (a=0; a<1000000; a++) Sha256.write('a');
  printHash(Sha256.result());
}

void loop() {
}