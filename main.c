/* cracker for casascius's contest, details here:

   https://bitcointalk.org/index.php?topic=128699.0

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include "scrypt/crypto/crypto_scrypt.h"
#include "ccoin/base58.h"
#include "ccoin/key.h"
#include "ccoin/address.h"

#define NUM_THREADS 8

void print_hex(char * hex, size_t len) {
    int i;
    for(i=0; i<len; i++) {
        printf("%.02x",(unsigned char)hex[i]);
    }
}

#define PASSFACTOR_SIZE 32
#define PASSPHRASE_MAGIC_SIZE 8
#define PASSPHRASE_SIZE (PASSPHRASE_MAGIC_SIZE + OWNERSALT_SIZE + 33)
#define DERIVED_SIZE 64
#define ADDRESSHASH_SIZE 4
#define OWNERSALT_SIZE 8
 
int crack(char * pKey, char * pKey_pass) {
    int i;
    uint8_t passfactor[PASSFACTOR_SIZE];

    /* printf("testing key %s, %s\r\n",pKey, pKey_pass); */

    GString * b58dec;
    b58dec = base58_decode_check(NULL,pKey);

    if(b58dec) {
        /*
        printf("%s", "base58decode of encrypted key: ");
        print_hex(b58dec->str,b58dec->len);
        printf("%s", "\r\n");
        printf("flagByte: %.02x addresshash:%.02x%.02x%.02x%.02x ownersalt:",
            (unsigned char)b58dec->str[2], (unsigned char)b58dec->str[3],
            (unsigned char)b58dec->str[4], (unsigned char)b58dec->str[5],
            (unsigned char)b58dec->str[6]);
       	print_hex(&b58dec->str[3+ADDRESSHASH_SIZE], OWNERSALT_SIZE);
        printf("\r\n");
        */
        memset(passfactor,0,PASSFACTOR_SIZE);
        crypto_scrypt( pKey_pass, strlen(pKey_pass), &(b58dec->str[3+ADDRESSHASH_SIZE]), OWNERSALT_SIZE, 16384, 8, 8, passfactor, PASSFACTOR_SIZE );
        /*
        printf("%s", "passfactor: ");
        print_hex(passfactor, PASSFACTOR_SIZE);
        printf("%s", "\r\n");
        */
    } else {
        fprintf(stderr,"%s","cannot b58 decode private key.");
        exit(1);
    }

    // compute EC point (passpoint) using passfactor
    struct bp_key ec_point;
    if(!bp_key_init(&ec_point)) {
        fprintf(stderr,"%s","cannot init EC point key");
        exit(3);
    }
    if(!bp_key_secret_set(&ec_point,passfactor,PASSFACTOR_SIZE)) {
        fprintf(stderr,"%s","cannot set EC point from passfactor");
        exit(3);
    }

    // get the passpoint as bytes
    unsigned char * passpoint;
    unsigned int passpoint_len;

    if(!bp_pubkey_get(&ec_point,(void *)&passpoint,&passpoint_len)) {
        fprintf(stderr,"%s","cannot get pubkey for EC point");
        exit(4);
    }

    /*
    printf("len is %d, passpoint: ", passpoint_len);
    print_hex(passpoint,passpoint_len);
    printf("%s", "\r\n");
    */

    /*
    // check: generate the passphrase
    char passphrase_bytes[PASSPHRASE_SIZE];
    char passphrase_magic[] = { 0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53 };
    memset(passphrase_bytes,0,PASSPHRASE_SIZE);
    memcpy(passphrase_bytes, passphrase_magic, PASSPHRASE_MAGIC_SIZE);
    memcpy(passphrase_bytes + PASSPHRASE_MAGIC_SIZE, &b58dec->str[3+ADDRESSHASH_SIZE], OWNERSALT_SIZE);
    memcpy(passphrase_bytes + PASSPHRASE_MAGIC_SIZE + OWNERSALT_SIZE, passpoint, passpoint_len);
    GString * passphrase_g = base58_encode_check(0,false,passphrase_bytes, PASSPHRASE_SIZE);
    printf("Passphrase: %s\r\n\r\n", passphrase_g->str);
    */

    // now we need to decrypt seedb
    uint8_t encryptedpart2[16];
    memset(encryptedpart2,0,16);
    memcpy(encryptedpart2,&b58dec->str[3 + ADDRESSHASH_SIZE + OWNERSALT_SIZE + 8],16);
    uint8_t encryptedpart1[16];
    memset(encryptedpart1,0,16);
    memcpy(encryptedpart1,&b58dec->str[3 + ADDRESSHASH_SIZE + OWNERSALT_SIZE],8);

    unsigned char derived[DERIVED_SIZE];
    // get the encryption key for seedb using scrypt with passpoint as the key, salt is addresshash+ownersalt
    unsigned char derived_scrypt_salt[ADDRESSHASH_SIZE + OWNERSALT_SIZE];
    memcpy(derived_scrypt_salt, &b58dec->str[3], ADDRESSHASH_SIZE); // copy the addresshash
    memcpy(derived_scrypt_salt+ADDRESSHASH_SIZE, &b58dec->str[3+ADDRESSHASH_SIZE], OWNERSALT_SIZE); // copy the ownersalt
    crypto_scrypt( passpoint, passpoint_len, derived_scrypt_salt, ADDRESSHASH_SIZE+OWNERSALT_SIZE, 1024, 1, 1, derived, DERIVED_SIZE );

    //get decryption key
    unsigned char derivedhalf2[DERIVED_SIZE/2];
    memcpy(derivedhalf2, derived+(DERIVED_SIZE/2), DERIVED_SIZE/2);

    unsigned char iv[32];
    memset(iv,0,32);
    EVP_CIPHER_CTX d;
    EVP_CIPHER_CTX_init(&d);
    EVP_DecryptInit_ex(&d, EVP_aes_256_ecb(), NULL, derivedhalf2, iv);

    unsigned char unencryptedpart2[32];
    int decrypt_len;
    EVP_DecryptUpdate(&d, unencryptedpart2, &decrypt_len, encryptedpart2, 16);
    EVP_DecryptUpdate(&d, unencryptedpart2, &decrypt_len, encryptedpart2, 16);
    for(i=0; i<16; i++) {
        unencryptedpart2[i] ^= derived[i + 16];
    }
    unsigned char unencryptedpart1[32];
    memcpy(encryptedpart1+8, unencryptedpart2, 8);
    EVP_DecryptUpdate(&d, unencryptedpart1, &decrypt_len, encryptedpart1, 16);
    EVP_DecryptUpdate(&d, unencryptedpart1, &decrypt_len, encryptedpart1, 16);
    for(i=0; i<16; i++) {
        unencryptedpart1[i] ^= derived[i];
    }

    // recoved seedb
    unsigned char seedb[24];
    memcpy(seedb, unencryptedpart1, 16);
    memcpy(&(seedb[16]), &(unencryptedpart2[8]), 8);

    // turn seedb into factorb (factorb = SHA256(SHA256(seedb)))
    unsigned char factorb[32];
    bu_Hash(factorb, seedb, 24);

    // multiply by passfactor (ec_point_pub)
    const EC_GROUP * ec_group = EC_KEY_get0_group(ec_point.k);
    const EC_POINT * ec_point_pub = EC_KEY_get0_public_key(ec_point.k);
    BIGNUM * bn_passfactor = BN_bin2bn(passfactor,32,BN_new());
    BIGNUM * bn_factorb = BN_bin2bn(factorb,32,BN_new());
    BIGNUM * bn_res = BN_new();
    BIGNUM * bn_final = BN_new();
    BIGNUM * bn_n = BN_new();
    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP_get_order(ec_group, bn_n, ctx);
    BN_mul(bn_res, bn_passfactor, bn_factorb, ctx);
    BN_mod(bn_final, bn_res, bn_n, ctx);

    unsigned char finalKey[32];
    memset(finalKey, 0, 32);
    int n = BN_bn2bin(bn_final, finalKey);

    BN_clear_free(bn_passfactor);
    BN_clear_free(bn_factorb);
    BN_clear_free(bn_res);
    BN_clear_free(bn_n);
    BN_clear_free(bn_final);

    // we have a private key! check hash
    /*
    printf("have private key: ");
    print_hex(finalKey, 32);
    printf("%s", "\r\n");
    */

    // turn it into a real address
    struct bp_key wallet;
    if(!bp_key_init(&wallet)) {
        fprintf(stderr,"%s","cannot init wallet key");
        exit(10);
    }
    if(!bp_key_secret_set(&wallet,finalKey,32)) {
        fprintf(stderr,"%s","cannot init wallet key");
        exit(10);
    }

    unsigned char * pubKey;
    size_t pubKeylen;
    bp_pubkey_get(&wallet, ((void **) &pubKey), &pubKeylen);

    /*
    printf("pubkey len: %d hex: ",pubKeylen);
    print_hex(pubKey,pubKeylen);
    printf("%s","\r\n");
    */

    GString * btcAddress;
    btcAddress = bp_pubkey_get_address(&wallet, 0);

    /*
    printf("address: %s\r\n",btcAddress->str);
    */

    unsigned char checkHash[32];
    bu_Hash(checkHash, btcAddress->str, strlen(btcAddress->str));

    /* printf("checkhash: %.02x%.02x%.02x%.02x\r\n",checkHash[0],checkHash[1],checkHash[2],checkHash[3]); */

    if(!memcmp(&b58dec->str[3],checkHash,4)) {
        printf("!!!!!!!!!!!!!!!!!!!!\r\n");
        printf("!!hash match found!!\r\n");
        printf("!!  key is %s  !!\r\n", pKey_pass);
        printf("!!!!!!!!!!!!!!!!!!!!\r\n");
        return 0;
    }

    return 1;
}

char pass[6]; // the current password being checked
pthread_mutex_t coderoll_mutex;
long unsigned int number_tested;

void coderoll(char * currentPass) {
    pthread_mutex_lock(&coderoll_mutex);
    if(number_tested % 10 == 0) {
        printf("total tested: %lu, current code: %s\r\n",number_tested, pass);
    }
    number_tested ++;
    pass[4]++;
    if(pass[4] > 'Z') {
        pass[4] = 'A';
        pass[3]++;
        if(pass[3] > 'z') {
            pass[3] = 'a';
            pass[2]++;
            if(pass[2] > 'Z') {
                pass[2] = 'A';
                pass[1]++;
                if(pass[1] > 'z') {
                    pass[1] = 'a';
                    pass[0]++;
                    if(pass[0] > 'Z') {
                        pass[0] = 'A';
                        pass[1] = 'a';
                        pass[2] = 'A';
                        pass[3] = 'a';
                        pass[4] = 'A';
                    }
                }
            }
        }
    }
    strcpy(currentPass,pass);
    pthread_mutex_unlock(&coderoll_mutex);
}

void * crackthread(void * ctx) {
    char * pKey;
    char currentPass[6];
    pKey = (char *)ctx;
    while(true) {
        coderoll(currentPass);
        if(!crack(pKey, currentPass)) {
            printf("found password: %s\r\n",currentPass);
            exit(0);
        }
    }
}

int main(int argc, char * argv[]) {
    int i;
    pthread_t threads[NUM_THREADS];
    number_tested = 0;
    printf("casascius bip38 private key brute forcer\r\n");

    /* takes a single command line arg. */
    /* if passed in, uses this as the starting string to check instead of AaAaA */
    if(argc > 1) {
        strncpy(pass,argv[1],5);
    } else {
        strncpy(pass,"AaAaA",5);
    }

    /* make sure the crack function is working */
    /*if(crack("6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd","Satoshi")){
    	fprintf(stderr,"the crack function is not working, sorry.");
    }*/

    /* the target encrypted private key to crack. */
    //const char pKey[] = "6PfTokDpyZUYwaVg37aZZ67MvD1bTyrCyjrjacz1XAgfVndWjZSsxLuDrE"; // official Casascius contest key

    const char pKey[] = "6PfMxA1n3cqYarHoDqPRPLpBBJGWLDY1qX94z8Qyjg7XAMNZJMvHLqAMyS"; // test key that decrypts with AaAaA
    pthread_mutex_t coderoll_mutex = PTHREAD_MUTEX_INITIALIZER;

    for(i=0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, crackthread, (void *)pKey);
    }

    pthread_exit(NULL);
    return 0;
}
