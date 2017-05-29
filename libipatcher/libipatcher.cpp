//
//  libipatcher.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include "all_libipatcher.h"
#include <libipatcher/libipatcher.hpp>
#include <curl/curl.h>
#include <cstdlib>
#include <cstring>
#include <functional>
extern "C" {
#include "jssy.h"
#include <xpwn/libxpwn.h>
#include <xpwn/pwnutil.h>
#include <xpwn/nor_files.h>
#include <include/iBoot32Patcher.h>
#include <include/functions.h>
#include <include/patchers.h>
}


#define FIRMWARE_JSON_URL_START "https://firmware-keys.ipsw.me/firmware/"
#define reterror(err) throw exception(__LINE__,err)
#define assure(cond) if ((cond) == 0) throw exception(__LINE__)
#define retassure(err,cond) if ((cond) == 0) throw exception(__LINE__,err)

#define bswap32 __builtin_bswap32

#define IMAGE3_MAGIC 'Img3'
#define IBOOT_VERS_STR_OFFSET 0x286
#define IBOOT32_RESET_VECTOR_BYTES bswap32(0x0E0000EA)


namespace libipatcher {
    namespace helpers {
        size_t downloadFunction(void* buf, size_t size, size_t nmemb, std::string &data) {
            data.append((char*)buf, size*nmemb);
            return nmemb*size;
        }
        int parseHex(const char *nonce, size_t nonceLen, unsigned char *ret, size_t retSize){
            nonceLen = nonceLen/2 + nonceLen%2; //one byte more if len is odd
            
            if (!ret) return -3;
            
            memset(ret, 0, retSize);
            unsigned int nlen = 0;
            
            int next = strlen(nonce)%2 == 0;
            char tmp = 0;
            while (*nonce && retSize) {
                char c = *(nonce++);
                
                tmp *=16;
                if (c >= '0' && c<='9') {
                    tmp += c - '0';
                }else if (c >= 'a' && c <= 'f'){
                    tmp += 10 + c - 'a';
                }else if (c >= 'A' && c <= 'F'){
                    tmp += 10 + c - 'A';
                }else{
                    return -1; //ERROR parsing failed
                }
                if ((next =! next) && nlen < nonceLen)
                    ret[nlen++] = tmp,tmp=0,retSize--;
            }
            return 0;
        }
        template <typename T>
        class ptr_smart {
            std::function<void(T)> _ptr_free = NULL;
            T p;
        public:
            ptr_smart(T pp, std::function<void(T)> ptr_free) : p(pp) {static_assert(std::is_pointer<T>(), "error: this is for pointers only\n"); _ptr_free = ptr_free;}
            ptr_smart(T pp) {p = pp;}
            ptr_smart() {p = NULL;}
            T operator=(T pp) {return p = pp;}
            T *operator&() {return &p;}
            operator const T() const {return p;}
            ~ptr_smart() {if (p) (_ptr_free) ? _ptr_free(p) : free((void*)p);}
        };
        
        class AbstractFile_smart{
        public:
            AbstractFile* p;
            AbstractFile_smart() {p = NULL;};
            AbstractFile_smart(AbstractFile *pp) {p = pp;};
            AbstractFile* operator=(AbstractFile* pp) {return p = pp;}
            AbstractFile* *operator&() {return &p;}
            ~AbstractFile_smart() {if (p) p->close(p),p = NULL;};
        };
        
    }
    std::string getFirmwareJson(const std::string &device, const std::string &buildnum);
    std::pair<char*,size_t>patchfile(char *ibss, size_t ibssSize, const fw_key &keys, const std::string &findstr, std::function<int(char *, size_t)> patchfunc);
}
using namespace std;
using namespace libipatcher;
using namespace helpers;

string libipatcher::getFirmwareJson(const std::string &device, const std::string &buildnum){
    string buf;
    CURL *mc = curl_easy_init();
    assure(mc);
    
    string url(FIRMWARE_JSON_URL_START);
    url += device + "/" + buildnum;
    
    curl_easy_setopt(mc, CURLOPT_URL, url.c_str());
    curl_easy_setopt(mc, CURLOPT_USERAGENT, "libipatcher/" LIBIPATCHER_VERSION_COMMIT_COUNT " APIKEY=" LIBIPATCHER_VERSION_COMMIT_SHA);
    curl_easy_setopt(mc, CURLOPT_CONNECTTIMEOUT, 30);
    curl_easy_setopt(mc, CURLOPT_FOLLOWLOCATION, 1);
    
    curl_easy_setopt(mc, CURLOPT_WRITEFUNCTION, &helpers::downloadFunction);
    curl_easy_setopt(mc, CURLOPT_WRITEDATA, &buf);

    assure(curl_easy_perform(mc) == CURLE_OK);

    curl_easy_cleanup(mc);
    return buf;
}


fw_key libipatcher::getFirmwareKey(const std::string &device, const std::string &buildnum, std::string file){
    if (file == "RestoreLogo")
        file = "AppleLogo";
    else if (file == "RestoreRamDisk")
        file = "RestoreRamdisk";
    else if (file == "RestoreDeviceTree")
        file = "DeviceTree";
    else if (file == "RestoreKernelCache")
        file = "Kernelcache";
    
    fw_key rt;
    ptr_smart<jssytok_t*> tokens = NULL;
    long tokensCnt = 0;
    
    string json = getFirmwareJson(device, buildnum);
    
    assure((tokensCnt = jssy_parse(json.c_str(), json.size(), NULL, 0)) > 0);
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(json.c_str(), json.size(), tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);
    
    jssytok_t *keys = jssy_dictGetValueForKey(tokens, "keys");
    assure(keys);
    
    jssytok_t *iv = NULL;
    jssytok_t *key = NULL;
    jssy_doForValuesInArray(keys, {
        jssytok_t *image = jssy_dictGetValueForKey(t, "image");
        assure(image);
        if (strncmp(file.c_str(), image->value, image->size) == 0){
            iv = jssy_dictGetValueForKey(t, "iv");
            key = jssy_dictGetValueForKey(t, "key");
            break;
        }
    });
    assure(iv && key);
    
    assure(iv->size <= sizeof(rt.iv));
    assure(key->size <= sizeof(rt.key));
    memcpy(rt.iv, iv->value, iv->size);
    memcpy(rt.key, key->value, key->size);
    rt.iv[sizeof(rt.iv)-1] = 0;
    rt.key[sizeof(rt.key)-1] = 0;
    
    return rt;
}

pair<char*,size_t>libipatcher::patchfile(char *ibss, size_t ibssSize, const fw_key &keys, const string&findstr, function<int(char *, size_t)> patchfunc){
    TestByteOrder();
    char *decibss = NULL;
    size_t decibssSize = 0;
    ptr_smart<unsigned int *>key;
    ptr_smart<unsigned int *>iv;
    AbstractFile *afibss;
    char *patched = NULL;
    size_t patchedSize = 0;
    AbstractFile *enc = NULL;
    
    size_t bytes;
    hexToInts(keys.iv, &iv, &bytes);
    assure(bytes == 16);
    hexToInts(keys.key, &key, &bytes);
    assure(bytes == 32);
    
    assure(afibss = openAbstractFile2(enc = createAbstractFileFromMemoryFile((void**)&ibss, &ibssSize), key, iv));
    assure(decibssSize = afibss->getLength(afibss));
    assure(decibss = (char*)malloc(decibssSize));
    assure(afibss->read(afibss,decibss, decibssSize) == decibssSize);
    
    assure(*decibss != '3' && memmem(decibss, decibssSize, findstr.c_str() , findstr.size()));
    
    //patch here
    assure(!patchfunc(decibss, decibssSize));
    
    //close file
    assure(patched = (char*)malloc(1));
    
    AbstractFile_smart newFile = duplicateAbstractFile2(enc, createAbstractFileFromMemoryFile((void**)&patched, &patchedSize), NULL, NULL, NULL);
    assure(newFile.p);
    assure(newFile.p->write(newFile.p, decibss, decibssSize) == decibssSize);
    newFile.p->close(newFile.p);
    newFile = NULL;
    
    return pair<char*,size_t>{patched,patchedSize};
}

int iBoot32Patch(char *deciboot, size_t decibootSize){
    struct iboot_img iboot_in;
    iboot_in.buf = deciboot;
    iboot_in.len = decibootSize;
    int ret = 0;
    const char* iboot_vers_str = ((char*)iboot_in.buf + IBOOT_VERS_STR_OFFSET);
    
    iboot_in.VERS = atoi(iboot_vers_str);
    if(!iboot_in.VERS) {
        printf("%s: No iBoot version found!\n", __FUNCTION__);
        return -1;
    }
    
    printf("%s: iBoot-%d inputted.\n", __FUNCTION__, iboot_in.VERS);
    
    /* Check to see if the loader has a kernel load routine before trying to apply custom boot args + debug-enabled override. */
    if(has_kernel_load(&iboot_in)) {
        
        /* Only bootloaders with the kernel load routines pass the DeviceTree. */
        ret = patch_debug_enabled(&iboot_in);
        if(!ret) {
            printf("%s: Error doing patch_debug_enabled()!\n", __FUNCTION__);
            return -1;
        }
    }
    
    /* All loaders have the RSA check. */
    ret = patch_rsa_check(&iboot_in);
    if(!ret) {
        printf("%s: Error doing patch_rsa_check()!\n", __FUNCTION__);
        free(iboot_in.buf);
        return -1;
    }
    
    printf("%s: Quitting...\n", __FUNCTION__);
    return 0;
}

pair<char*,size_t>libipatcher::patchiBSS(char *ibss, size_t ibssSize, const fw_key &keys){
    return patchfile(ibss, ibssSize, keys, "iBSS", iBoot32Patch);
}

pair<char*,size_t>libipatcher::patchiBEC(char *ibec, size_t ibecSize, const libipatcher::fw_key &keys){
    return patchfile(ibec, ibecSize, keys, "iBEC", iBoot32Patch);
}

pair<char*,size_t>libipatcher::decryptFile3(char *encfile, size_t encfileSize, const libipatcher::fw_key &keys){
    TestByteOrder();
    char *decibss = NULL;
    size_t decibssSize = 0;
    ptr_smart<unsigned int *>key;
    ptr_smart<unsigned int *>iv;
    AbstractFile *afibss;
    char *patched = NULL;
    size_t patchedSize = 0;
    AbstractFile *enc = NULL;
    
    size_t bytes;
    hexToInts(keys.iv, &iv, &bytes);
    assure(bytes == 16);
    hexToInts(keys.key, &key, &bytes);
    assure(bytes == 32);
    
    assure(afibss = openAbstractFile3(enc = createAbstractFileFromMemoryFile((void**)&encfile, &encfileSize), key, iv, 0));
    assure(decibssSize = afibss->getLength(afibss));
    assure(decibss = (char*)malloc(decibssSize));
    assure(afibss->read(afibss,decibss, decibssSize) == decibssSize);
    
    assure(*decibss != '3');
    
    //close file
    assure(patched = (char*)malloc(1));
    
    AbstractFile_smart newFile = duplicateAbstractFile2(enc, createAbstractFileFromMemoryFile((void**)&patched, &patchedSize), NULL, NULL, NULL);
    assure(newFile.p);
    assure(newFile.p->write(newFile.p, decibss, decibssSize) == decibssSize);
    newFile.p->close(newFile.p);
    newFile = NULL;
    
    return pair<char*,size_t>{patched,patchedSize};
}



















