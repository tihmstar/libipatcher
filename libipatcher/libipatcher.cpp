//
//  libipatcher.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <libipatcher/libipatcher.hpp>
#include <curl/curl.h>
#include <cstdlib>
#include <cstring>
#include <functional>

#include <libgeneral/macros.h>

#ifdef HAVE_IMG4TOOL
#include <img4tool/img4tool.hpp>
#endif //HAVE_IMG4TOOL

#ifdef HAVE_LIBOFFSETFINDER64
#include <liboffsetfinder64/ibootpatchfinder64.hpp>
#endif //HAVE_LIBOFFSETFINDER64

extern "C" {
#include <string.h>
#include "jssy.h"
#include <xpwn/libxpwn.h>
#include <xpwn/pwnutil.h>
#include <xpwn/nor_files.h>
#include <include/iBoot32Patcher.h>
#include <include/functions.h>
#include <include/patchers.h>
AbstractFile* createAbstractFileFromComp(AbstractFile* file);
}


#define FIRMWARE_JSON_URL_START "https://firmware-keys.ipsw.me/firmware/"
#define DEVICE_JSON_URL_START   "https://firmware-keys.ipsw.me/device/"

#define bswap32 __builtin_bswap32

#define IMAGE3_MAGIC 'Img3'
#define IBOOT_VERS_STR_OFFSET 0x286
#define IBOOT32_RESET_VECTOR_BYTES bswap32(0x0E0000EA)

using namespace tihmstar;

namespace tihmstar {
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
                T operator->() {return p;}
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
        std::string getRemoteFile(std::string url);
        std::string getRemoteDestination(std::string url);
        std::string getFirmwareJson(std::string device, std::string buildnum);
        std::string getDeviceJson(std::string device);
        std::pair<char*,size_t>patchfile32(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc);

#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
        std::pair<char*,size_t>patchfile64(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc);
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL
    }
}
using namespace std;
using namespace libipatcher;
using namespace helpers;

int iBoot32Patch(char *deciboot, size_t decibootSize, void *bootargs) noexcept;
#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
int iBoot64Patch(char *deciboot, size_t decibootSize, void *bootargs) noexcept;
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL


string libipatcher::version(){
    return {"Libipatcher Version: " VERSION_COMMIT_SHA " - " VERSION_COMMIT_COUNT};
}

bool libipatcher::has64bitSupport(){
#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
    return true;
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL
    return false;
}


string libipatcher::getRemoteFile(std::string url){
    string buf;
    CURL *mc = curl_easy_init();
    assure(mc);
    
    curl_easy_setopt(mc, CURLOPT_URL, url.c_str());
    curl_easy_setopt(mc, CURLOPT_USERAGENT, "libipatcher/" VERSION_COMMIT_COUNT " APIKEY=" VERSION_COMMIT_SHA);
    curl_easy_setopt(mc, CURLOPT_CONNECTTIMEOUT, 30);
    curl_easy_setopt(mc, CURLOPT_FOLLOWLOCATION, 1);
    
    curl_easy_setopt(mc, CURLOPT_WRITEFUNCTION, &helpers::downloadFunction);
    curl_easy_setopt(mc, CURLOPT_WRITEDATA, &buf);
    
    assure(curl_easy_perform(mc) == CURLE_OK);
    long http_code = 0;
    curl_easy_getinfo (mc, CURLINFO_RESPONSE_CODE, &http_code);
    assure(http_code == 200);
    
    curl_easy_cleanup(mc);
    return buf;
}

std::string libipatcher::getRemoteDestination(std::string url){
    char* location = NULL; //don't free me manually
    string buf;
    CURL *mc = curl_easy_init();
    assure(mc);
    
    curl_easy_setopt(mc, CURLOPT_URL, url.c_str());
    curl_easy_setopt(mc, CURLOPT_USERAGENT, "libipatcher/" VERSION_COMMIT_COUNT " APIKEY=" VERSION_COMMIT_SHA);
    curl_easy_setopt(mc, CURLOPT_CONNECTTIMEOUT, 30);
    curl_easy_setopt(mc, CURLOPT_NOBODY, 1);
    
    assure(curl_easy_perform(mc) == CURLE_OK);
    
    assure(curl_easy_getinfo(mc, CURLINFO_REDIRECT_URL, &location) == CURLE_OK);
    buf = location;

    curl_easy_cleanup(mc);
    return buf;
}


string libipatcher::getFirmwareJson(std::string device, std::string buildnum){
    try {
        string url("localhost:8888/firmware/");
        url += device + "/" + buildnum;
        return getRemoteFile(url);
    } catch (...) {
        //retrying with api server
    }
    try {
        string url(FIRMWARE_JSON_URL_START);
        url += device + "/" + buildnum;
        return getRemoteFile(url);
    } catch (...) {
        reterror("failed to get FirmwareJson from Server");
    }
    
    
    //we will never reach this
    return {};
}

string libipatcher::getDeviceJson(std::string device){
    try {
        string url("localhost:8888/device/");
        url += device;
        return getRemoteFile(url);
    } catch (...) {
        //retrying with local server
    }
    try {
        string url(DEVICE_JSON_URL_START);
        url += device;
        return getRemoteFile(url);
    } catch (...) {
        reterror("failed to get DeviceJson from Server");
    }
    
    //we will never reach this
    return {};
}


fw_key libipatcher::getFirmwareKey(std::string device, std::string buildnum, std::string file){
    if (file == "RestoreLogo")
        file = "AppleLogo";
    else if (file == "RestoreRamDisk")
        file = "RestoreRamdisk";
    else if (file == "RestoreDeviceTree")
        file = "DeviceTree";
    else if (file == "RestoreKernelCache")
        file = "Kernelcache";
    
    fw_key rt = {0};
    ptr_smart<jssytok_t*> tokens = NULL;
    long tokensCnt = 0;
    
    string json = getFirmwareJson(device, buildnum);
    
    retassure((tokensCnt = jssy_parse(json.c_str(), json.size(), NULL, 0)) > 0, "failed to parse json");
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(json.c_str(), json.size(), tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);
    
    jssytok_t *keys = jssy_dictGetValueForKey(tokens, "keys");
    assure(keys);
    
    jssytok_t *iv = NULL;
    jssytok_t *key = NULL;
    
    jssytok_t *tmp = keys->subval;
    for (size_t i=0; i<keys->size; tmp=tmp->next, i++) {
        jssytok_t *image = jssy_dictGetValueForKey(tmp, "image");
        assure(image);
        if (strncmp(file.c_str(), image->value, image->size) == 0){
            iv = jssy_dictGetValueForKey(tmp, "iv");
            key = jssy_dictGetValueForKey(tmp, "key");
            break;
        }
    }
    assure(iv && key);
    
    assure(iv->size <= sizeof(rt.iv));
    assure(key->size <= sizeof(rt.key));
    memcpy(rt.iv, iv->value, iv->size);
    memcpy(rt.key, key->value, key->size);
    rt.iv[sizeof(rt.iv)-1] = 0;
    rt.key[sizeof(rt.key)-1] = 0;
    
    ptr_smart<unsigned int *>tkey;
    ptr_smart<unsigned int *>tiv;
    size_t bytes;
    hexToInts(rt.iv, &tiv, &bytes);
    retassure(bytes == 16 || bytes == 0, "IV has bad length. Expected=16 actual=%lld. Got IV=%s",bytes,rt.iv);
    if (!bytes) *rt.iv = '0'; //indicate no key required
    hexToInts(rt.key, &tkey, &bytes);
    retassure(bytes == 32 || bytes == 0, "KEY has bad length. Expected=32 actual=%lld. Got KEY=%s",bytes,rt.key);
    if (!bytes) *rt.key = '0'; //indicate no key required
    return rt;
}

pair<char*,size_t>libipatcher::patchfile32(const char *ibss, size_t ibssSize, const fw_key &keys, string findstr, void *param, function<int(char *, size_t, void*)> patchfunc){
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
    retassure(bytes == 16 || (bytes == 0 && *keys.iv == '0'), "IV has bad length. Expected=16 actual=%lld. Got IV=%s",bytes,keys.iv);
    
    hexToInts(keys.key, &key, &bytes);
    retassure(bytes == 32 || (bytes == 0 && *keys.key == '0'), "KEY has bad length. Expected=32 actual=%lld. Got KEY=%s",bytes,keys.key);
    
    if (*keys.key == '0' && *keys.iv == '0') { //file is not encrypted
        assure(afibss = openAbstractFile2(enc = createAbstractFileFromMemoryFile((void**)&ibss, &ibssSize), 0, 0));
    }else{
        assure(afibss = openAbstractFile2(enc = createAbstractFileFromMemoryFile((void**)&ibss, &ibssSize), key, iv));
    }
    assure(decibssSize = afibss->getLength(afibss));
    assure(decibss = (char*)malloc(decibssSize));
    assure(afibss->read(afibss,decibss, decibssSize) == decibssSize);
    
    //check if decryption was successfull
    assure(*decibss != '3' && memmem(decibss, decibssSize, findstr.c_str() , findstr.size()));
    
    //patch here
    assure(!patchfunc(decibss, decibssSize, param));
    
    //close file
    assure(patched = (char*)malloc(1));
    
    AbstractFile_smart newFile = duplicateAbstractFile2(enc, createAbstractFileFromMemoryFile((void**)&patched, &patchedSize), NULL, NULL, NULL);
    assure(newFile.p);
    assure(newFile.p->write(newFile.p, decibss, decibssSize) == decibssSize);
    newFile.p->close(newFile.p);
    newFile = NULL;
    
    return pair<char*,size_t>{patched,patchedSize};
}

#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
std::pair<char*,size_t> libipatcher::patchfile64(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc){
    char *patched = NULL;

    img4tool::ASN1DERElement im4p(ibss,ibssSize);
    
    img4tool::ASN1DERElement payload = getPayloadFromIM4P(im4p, keys.iv, keys.key);
    
    //check if decryption was successfull
    assure(memmem(payload.payload(), payload.payloadSize(), findstr.c_str() , findstr.size()));

    assure(payload.ownsBuffer());
    
    //patch here
    assure(!patchfunc((char*)payload.payload(), payload.payloadSize(), param));

    img4tool::ASN1DERElement patchedIM4P = img4tool::getEmptyIM4PContainer(im4p[1].getStringValue().c_str(), "Patched by libipatcher");
    
    patchedIM4P = img4tool::appendPayloadToIM4P(patchedIM4P, payload.payload(), payload.payloadSize());
    
    patched = (char*)malloc(patchedIM4P.size());
    memcpy(patched, patchedIM4P.buf(), patchedIM4P.size());
    
    return {patched,patchedIM4P.size()};
}
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL


int iBoot32Patch(char *deciboot, size_t decibootSize, void *bootargs_) noexcept{
    struct iboot_img iboot_in;
    iboot_in.buf = deciboot;
    iboot_in.len = decibootSize;
    int ret = 0;
    const char* iboot_vers_str = ((char*)iboot_in.buf + IBOOT_VERS_STR_OFFSET);
    const char *bootargs = (const char*)bootargs_;

    iboot_in.VERS = atoi(iboot_vers_str);
    if(!iboot_in.VERS) {
        printf("%s: No iBoot version found!\n", __FUNCTION__);
        return -1;
    }
    
    printf("%s: iBoot-%d inputted.\n", __FUNCTION__, iboot_in.VERS);
    
    /* Check to see if the loader has a kernel load routine before trying to apply custom boot args + debug-enabled override. */
    if(has_kernel_load(&iboot_in)) {
        
        if (iboot_in.VERS == 3406) {
            printf("%s: iOS 10 iBoot detected, patching remote command!\n", __FUNCTION__);
            ret = patch_remote_boot(&iboot_in);
            if(!ret) {
                printf("%s: Error doing patch_remote_boot()!\n", __FUNCTION__);
                free(iboot_in.buf);
                return -1;
            }
        }
        
        ret = patch_ticket_check(&iboot_in);

        if(!ret) {
            printf("%s: Error doing patch_ticket_check()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
        
        if (bootargs) {
            ret = patch_boot_args(&iboot_in, bootargs);
            
            if(!ret) {
                printf("%s: Error doing patch_boot_args()!\n", __FUNCTION__);
                free(iboot_in.buf);
                return -1;
            }
            if (strstr(bootargs, "debug")) {
                ret = patch_debug_enabled(&iboot_in);
                
                if(!ret) {
                    printf("%s: Error doing patch_debug_enabled()!\n", __FUNCTION__);
                    free(iboot_in.buf);
                    return -1;
                }
            }
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

#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
int iBoot64Patch(char *deciboot, size_t decibootSize, void *bootargs_) noexcept{
    offsetfinder64::ibootpatchfinder64 *ibpf = NULL;
    cleanup([&]{
        if (ibpf) {
            delete ibpf;
        }
    });
    const char *bootargs = (const char*)bootargs_;
    std::vector<offsetfinder64::patch> patches;

    printf("%s: Staring iBoot64Patch!\n", __FUNCTION__);
    try {
        ibpf = new offsetfinder64::ibootpatchfinder64(deciboot,decibootSize);
    } catch (...) {
        printf("%s: Failed initing ibootpatchfinder64!\n", __FUNCTION__);
        return -(__LINE__);
    }
    printf("%s: Inited ibootpatchfinder64!\n", __FUNCTION__);

    try { //do sigpatches
        auto patch = ibpf->get_sigcheck_patch();
        patches.insert(patches.end(), patch.begin(), patch.end());
    } catch (...) {
        printf("%s: Failed getting sigpatches!\n", __FUNCTION__);
        return -(__LINE__);
    }
    printf("%s: Added sigpatches!\n", __FUNCTION__);

    if (ibpf->has_kernel_load()) {
        printf("%s: has_kernel_load is true!\n", __FUNCTION__);
        
        try { //do debugenabled patch
            auto patch = ibpf->get_debug_enabled_patch();
            patches.insert(patches.end(), patch.begin(), patch.end());
        } catch (...) {
            printf("%s: Failed getting debugenabled patch!\n", __FUNCTION__);
            return -(__LINE__);
        }
        printf("%s: Added debugenabled patch!\n", __FUNCTION__);

        if (bootargs) {
            try { //do bootarg patches
                auto patch = ibpf->get_boot_arg_patch(bootargs);
                patches.insert(patches.end(), patch.begin(), patch.end());
            } catch (...) {
                printf("%s: Failed getting bootarg patch!\n", __FUNCTION__);
                return -(__LINE__);
            }
            printf("%s: Added bootarg patch!\n", __FUNCTION__);
        }
        
        try { //do unlock nvram patch
            auto patch = ibpf->get_unlock_nvram_patch();
            patches.insert(patches.end(), patch.begin(), patch.end());
        } catch (...) {
            printf("%s: Failed getting nlock nvram patch!\n", __FUNCTION__);
            return -(__LINE__);
        }
        printf("%s: Added unlock nvram patch!\n", __FUNCTION__);
                
        try { //do freshnonce patch
            auto patch = ibpf->get_freshnonce_patch();
            patches.insert(patches.end(), patch.begin(), patch.end());
        } catch (...) {
            printf("%s: Failed getting freshnonce patch!\n", __FUNCTION__);
            return -(__LINE__);
        }
        printf("%s: Added freshnonce patch!\n", __FUNCTION__);
        
    }else{
        printf("%s: has_kernel_load is false!\n", __FUNCTION__);
    }

    for (auto p : patches) {
        offsetfinder64::offset_t off = (offsetfinder64::offset_t)(p._location - ibpf->find_base());
        printf("%s: Applying patch=%p : ",__FUNCTION__,(void*)p._location);
        for (int i=0; i<p._patchSize; i++) {
            printf("%02x",((uint8_t*)p._patch)[i]);
        }
        printf("\n");
        memcpy(&deciboot[off], p._patch, p._patchSize);
    }
    
    printf("%s: Patches applied!\n", __FUNCTION__);

    return 0;
}
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL


pair<char*,size_t>libipatcher::patchiBSS(const char *ibss, size_t ibssSize, const fw_key &keys){
#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
    bool is64Bit = false;
    try {
       img4tool::ASN1DERElement im4p(ibss,ibssSize);
       if (img4tool::isIM4P(im4p)) {
           is64Bit = true;
       }
    } catch (...) {
       //
    }
    if (is64Bit) {
        return patchfile64(ibss, ibssSize, keys, "iBoot", NULL, iBoot64Patch);
    }
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL
    return patchfile32(ibss, ibssSize, keys, "iBoot", NULL, iBoot32Patch);
}

pair<char*,size_t>libipatcher::patchiBEC(const char *ibec, size_t ibecSize, const libipatcher::fw_key &keys, std::string bootargs){
#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
    bool is64Bit = false;
    try {
        img4tool::ASN1DERElement im4p(ibec,ibecSize);
        if (img4tool::isIM4P(im4p)) {
            is64Bit = true;
        }
    } catch (...) {
        //
    }
    
    if (is64Bit) {
        return patchfile64(ibec, ibecSize, keys, "iBoot", (void*)(bootargs.size() ? bootargs.c_str() : NULL), iBoot64Patch);
    }
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL
    return patchfile32(ibec, ibecSize, keys, "iBoot", (void*)(bootargs.size() ? bootargs.c_str() : NULL), iBoot32Patch);
}

std::pair<char*,size_t>libipatcher::patchCustom(const char *file, size_t fileSize, const fw_key &keys, std::function<int(char *, size_t, void *)> patchfunc, void *parameter){
#ifdef HAVE_IMG4TOOL
#ifdef HAVE_LIBOFFSETFINDER64
    bool is64Bit = false;
    try {
        img4tool::ASN1DERElement im4p(file,fileSize);
        if (img4tool::isIM4P(im4p)) {
            is64Bit = true;
        }
    } catch (...) {
        //
    }
    
    if (is64Bit) {
        return patchfile64(file, fileSize, keys, "iBoot", parameter, patchfunc);
    }
#endif //HAVE_LIBOFFSETFINDER64
#endif //HAVE_IMG4TOOL
    return patchfile32(file, fileSize, keys, "iBoot", parameter, patchfunc);
}

std::pair<char*,size_t>libipatcher::packIM4PToIMG4(const void *im4p, size_t im4pSize, const void *im4m, size_t im4mSize){
#ifdef HAVE_IMG4TOOL
    char *out = NULL;
    img4tool::ASN1DERElement eim4p{im4p,im4pSize};
    img4tool::ASN1DERElement eim4m{im4m,im4mSize};

    img4tool::ASN1DERElement img4 = img4tool::getEmptyIMG4Container();
    
    img4 = img4tool::appendIM4PToIMG4(img4, eim4p);
    img4 = img4tool::appendIM4MToIMG4(img4, eim4m);
    
    out = (char*)malloc(img4.size());
    memcpy(out, img4.buf(), img4.size());
    return {out,img4.size()};
#else
    reterror("Compiled without img4tool!");
#endif //HAVE_IMG4TOOL
}


pair<char*,size_t>libipatcher::decryptFile3(const char *encfile, size_t encfileSize, const libipatcher::fw_key &keys){
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
    retassure(bytes == 16 || (bytes == 0 && *keys.iv == '0'), "IV has bad length. Expected=16 actual=%lld. Got IV=%s",bytes,keys.iv);
    
    hexToInts(keys.key, &key, &bytes);
    retassure(bytes == 32 || (bytes == 0 && *keys.key == '0'), "KEY has bad length. Expected=32 actual=%lld. Got KEY=%s",bytes,keys.key);

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

pair<char*,size_t>libipatcher::extractKernel(const char *encfile, size_t encfileSize, const libipatcher::fw_key &keys){
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
    retassure(bytes == 16 || (bytes == 0 && *keys.iv == '0'), "IV has bad length. Expected=16 actual=%lld. Got IV=%s",bytes,keys.iv);
    
    hexToInts(keys.key, &key, &bytes);
    retassure(bytes == 32 || (bytes == 0 && *keys.key == '0'), "KEY has bad length. Expected=32 actual=%lld. Got KEY=%s",bytes,keys.key);

    assure(afibss = openAbstractFile2(enc = createAbstractFileFromMemoryFile((void**)&encfile, &encfileSize), key, iv));
    assure(decibssSize = afibss->getLength(afibss));
    assure(decibss = (char*)malloc(decibssSize));
    assure(afibss->read(afibss,decibss, decibssSize) == decibssSize);
    
    assure(*decibss != '3');
    
    return pair<char*,size_t>{decibss,decibssSize};
}

pwnBundle libipatcher::getPwnBundleForDevice(std::string device, std::string buildnum){
    pwnBundle rt;
    ptr_smart<jssytok_t*> tokens = NULL;
    long tokensCnt = 0;
    
    string json = getDeviceJson(device);
    
    assure((tokensCnt = jssy_parse(json.c_str(), json.size(), NULL, 0)) > 0);
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(json.c_str(), json.size(), tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);
    
    assure(tokens->type == JSSY_ARRAY);
    
    jssytok_t *tmp = tokens->subval;
    for (size_t i=0; i<tokens->size; tmp=tmp->next, i++) {
        jssytok_t *deviceName = jssy_dictGetValueForKey(tmp, "identifier");
        assure(deviceName && deviceName->type == JSSY_STRING);
        if (strncmp(deviceName->value, device.c_str(), deviceName->size))
            continue;
        
        jssytok_t *buildID = jssy_dictGetValueForKey(tmp, "buildid");
        
        string curbuildnum = string(buildID->value,buildID->size);
        if (buildnum.size() && curbuildnum != buildnum) {
            continue;
        }
        
        string firmwareUrl = "https://api.ipsw.me/v2.1/";
        firmwareUrl += device;
        firmwareUrl += "/";
        firmwareUrl += curbuildnum;
        firmwareUrl += "/url/dl";
        
        rt.firmwareUrl = getRemoteDestination(firmwareUrl);
        try {
            rt.iBSSKey = getFirmwareKey(device, curbuildnum, "iBSS");
            rt.iBECKey = getFirmwareKey(device, curbuildnum, "iBEC");
        } catch (...) {
            if (!buildnum.size()) {
                //if we are looking for *any* bundle, ignore failure and keep looking
                rt.firmwareUrl.erase();
                rt.iBSSKey = {};
                rt.iBECKey = {};
                continue;
            }else{
                //if we are looking for a specific bundle, this is fatal
                throw;
            }
        }
        return rt;
    }
    
    reterror("Failed to create pwnBundle for device=%s buildnum=%s",device.c_str(),buildnum.size() ? buildnum.c_str() : "any");
    return {};
}
















