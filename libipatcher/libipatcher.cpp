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
#include <string.h>

#include <libgeneral/macros.h>

#ifdef WITH_IBOOT64PATCHER
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder64.hpp>
#endif //WITH_IBOOT64PATCHER

#ifdef WITH_IBOOT32PATCHER
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder32.hpp>
#endif //WITH_IBOOT32PATCHER

#ifdef HAVE_IMG4TOOL
#include <img4tool/img4tool.hpp>
#endif //HAVE_IMG4TOOL

#ifdef HAVE_IMG3TOOL
#include <img3tool/img3tool.hpp>
#endif //HAVE_IMG3TOOL

#ifdef HAVE_LIBFRAGMENTZIP
#include <libfragmentzip/libfragmentzip.h>
#endif //HAVE_LIBFRAGMENTZIP

extern "C" {
#include "jssy.h"
}

#ifdef WITH_REMOTE_KEYS
#define FIRMWARE_JSON_URL_START "https://raw.githubusercontent.com/tihmstar/fwkeydb/master/keys/firmware/"
#define FWKEYDB_LATEST_RELESES "https://api.github.com/repos/tihmstar/fwkeydb/releases/latest"
#define FWKEYDB_KBAGMAP_TEMPLATE_STR "https://github.com/tihmstar/fwkeydb/releases/download/%s/KBAGMap.zip"
#define FWKEYDB_KBAGMAP_FILE "KBAGMap.json"
#endif

#define bswap32 __builtin_bswap32

#define IMAGE3_MAGIC 'Img3'
#define IBOOT_VERS_STR_OFFSET 0x286
#define IBOOT32_RESET_VECTOR_BYTES bswap32(0x0E0000EA)


#ifndef HAVE_MEMMEM
void *memmem(const void *haystack_start, size_t haystack_len, const void *needle_start, size_t needle_len){
    const unsigned char *haystack = (const unsigned char *)haystack_start;
    const unsigned char *needle = (const unsigned char *)needle_start;
    const unsigned char *h = NULL;
    const unsigned char *n = NULL;
    size_t x = needle_len;

    /* The first occurrence of the empty string is deemed to occur at
    the beginning of the string.  */
    if (needle_len == 0) {
        return (void *)haystack_start;
    }

    /* Sanity check, otherwise the loop might search through the whole
        memory.  */
    if (haystack_len < needle_len) {
        return NULL;
    }

    for (; *haystack && haystack_len--; haystack++) {
        x = needle_len;
        n = needle;
        h = haystack;

        if (haystack_len < needle_len)
            break;

        if ((*haystack != *needle) || (*haystack + needle_len != *needle + needle_len))
            continue;

        for (; x; h++, n++) {
            x--;

            if (*h != *n)
                break;

            if (x == 0)
                return (void *)haystack;
        }
    }
    return NULL;
}
#endif


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
        }
        std::string getRemoteFile(std::string url);
        std::string getRemoteDestination(std::string url);
        std::string getFirmwareJson(std::string device, std::string buildnum, uint32_t cpid = 0);
        std::string getDeviceJson(std::string device);
#ifdef HAVE_LIBFRAGMENTZIP
        std::string getFirmwareJsonFromZip(std::string device, std::string buildnum, std::string zipURL, uint32_t cpid = 0);
        std::string getDeviceJsonFromZip(std::string device, std::string zipURL);
#endif //HAVE_LIBFRAGMENTZIP
    
#ifdef WITH_IBOOT32PATCHER
        std::pair<char*,size_t>patchfile32(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc);
#endif
#ifdef WITH_IBOOT64PATCHER
        std::pair<char*,size_t>patchfile64(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc);
#endif //WITH_IBOOT64PATCHER
    }
}

static inline void hexToInts(const char* hex, unsigned int** buffer, size_t* bytes) {
    *bytes = strlen(hex) / 2;
    *buffer = (unsigned int*) malloc((*bytes) * sizeof(int));
    size_t i;
    for(i = 0; i < *bytes; i++) {
        sscanf(hex, "%2x", &((*buffer)[i]));
        hex += 2;
    }
}

using namespace std;
using namespace libipatcher;
using namespace helpers;

#ifdef WITH_IBOOT32PATCHER
int iBoot32Patch(char *deciboot, size_t decibootSize, void *bootargs) noexcept;
#endif

#ifdef WITH_IBOOT64PATCHER
int iBoot64Patch(char *deciboot, size_t decibootSize, void *bootargs) noexcept;
#endif //WITH_IBOOT64PATCHER


const char *libipatcher::version(){
    return VERSION_STRING;
}

bool libipatcher::has32bitSupport(){
#ifdef WITH_IBOOT32PATCHER
    return true;
#endif //WITH_IBOOT32PATCHER
    return false;
}

bool libipatcher::has64bitSupport(){
#ifdef WITH_IBOOT64PATCHER
    return true;
#endif //WITH_IBOOT64PATCHER
    return false;
}

string libipatcher::getRemoteFile(std::string url){
    CURL *mc = NULL;
    cleanup([&]{
        safeFreeCustom(mc, curl_easy_cleanup);
    });
    string buf;
    assure(mc = curl_easy_init());
    
    curl_easy_setopt(mc, CURLOPT_URL, url.c_str());
    curl_easy_setopt(mc, CURLOPT_USERAGENT, "libipatcher/" VERSION_COMMIT_COUNT " APIKEY=" VERSION_COMMIT_SHA);
    curl_easy_setopt(mc, CURLOPT_CONNECTTIMEOUT, 30);
    curl_easy_setopt(mc, CURLOPT_FOLLOWLOCATION, 1);
    
    curl_easy_setopt(mc, CURLOPT_WRITEFUNCTION, &helpers::downloadFunction);
    curl_easy_setopt(mc, CURLOPT_WRITEDATA, &buf);
    
    assure(curl_easy_perform(mc) == CURLE_OK);
    {
        long http_code = 0;
        curl_easy_getinfo (mc, CURLINFO_RESPONSE_CODE, &http_code);
        assure(http_code == 200);
    }
    return buf;
}

std::string libipatcher::getRemoteDestination(std::string url){
    char* location = NULL; //don't free me manually
    string buf;
    uint64_t curlcode = 0;
    CURL *mc = curl_easy_init();
    assure(mc);
    
    curl_easy_setopt(mc, CURLOPT_URL, url.c_str());
    curl_easy_setopt(mc, CURLOPT_USERAGENT, "libipatcher/" VERSION_COMMIT_COUNT " APIKEY=" VERSION_COMMIT_SHA);
    curl_easy_setopt(mc, CURLOPT_CONNECTTIMEOUT, 30);
    curl_easy_setopt(mc, CURLOPT_NOBODY, 1);
    
    assure(curl_easy_perform(mc) == CURLE_OK);
    
    curl_easy_getinfo(mc, CURLINFO_RESPONSE_CODE, &curlcode);
    assure(curlcode < 400);
    
    assure(curl_easy_getinfo(mc, CURLINFO_REDIRECT_URL, &location) == CURLE_OK);
    buf = location;

    curl_easy_cleanup(mc);
    return buf;
}


string libipatcher::getFirmwareJson(std::string device, std::string buildnum, uint32_t cpid){
    std::string cpid_str;
    if (cpid) {
        char buf[0x100] = {};
        snprintf(buf, sizeof(buf), "0x%x/",cpid);
        cpid_str = buf;
    }
    
    {
        //try localhost
        string url("http://localhost:8888/firmware/");
        url += device + "/";
        if (cpid_str.size()) {
            try {return getRemoteFile(url + cpid_str + buildnum);} catch (...) {}
        }
        try {return getRemoteFile(url + buildnum);} catch (...) {}
    }

#ifdef FIRMWARE_JSON_URL_START
    {
        //retrying with api server
        string url(FIRMWARE_JSON_URL_START);
        url += device + "/";
                
        if (cpid_str.size()) {
            try {return getRemoteFile(url + cpid_str + buildnum);} catch (...) {}
        }
        try {return getRemoteFile(url + buildnum);} catch (...) {}
    }
#endif
    
    reterror("failed to get FirmwareJson from Server");
}

string libipatcher::getDeviceJson(std::string device){
    try {
        string url("localhost:8888/device/");
        url += device;
        return getRemoteFile(url);
    } catch (...) {
        //retrying with local server
    }
    
#ifdef DEVICE_JSON_URL_START
    try {
        string url(DEVICE_JSON_URL_START);
        url += device;
        return getRemoteFile(url);
    } catch (...) {
        //fall though and fail
    }
#endif
    
    reterror("failed to get DeviceJson from Server");
}

#ifdef HAVE_LIBFRAGMENTZIP
std::string libipatcher::getFirmwareJsonFromZip(std::string device, std::string buildnum, std::string zipURL, uint32_t cpid){
    fragmentzip_t *fz = NULL;
    char *outBuf = NULL;
    cleanup([&]{
        safeFree(outBuf);
        safeFreeCustom(fz, fragmentzip_close);
    });
    size_t outBufSize = 0;
    
    std::string cpid_str;
    if (cpid) {
        char buf[0x100] = {};
        snprintf(buf, sizeof(buf), "0x%x/",cpid);
        cpid_str = buf;
    }

    retassure(fz = fragmentzip_open(zipURL.c_str()), "Failed to open zipURL '%s'",zipURL.c_str());
        
    {
        int err = 0;
        std::string filePath = "firmware/" + device + "/";
        if ((err = fragmentzip_download_to_memory(fz, (filePath + cpid_str + buildnum).c_str(), &outBuf, &outBufSize, NULL))) {
            err = fragmentzip_download_to_memory(fz, (filePath + buildnum).c_str(), &outBuf, &outBufSize, NULL);
        }
        retassure(!err, "Failed to get firmware json from zip with err=%d",err);
    }
    
    return {outBuf,outBuf+outBufSize};
}

string libipatcher::getDeviceJsonFromZip(std::string device, std::string zipURL){
    fragmentzip_t *fz = NULL;
    char *outBuf = NULL;
    cleanup([&]{
        safeFree(outBuf);
        safeFreeCustom(fz, fragmentzip_close);
    });
    size_t outBufSize = 0;
    
    retassure(fz = fragmentzip_open(zipURL.c_str()), "Failed to open zipURL '%s'",zipURL.c_str());
    
    {
        int err = 0;
        std::string filePath = "firmware/" + device;
        retassure(!(err = fragmentzip_download_to_memory(fz, filePath.c_str(), &outBuf, &outBufSize, NULL)), "Failed to get firmware json from zip with err=%d",err);
    }

    return {outBuf,outBuf+outBufSize};
}

#endif //HAVE_LIBFRAGMENTZIP


fw_key getFirmwareKeyForComparator(std::string device, std::string buildnum, std::function<bool(const jssytok_t *e, std::string apiversion)> comparator, uint32_t cpid, std::string zipURL){
    jssytok_t* tokens = NULL;
    unsigned int * tkey = NULL;
    unsigned int * tiv = NULL;
    cleanup([&]{
        safeFree(tiv);
        safeFree(tkey);
        safeFree(tokens);
    });
    fw_key rt = {0};
    long tokensCnt = 0;
    std::string apiversion;

#ifdef HAVE_LIBFRAGMENTZIP
    string json = (zipURL.size()) ? getFirmwareJsonFromZip(device, buildnum, zipURL, cpid) : getFirmwareJson(device, buildnum, cpid);
#else
    string json = getFirmwareJson(device, buildnum, cpid);
#endif //HAVE_LIBFRAGMENTZIP
    
    retassure((tokensCnt = jssy_parse(json.c_str(), json.size(), NULL, 0)) > 0, "failed to parse json");
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(json.c_str(), json.size(), tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);
    
    jssytok_t *keys = jssy_dictGetValueForKey(tokens, "keys");
    assure(keys);
    
    {
        jssytok_t *apivers = jssy_dictGetValueForKey(tokens, "version");
        if (apivers){
            retassure(apivers->type == JSSY_STRING, "Got version, but not string!");
            apiversion = {apivers->value,apivers->value+apivers->size};
        }
    }
    
    jssytok_t *iv = NULL;
    jssytok_t *key = NULL;
    jssytok_t *path = NULL;

    jssytok_t *tmp = keys->subval;
    for (size_t i=0; i<keys->size; tmp=tmp->next, i++) {
        jssytok_t *tmpV = (tmp->type == JSSY_DICT_KEY) ? tmp->subval : tmp;
        if (comparator(tmpV, apiversion)){
            iv = jssy_dictGetValueForKey(tmpV, "iv");
            key = jssy_dictGetValueForKey(tmpV, "key");
            path = jssy_dictGetValueForKey(tmpV, "filename");
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

    if (path) rt.pathname = {path->value,path->value+path->size};
    
    {
        size_t bytes;
        hexToInts(rt.iv, &tiv, &bytes);
        retassure(bytes == 16 || bytes == 0, "IV has bad length. Expected=16 actual=%lld. Got IV=%s",bytes,rt.iv);
        if (!bytes) memset(rt.iv, 0, sizeof(rt.iv)); //indicate no key required
        hexToInts(rt.key, &tkey, &bytes);
        retassure(bytes == 32  || bytes == 16 || bytes == 0, "KEY has bad length. Expected 32 or 16 actual=%lld. Got KEY=%s",bytes,rt.key);
        if (!bytes) memset(rt.key, 0, sizeof(rt.key)); //indicate no key required
    }
    return rt;
}

static std::string getLatestfwkeydbRelease(){
    static std::string ret;
    if (!ret.size()){
#ifndef FWKEYDB_LATEST_RELESES
    reterror("Compiled without getLatestfwkeydbRelease support");
#endif
        jssytok_t* tokens = NULL;
        cleanup([&]{
            safeFree(tokens);
        });
        long tokensCnt = 0;

        auto json = getRemoteFile(FWKEYDB_LATEST_RELESES);

        retassure((tokensCnt = jssy_parse(json.c_str(), json.size(), NULL, 0)) > 0, "failed to parse json");
        assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
        assure(jssy_parse(json.c_str(), json.size(), tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);
        
        jssytok_t *tagname = jssy_dictGetValueForKey(tokens, "tag_name");
        assure(tagname);
        assure(tagname->type == JSSY_STRING && tagname->size > 0);
        ret = {tagname->value, tagname->value+tagname->size};
    }
        
    return ret;
}

fw_key libipatcher::getFirmwareKeyForKBAG(std::string kbag){
#ifndef HAVE_LIBFRAGMENTZIP
    reterror("compiled without libfragmentzip");
#else
    int err = 0;
    fragmentzip_t *fz = NULL;
    char *outBuf = NULL;
    jssytok_t* tokens = NULL;
    cleanup([&]{
        safeFree(tokens);
        safeFree(outBuf);
        safeFreeCustom(fz, fragmentzip_close);
    });
    size_t outBufSize = 0;
    long tokensCnt = 0;
    jssytok_t *tgt = NULL;
    char kbagmapurl[sizeof(FWKEYDB_KBAGMAP_TEMPLATE_STR) + 20] = {};
    
    auto lastFWKeyDBRelease = getLatestfwkeydbRelease();
    
    retassure(snprintf(kbagmapurl, sizeof(kbagmapurl), FWKEYDB_KBAGMAP_TEMPLATE_STR,lastFWKeyDBRelease.c_str()) < sizeof(kbagmapurl), "kbagmapurl buf too small");
    
    retassure(fz = fragmentzip_open(kbagmapurl), "Failed to open kbagmapurl '%s'",kbagmapurl);
    retassure(!(err = fragmentzip_download_to_memory(fz, FWKEYDB_KBAGMAP_FILE, &outBuf, &outBufSize, NULL)), "Failed to get %s from zip with err=%d",FWKEYDB_KBAGMAP_FILE,err);

    retassure((tokensCnt = jssy_parse(outBuf, outBufSize, NULL, 0)) > 0, "failed to parse json");
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(outBuf, outBufSize, tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);

    retassure(tgt = jssy_dictGetValueForKey(tokens, kbag.c_str()), "Failed to find IV/Key for KBAG '%s'",kbag.c_str());
    
    {
        fw_key rt = {};
        jssytok_t *iv = NULL;
        jssytok_t *key = NULL;

        iv = jssy_dictGetValueForKey(tgt, "iv");
        key = jssy_dictGetValueForKey(tgt, "key");

        assure(iv && key);
        
        assure(iv->size <= sizeof(rt.iv));
        assure(key->size <= sizeof(rt.key));
        memcpy(rt.iv, iv->value, iv->size);
        memcpy(rt.key, key->value, key->size);
        rt.iv[sizeof(rt.iv)-1] = 0;
        rt.key[sizeof(rt.key)-1] = 0;
        
        return rt;
    }
#endif
}

fw_key libipatcher::getFirmwareKeyForComponent(std::string device, std::string buildnum, std::string component, uint32_t cpid, std::string zipURL){
    if (component == "RestoreLogo")
        component = "AppleLogo";
    else if (component == "RestoreRamDisk")
        component = "RestoreRamdisk";
    else if (component == "RestoreDeviceTree")
        component = "DeviceTree";
    else if (component == "RestoreKernelCache")
        component = "Kernelcache";
    
    return getFirmwareKeyForComparator(device, buildnum, [&component](const jssytok_t *e, std::string apiversion)->bool{
        if (apiversion == "1.0") {
            jssytok_t *names = jssy_dictGetValueForKey(e, "names");
            jssytok_t *name = names->subval;
            for (size_t i=0; i<names->size; name=name->next, i++) {
                if (strncmp(component.c_str(), name->value, name->size) == 0) {
                    return true;
                }
            }
            return false;
        }else{
            jssytok_t *image = jssy_dictGetValueForKey(e, "image");
            assure(image);
            return strncmp(component.c_str(), image->value, image->size) == 0;
        }
    }, cpid, zipURL);
}

fw_key libipatcher::getFirmwareKeyForPath(std::string device, std::string buildnum, std::string path, uint32_t cpid, std::string zipURL){
    return getFirmwareKeyForComparator(device, buildnum, [&path](const jssytok_t *e, std::string apiversion){
        jssytok_t *filename = jssy_dictGetValueForKey(e, "filename");
        assure(filename);
        return strncmp(path.c_str(), filename->value, filename->size) == 0;
    }, cpid, zipURL);
}

#ifdef WITH_IBOOT32PATCHER
pair<char*,size_t>libipatcher::patchfile32(const char *ibss, size_t ibssSize, const fw_key &keys, string findstr, void *param, function<int(char *, size_t, void*)> patchfunc){
    char *patched = NULL;
    const char *key_iv = NULL;
    const char *key_key = NULL;
    const char *usedCompression = NULL;

    //if one single byte isn't \x00 then set the iv
    for (int i=0; i<sizeof(keys.iv); i++) {
        if (keys.iv[i]){
            key_iv = keys.iv;
            break;
        }
    }

    //if one single byte isn't \x00 then set the key
    for (int i=0; i<sizeof(keys.key); i++) {
        if (keys.key[i]){
            key_key = keys.key;
            break;
        }
    }
    
    auto payload = img3tool::getPayloadFromIMG3(ibss, ibssSize, key_iv, key_key, &usedCompression);
    
    if (findstr.size()){
        //check if decryption was successfull
        retassure(memmem(payload.data(), payload.size(), findstr.c_str() , findstr.size()), "Failed to find '%s'. Assuming decryption failed!",findstr.c_str());
    }
    //patch here
    if (patchfunc) {
        assure(!patchfunc((char*)payload.data(), payload.size(), param));
    }

    auto newpayload = img3tool::replaceDATAinIMG3({ibss,ibssSize}, payload, usedCompression);
    newpayload = img3tool::removeTagFromIMG3(newpayload.data(), newpayload.size(), 'KBAG');

    patched = (char*)malloc(newpayload.size());
    memcpy(patched, newpayload.data(), newpayload.size());
    
    return {patched,newpayload.size()};
}
#endif

#ifdef WITH_IBOOT64PATCHER
std::pair<char*,size_t> libipatcher::patchfile64(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc){
    char *patched = NULL;
    const char *key_iv = NULL;
    const char *key_key = NULL;
    const char *usedCompression = NULL;
    img4tool::ASN1DERElement hypervisor{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};
    
    //if one single byte isn't \x00 then set the iv
    for (int i=0; i<sizeof(key_iv); i++) {
        if (keys.iv[i]){
            key_iv = keys.iv;
            break;
        }
    }

    //if one single byte isn't \x00 then set the key
    for (int i=0; i<sizeof(key_key); i++) {
        if (keys.key[i]){
            key_key = keys.key;
            break;
        }
    }
    
    img4tool::ASN1DERElement im4p(ibss,ibssSize);
    
    img4tool::ASN1DERElement payload = getPayloadFromIM4P(im4p, key_iv, key_key, &usedCompression, &hypervisor);
    
    if (findstr.size()){
        //check if decryption was successfull
        retassure(memmem(payload.payload(), payload.payloadSize(), findstr.c_str() , findstr.size()), "Failed to find '%s'. Assuming decryption failed!",findstr.c_str());
    }

    assure(payload.ownsBuffer());
    
    //patch here
    if (patchfunc) {
        assure(!patchfunc((char*)payload.payload(), payload.payloadSize(), param));
    }
    
    img4tool::ASN1DERElement patchedIM4P = img4tool::getEmptyIM4PContainer(im4p[1].getStringValue().c_str(), im4p[2].getStringValue().c_str());
    
    {
#warning BUG WORKAROUND recompressing images with bvx2 makes them not boot for some reason
        if (usedCompression && strcmp(usedCompression, "bvx2") == 0) {
            warning("BUG WORKAROUND recompressing images with bvx2 makes them not boot for some reason. Skipping compression");
            usedCompression = NULL;
        }
    }
    
    patchedIM4P = img4tool::appendPayloadToIM4P(patchedIM4P, payload.payload(), payload.payloadSize(), usedCompression, hypervisor.payload(), hypervisor.payloadSize());
    
    patched = (char*)malloc(patchedIM4P.size());
    memcpy(patched, patchedIM4P.buf(), patchedIM4P.size());
    
    return {patched,patchedIM4P.size()};
}
#endif //WITH_IBOOT64PATCHER


#ifdef WITH_IBOOT32PATCHER
int iBoot32Patch(char *deciboot, size_t decibootSize, void *bootargs_) noexcept{
    patchfinder::ibootpatchfinder32 *ibpf = NULL;
    cleanup([&]{
        if (ibpf) {
            delete ibpf;
        }
    });
    const char *bootargs = (const char*)bootargs_;
    std::vector<patchfinder::patch> patches;

    printf("%s: Staring iBoot32Patch!\n", __FUNCTION__);
    try {
        ibpf = patchfinder::ibootpatchfinder32::make_ibootpatchfinder32(deciboot,decibootSize);
    } catch (...) {
        printf("%s: Failed initing ibootpatchfinder32!\n", __FUNCTION__);
        return -(__LINE__);
    }
    printf("%s: Inited ibootpatchfinder32!\n", __FUNCTION__);

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
    }else{
        printf("%s: has_kernel_load is false!\n", __FUNCTION__);
    }

    for (auto p : patches) {
        uint64_t off = (uint64_t)(p._location - ibpf->find_base());
        printf("%s: Applying patch=%p : ",__FUNCTION__,(void*)p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
        memcpy(&deciboot[off], p.getPatch(), p.getPatchSize());
    }
    
    printf("%s: Patches applied!\n", __FUNCTION__);

    return 0;
}
#endif

#ifdef WITH_IBOOT64PATCHER
int iBoot64Patch(char *deciboot, size_t decibootSize, void *bootargs_) noexcept{
    patchfinder::ibootpatchfinder64 *ibpf = NULL;
    cleanup([&]{
        if (ibpf) {
            delete ibpf;
        }
    });
    const char *bootargs = (const char*)bootargs_;
    std::vector<patchfinder::patch> patches;

    printf("%s: Staring iBoot64Patch!\n", __FUNCTION__);
    try {
        ibpf = patchfinder::ibootpatchfinder64::make_ibootpatchfinder64(deciboot,decibootSize);
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
        uint64_t off = (uint64_t)(p._location - ibpf->find_base());
        printf("%s: Applying patch=%p : ",__FUNCTION__,(void*)p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
        memcpy(&deciboot[off], p.getPatch(), p.getPatchSize());
    }
    
    printf("%s: Patches applied!\n", __FUNCTION__);

    return 0;
}
#endif //WITH_IBOOT64PATCHER

pair<char*,size_t>libipatcher::patchiBSS(const char *ibss, size_t ibssSize, const fw_key &keys){
#ifdef WITH_IBOOT64PATCHER
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
#endif //WITH_IBOOT64PATCHER

#ifdef WITH_IBOOT32PATCHER
    return patchfile32(ibss, ibssSize, keys, "iBoot", NULL, iBoot32Patch);
#endif
    reterror("No compatible backend available!");
}

pair<char*,size_t>libipatcher::patchiBEC(const char *ibec, size_t ibecSize, const libipatcher::fw_key &keys, std::string bootargs){
#ifdef WITH_IBOOT64PATCHER
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
#endif //WITH_IBOOT64PATCHER

#ifdef WITH_IBOOT32PATCHER
    return patchfile32(ibec, ibecSize, keys, "iBoot", (void*)(bootargs.size() ? bootargs.c_str() : NULL), iBoot32Patch);
#endif
    reterror("No compatible backend available!");
}

std::pair<char*,size_t>libipatcher::patchCustom(const char *file, size_t fileSize, const fw_key &keys, std::function<int(char *, size_t, void *)> patchfunc, void *parameter, std::string findDecStr){
#ifdef WITH_IBOOT64PATCHER
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
        return patchfile64(file, fileSize, keys, findDecStr, parameter, patchfunc);
    }
#endif //WITH_IBOOT64PATCHER
    
#ifdef WITH_IBOOT32PATCHER
    return patchfile32(file, fileSize, keys, findDecStr, parameter, patchfunc);
#endif
    reterror("No compatible backend available!");
}

std::pair<char*,size_t> libipatcher::decryptFile(const char *fbuf, size_t fbufSize, const fw_key &keys){
    return patchCustom(fbuf, fbufSize, keys, NULL, NULL, {});
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

pwnBundle libipatcher::getPwnBundleForDevice(std::string device, std::string buildnum, uint32_t cpid, std::string zipURL){
    jssytok_t* tokens = NULL;
    cleanup([&]{
        safeFree(tokens);
    });
    long tokensCnt = 0;

    auto getKeys = [cpid,zipURL](std::string device, std::string curbuildnum)->pwnBundle{
        pwnBundle rt;
        rt.iBSSKey = getFirmwareKeyForComponent(device, curbuildnum, "iBSS", cpid, zipURL);
        rt.iBECKey = getFirmwareKeyForComponent(device, curbuildnum, "iBEC", cpid, zipURL);
        return rt;
    };
    
    if (buildnum.size()) { //if buildnum is given, try to get keys once. error is fatal.
        return getKeys(device,buildnum);
    }
    
#ifdef HAVE_LIBFRAGMENTZIP
    string json = (zipURL.size()) ? getDeviceJsonFromZip(device, zipURL) : getDeviceJson(device);
#else
    string json = getDeviceJson(device);
#endif //HAVE_LIBFRAGMENTZIP

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
        
        //if we are interested in *any* bundle, ignore errors until we run out of builds.
        try {
            return getKeys(device,curbuildnum);
        } catch (...) {
            continue;
        }
    }
    
    reterror("Failed to create pwnBundle for device=%s buildnum=%s",device.c_str(),buildnum.size() ? buildnum.c_str() : "any");
    return {};
}
















