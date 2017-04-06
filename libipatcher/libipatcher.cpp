//
//  libipatcher.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include "all_libipatcher.h"
#include "libipatcher.hpp"
#include <curl/curl.h>
#include <cstdlib>
#include <cstring>
#include <functional>
extern "C" {
#include "jssy.h"
}


#define FIRMWARE_JSON_URL_START "https://firmware-keys.ipsw.me/firmware/"
#define reterror(err) throw exception(__LINE__,err)
#define assure(cond) if ((cond) == 0) throw exception(__LINE__)

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
        public:
            T p;
            ptr_smart(T pp, std::function<void(T)> ptr_free) : p(pp) {static_assert(std::is_pointer<T>(), "error: this is for pointers only\n"); _ptr_free = ptr_free;}
            ptr_smart(T pp) : p(pp){}
            ptr_smart() : p(NULL) {}
            T operator=(T pp) {return p = pp;}
            T *operator&(){return &p;}
            ~ptr_smart(){if (p) (_ptr_free) ? _ptr_free(p) : free((void*)p);}
        };
    }
    std::string getFirmwareJson(const std::string &device, const std::string &buildnum);
}
using namespace std;
using namespace libipatcher;
using helpers::ptr_smart;

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


fw_key libipatcher::getFirmwareKey(const std::string &device, const std::string &buildnum, const std::string &file){
    fw_key rt;
    ptr_smart<jssytok_t*> tokens = NULL;
    long tokensCnt = 0;
    
    string json = getFirmwareJson(device, buildnum);
    
    assure((tokensCnt = jssy_parse(json.c_str(), json.size(), NULL, 0)) > 0);
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(json.c_str(), json.size(), tokens.p, tokensCnt * sizeof(jssytok_t)) == tokensCnt);
    
    jssytok_t *keys = jssy_dictGetValueForKey(tokens.p, "keys");
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
    
    assure(!helpers::parseHex(iv->value, iv->size, (unsigned char*)&rt.iv, sizeof(rt.iv)));
    assure(!helpers::parseHex(key->value, key->size, (unsigned char*)&rt.key, sizeof(rt.key)));
    
    return rt;
}





















