//
//  libipatcher.hpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#ifndef libipatcher_hpp
#define libipatcher_hpp

#include <string>
#include <exception>

namespace libipatcher {
    struct fw_key{
        char iv[32 + 1];
        char key[64 + 1];
    };
    struct pwnBundle{
        std::string firmwareUrl;
        fw_key iBSSKey;
        fw_key iBECKey;
    };
    class exception : public std::exception{
        std::string _err;
        int _code;
    public:
        exception(int code, const std::string &err) : _err(err), _code(code) {};
        exception(const std::string &err) : _err(err), _code(0) {};
        exception(int code) : _code(code) {};
        const char *what(){return _err.c_str();}
        int code(){return _code;}
    };
    
    fw_key getFirmwareKey(std::string device, std::string buildnum, std::string file);
    pwnBundle getAnyPwnBundleForDevice(std::string device);
    
    std::pair<char*,size_t>decryptFile3(const char *fbuf, size_t fbufSize, const fw_key &keys);
    std::pair<char*,size_t>patchiBSS(const char *ibss, size_t ibssSize, const fw_key &keys);
    std::pair<char*,size_t>patchiBEC(const char *ibec, size_t ibecSize, const fw_key &keys, std::string bootargs = "");
    
    std::string version();
}

#endif /* libipatcher_hpp */
