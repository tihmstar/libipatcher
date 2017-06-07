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
    
    fw_key getFirmwareKey(const std::string &device, const std::string &buildnum, std::string file);
    std::pair<char*,size_t>decryptFile3(char *fbuf, size_t fbufSize, const fw_key &keys);
    
    std::pair<char*,size_t>patchiBSS(char *ibss, size_t ibssSize, const fw_key &keys);
    std::pair<char*,size_t>patchiBEC(char *ibec, size_t ibecSize, const fw_key &keys);
    
    std::string version();
}

#endif /* libipatcher_hpp */
