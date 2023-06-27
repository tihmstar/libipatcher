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
#include <functional>
#include <iostream>

namespace tihmstar {
    namespace libipatcher {
        struct fw_key{
            char iv[32 + 1];
            char key[64 + 1];
            std::string pathname;
        };
        struct pwnBundle{
            std::string firmwareUrl;
            fw_key iBSSKey;
            fw_key iBECKey;
        };
    
        fw_key getFirmwareKeyForComponent(std::string device, std::string buildnum, std::string component, uint64_t cpid = 0, std::string zipURL = "");
        fw_key getFirmwareKeyForPath(std::string device, std::string buildnum, std::string path, uint64_t cpid = 0, std::string zipURL = "");
        pwnBundle getPwnBundleForDevice(std::string device, std::string buildnum = "", uint64_t cpid = 0, std::string zipURL = "");
    
        std::pair<char*,size_t>decryptFile(const char *fbuf, size_t fbufSize, const fw_key &keys);
        std::pair<char*,size_t>extractKernel(const char *fbuf, size_t fbufSize, const fw_key &keys);
        std::pair<char*,size_t>patchiBSS(const char *ibss, size_t ibssSize, const fw_key &keys);
        std::pair<char*,size_t>patchiBEC(const char *ibec, size_t ibecSize, const fw_key &keys, std::string bootargs = "");
    
        std::pair<char*,size_t>patchCustom(const char *file, size_t fileSize, const fw_key &keys, std::function<int(char *, size_t, void *)> patchfunc, void *parameter, std::string findDecStr = "iBoot");
    
        std::pair<char*,size_t>packIM4PToIMG4(const void *im4p, size_t im4pSize, const void *im4m, size_t im4mSize);
    
        const char *version();
        bool has32bitSupport();
        bool has64bitSupport();
    }
}


#endif /* libipatcher_hpp */
