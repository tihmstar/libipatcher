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

namespace tihmstar {
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
    
        fw_key getFirmwareKey(std::string device, std::string buildnum, std::string file);
        pwnBundle getPwnBundleForDevice(std::string device, std::string buildnum = "");
    
        std::pair<char*,size_t>decryptFile3(const char *fbuf, size_t fbufSize, const fw_key &keys);
        std::pair<char*,size_t>extractKernel(const char *fbuf, size_t fbufSize, const fw_key &keys);
        std::pair<char*,size_t>patchiBSS(const char *ibss, size_t ibssSize, const fw_key &keys);
        std::pair<char*,size_t>patchiBEC(const char *ibec, size_t ibecSize, const fw_key &keys, std::string bootargs = "");

        std::pair<char*,size_t>packIM4PToIMG4(const void *im4p, size_t im4pSize, const void *im4m, size_t im4mSize);
    
        std::string version();
        bool has64bitSupport();
    }
}


#endif /* libipatcher_hpp */
