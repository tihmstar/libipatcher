//
//  main.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <iostream>
#include <cstdlib>
#include <libgeneral/macros.h>
#include <libipatcher/libipatcher.hpp>

using namespace tihmstar;
using namespace tihmstar::libipatcher;
using namespace std;

int main(int argc, const char * argv[]) {
    cout << "start" << endl;
    
    auto asd = libipatcher::getPwnBundleForDevice("iPhone10,1", "18A5332f");
    
    if (argc < 2){
        cout << "need buildnum"<<endl;
        return 1;
    }
    
    string bnum = argv[1];
    

    
    fw_key bun;
    try {
        bun = libipatcher::getFirmwareKeyForComponent("iPhone6,2", bnum, "iBEC");
    } catch (tihmstar::exception &e) {
        cout << e.what()<<endl;
    }
    
    cout << "IV=" << bun.iv << endl;
    cout << "Key=" << bun.key << endl;
    
    string fname = string("/tmp/kk/iBEC_")+bnum;
    FILE *f = fopen(fname.c_str(),"rb");
    size_t fs = 0;
    char  *buf = NULL;
    fseek(f, 0, SEEK_END);
    fs = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char*)malloc(fs);
    fread(buf, 1, fs, f);
    fclose(f);
    
    auto dec = libipatcher::patchiBEC(buf, fs, bun);
    {
        FILE *f = fopen((fname+".pwn").c_str(),"wb");
        fwrite(dec.first, 1, dec.second, f);
        fclose(f);
    }
    
    cout << "done " << endl;
    return 0;
}
