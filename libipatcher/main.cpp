//
//  main.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <iostream>
#include <cstdlib>
#include "libipatcher.hpp"

using namespace libipatcher;
using namespace std;

int main(int argc, const char * argv[]) {
    cout << "start" << endl;
    fw_key kk;
    try {
        kk = getFirmwareKey("iPhone4,1", "10B329", "iBSS");
    } catch (libipatcher::exception &e) {
        cout << "Error" << e.code() << " -- " << e.what() << endl;
    }
    
    FILE *f = fopen("iBSS.dfu", "r");
    size_t ibssSize = 0;
    char *ibss = NULL;
    fseek(f, 0, SEEK_END);
    ibssSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    ibss = (char*)malloc(ibssSize);
    fread(ibss, 1, ibssSize, f);
    fclose(f);
    
    
    auto patched = patchiBSS(ibss, ibssSize, kk);
    
    free(ibss);
    cout << "done"<<endl;
    return 0;
}
