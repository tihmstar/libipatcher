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
    fw_key kibss;
    fw_key kibec;
    fw_key klogo;
    char *ibss = NULL;
    char *ibec = NULL;
    char *logo = NULL;
    size_t ibssSize = 0;
    size_t ibecSize = 0;
    size_t logoSize = 0;
    
    try {
        kibss = getFirmwareKey("iPhone4,1", "10B329", "iBSS");
    } catch (libipatcher::exception &e) {
        cout << "Error" << e.code() << " -- " << e.what() << endl;
    }
    try {
        kibec = getFirmwareKey("iPhone4,1", "10B329", "iBEC");
    } catch (libipatcher::exception &e) {
        cout << "Error" << e.code() << " -- " << e.what() << endl;
    }
    try {
        klogo = getFirmwareKey("iPhone4,1", "10B329", "AppleLogo");
    } catch (libipatcher::exception &e) {
        cout << "Error" << e.code() << " -- " << e.what() << endl;
    }
    
    {
        FILE *f = fopen("iBSS.dfu", "r");
        fseek(f, 0, SEEK_END);
        ibssSize = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        ibss = (char*)malloc(ibssSize);
        fread(ibss, 1, ibssSize, f);
        fclose(f);
    }
    {
        FILE *f = fopen("iBEC.dfu", "r");
        fseek(f, 0, SEEK_END);
        ibecSize = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        ibec = (char*)malloc(ibecSize);
        fread(ibec, 1, ibecSize, f);
        fclose(f);
    }
    {
        FILE *f = fopen("logo.img3", "r");
        fseek(f, 0, SEEK_END);
        logoSize = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        logo = (char*)malloc(logoSize);
        fread(logo, 1, logoSize, f);
        fclose(f);
    }
    
    
    auto patchediBSS = patchiBSS(ibss, ibssSize, kibss);
    auto patchediBEC = patchiBEC(ibec, ibecSize, kibec);
    auto patchedlogo = decryptFile3(logo, logoSize, klogo);
    
    free(ibss);
    free(ibec);
    free(logo);
    cout << "done"<<endl;
    return 0;
}
