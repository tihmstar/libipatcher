//
//  main.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <iostream>
#include "libipatcher.hpp"

using namespace libipatcher;
using namespace std;

int main(int argc, const char * argv[]) {
    
    fw_key kk;
    try {
        kk = getFirmwareKey("iPad2,2", "11B554a", "iBEC");
    } catch (libipatcher::exception &e) {
        cout << e.code() << " -- " << e.what() << endl;
    }
    
    
    cout << "done"<<endl;
    return 0;
}
