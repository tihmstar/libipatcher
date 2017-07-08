//
//  main.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <iostream>
#include <cstdlib>
#include <libipatcher/libipatcher.hpp>

using namespace libipatcher;
using namespace std;

int main(int argc, const char * argv[]) {
    cout << "start" << endl;
    
    try {
        auto bun = libipatcher::getFirmwareKey("iPhone4,1", "9A406", "RestoreRamdisk");
    } catch (libipatcher::exception &e) {
        cout << e.what()<<endl;
    }
    
    cout << "done "<<endl;
    return 0;
}
