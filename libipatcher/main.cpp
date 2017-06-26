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
    
    
    auto bun = libipatcher::getAnyPwnBundleForDevice("iPhone4,1");
    
    
    cout << "done "<<endl;
    return 0;
}
