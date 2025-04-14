// nsfw.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "nsfw.h"


// This is an example of an exported variable
NSFW_API int nnsfw=0;

// This is an example of an exported function.
NSFW_API int fnnsfw(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
Cnsfw::Cnsfw()
{
    return;
}
