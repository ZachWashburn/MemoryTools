#ifndef WINDOWSREBUILD_H
#define WINDOWSREBUILD_H
#pragma once
#include "MemoryTools.h"
#include <stdio.h>



namespace WinRebuilt
{


    /// <summary>
    /// Queries Exception Information Contained Within An Image 
    /// </summary>
    /// <param name="Base"> A Pointer To The Base Address Of The Image </param>
    /// <param name="FunctionTable"> A Pointer That Recieves The Base Address Of The Function Table </param>
    /// <param name="TableSize"> Pointer To ULONG That Recieves The Size Of The Function Table </param>
    void MTCALL RtlCaptureImageExceptionValues(
        _In_  void* pBase,
        _Outptr_ void** pFunctionTable,
        _Outptr_ unsigned long* pTableSize
    );

    /// <summary>
    /// Gets The NT Header For A Module
    /// </summary>
    /// <param name="Base"> Base Address Of Module </param>
    /// <returns> Pointer To NT Header </returns>
    void* MTCALL RtlImageNtHeader(
        _In_ void* Base
    );

};
#endif

