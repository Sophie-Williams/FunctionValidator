#include <Windows.h>
#include <iostream>

#include "../Validator/Validator.h"
#ifdef _DEBUG
#pragma comment( lib, "../Debug/Validator.lib" )
#else
#pragma comment( lib, "../Release/Validator.lib" )
#endif
using namespace FunctionValidator;
static CFunctionValidator funcValidator;


void Sample()
{
	int iBpCount;
	int iFuncSize;
	unsigned long dwFuncChecksum;

	auto ret = funcValidator.ValidityFunction(Sample, &iBpCount, &iFuncSize, &dwFuncChecksum);

	printf("[*] F: %p\n\tRet: %d\n\tSize: %d BP: %d Checksum: %p\n", Sample, ret, iFuncSize, iBpCount, (void*)dwFuncChecksum);
}




int main()
{
	while (1)
	{
		Sample();

		Sleep(1000);
	}

	return 0;
}