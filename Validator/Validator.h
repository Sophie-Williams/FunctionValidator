#pragma once

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN

enum EDetectTypes {
	DONE = 1,

	INT3_BREAKPOINT = -11,

	PREFIX_1		= -121,
	PREFIX_2		= -122,

	UD1_BREAKPOINT			= -131,
	LONG_INT3_BREAKPOINT_1	= -132,
	LONG_INT3_BREAKPOINT_2	= -133,
	RDPMC					= -134,

	UD2_BREAKPOINT_1	= -141,
	UD2_BREAKPOINT_2	= -142,
	UD2_BREAKPOINT_3	= -143,

	ICE_BREAKPOINT		= -15,

	XORD_BREAKPOINT		= -16,

	INTERRUPT_1			= -171,
	INTERRUPT_2			= -172,
	INTERRUPT_3			= -173,

	VQUERY_FAIL			= -21,
	NOACCESS_EXCEPTION	= -22,
	GUARD_EXCEPTION		= -23,

	FUNCTION_INFO_FAIL	= -31,
	UNKNOWN_EBP			= -32,

	HARDWARE_BP			= -41,
};

namespace FunctionValidator
{
	class CFunctionValidator
	{
		public:
			CFunctionValidator();

			int ValidityFunction(void * pFunction, int * piBpCount, int * piFunctionSize, unsigned long * pdwChecksum);
	};
}


