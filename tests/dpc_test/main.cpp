#include <iostream>
#include <Windows.h>

int main()
{
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcp = {};
	dcp.ProhibitDynamicCode = 1;
	SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dcp, sizeof(dcp));
	std::cout << "PID: " << std::dec << GetCurrentProcessId() << "\n";
	std::cout << "PROCESS_MITIGATION_DYNAMIC_CODE_POLICY enabled...\n";
	while (true)
	{
		Sleep(6000);
	}
	return 0;
}
