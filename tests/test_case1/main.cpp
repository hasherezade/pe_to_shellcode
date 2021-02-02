#include <Windows.h>
#include <iostream>

//#define WITH_MESSAGE //only for manual tests

int get_date()
{
    SYSTEMTIME SystemTime;
    GetSystemTime(&SystemTime);

    char pszDate[200];
    GetDateFormatA( LOCALE_USER_DEFAULT, DATE_LONGDATE, &SystemTime, NULL, pszDate, 200 );
    std::cout << "Current date: " << pszDate << std::endl;
    return 1337;
}

int main()
{
    if (get_date() == 1337) {
        std::cout << "Test passed!\n";
    }
#ifdef WITH_MESSAGE
    MessageBoxW(0, L"Hello World!", L"Demo!", MB_OK);
#endif
    std::cout << "Test Case 1 finished\n";
    return 0;
}
