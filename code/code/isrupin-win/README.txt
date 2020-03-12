/**
 * Muhammad Ali Akbar
 * maa2206@columbia.edu
 * Columbia University, NY
 *
 * For queries: ali.akbar.ceme@gmail.com
 *
 */

About:
This is the source code of the isrupin (ISR pin tool for windows).

Pre-requisites:
1. From binary: The compiled pintool can be found here: isrupin\Debug\isrupin.dll

2. From source: The visual studio project with the source code is attached. It has been created
and compiled using Visual Studio 2008.

Visual Studio Configuration:
The project has been configured with relative library addresses.
Get the pin-2.10-43611-msvc9-ia32_intel64-windows PIN package,
and put the project folder (isrupin) at this location:
PIN_FOLDER\source\tools\MyWorkspace
Where PIN_FOLDER is the folder where you extracted the PIN package.



Usage:
[FULL_PATH_TO_PIN_FOLDER]\pin.bat -follow_execv -t [FULL_PATH_TO_PIN_FOLDER]\source\tools\MyWorkspace\isrupin\Debug\isrupin.dll -unique_logfile -keydb [FULL_PATH_TO_DATABASE_FOLDER]\image_keys.db -- [FULL_PATH_TO_EXECUTABLE]

For example:
C:\Research\ProjectFall2011\bins\pin-2.10-43611-msvc9-ia32_intel64-windows\pin.bat -follow_execv -t C:\Research\ProjectFall2011\bins\pin-2.10-43611-msvc9-ia32_intel64-windows\source\tools\MyWorkspace\isrupin\Debug\isrupin.dll -unique_logfile -keydb C:\Research\ProjectFall2011\database\image_keys.db -- C:\wamp32\bin\apache\Apache2.2.21\bin\httpd.exe


Formats supported: PE executables (32 bit)
Operating System : Tested on Windows 7
PIN version: pin-2.10-43611-msvc9-ia32_intel64-windows
