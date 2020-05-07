##############################################################################
##
##  Utility to trace Dynamic Linking.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

LIBS=$(LIBS) kernel32.lib

# cholonam: Needed for CoCreateInstanceEx
LIBS=$(LIBS) ole32.lib
# cholonam: Needed for RegQueryValueEx
LIBS=$(LIBS) advapi32.lib
# cholonam: Needed for LoadTypeLibEx
LIBS=$(LIBS) oleaut32.lib
# cholonam: Needed for PathUnExpandEnvStringsW
LIBS=$(LIBS) shlwapi.lib

##############################################################################

all: dirs \
    $(BIND)\trclnk$(DETOURS_BITS).dll \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\trclnk$(DETOURS_BITS).bsc \
!ENDIF
    option

## cholonam: USE PRECOMPILED HEADER
!IF "$(PRECOMP)" == "0"
!   MESSAGE Use nmake PRECOMP=1 to enable precompiled header
!ELSE
CFLAGS = $(CFLAGS) /DUSING_PCH=1
PRECOMPILED_HEADER = $(OBJD)\precomp.pch
PRECOMPILED_OBJ = $(OBJD)\precomp.obj
USE_PH = /Yuprecomp.h /Fp$(PRECOMPILED_HEADER)
.cpp{$(OBJD)}.obj::
    $(CC) $(CFLAGS) $(USE_PH) /Fd$(OBJD)\vc.pdb /Fo$(OBJD)\ /c $<
.SUFFIXES: .h .pch
.cpp{$(OBJD)}.pch:
    $(CC) $(CFLAGS) /Fd$(OBJD)\vc.pdb /Fo$(OBJD)\ /Yc /Fp$(PRECOMPILED_HEADER) /c $<
$(PRECOMPILED_HEADER): precomp.cpp precomp.h
!ENDIF

##############################################################################

clean:
    -del *~ test.txt 2>nul
    -del $(BIND)\trclnk*.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo .   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo .   Created $(OBJD)

##############################################################################

$(OBJD)\trclnk.obj : trclnk.cpp

#cholonam
CFLAGS = $(CFLAGS) /EHa # <- Make sure destructors are called for SEH exceptions too
# Headers that include other headers
comspy.h: retaddrlist.h tostring.h vtbl_repeat.h
iiddb.h: interfaceinfo.h
interfaceinfo.h: cslock.h

# Object dependencies (cpp and headers included by the cpp)
$(OBJD)\comspy.obj : comspy.cpp comspy.h iiddb.h retaddrlist.h tostring.h               $(PRECOMPILED_HEADER)
$(OBJD)\iiddb.obj : iiddb.cpp iiddb.h cslock.h tostring.h interfaceinfo.h               $(PRECOMPILED_HEADER)
$(OBJD)\interfaceinfo.obj : interfaceinfo.cpp interfaceinfo.h cslock.h tostring.h       $(PRECOMPILED_HEADER)
$(OBJD)\multiplepatcher.obj : multiplepatcher.cpp multiplepatcher.h cslock.h tostring.h $(PRECOMPILED_HEADER)
$(OBJD)\retaddrlist.obj : retaddrlist.cpp retaddrlist.h                                 $(PRECOMPILED_HEADER)
$(OBJD)\tostring.obj : tostring.cpp tostring.h iiddb.h                                  $(PRECOMPILED_HEADER)
$(OBJD)\trclnk.obj : trclnk.cpp comspy.h iiddb.h retaddrlist.h tostring.h               $(PRECOMPILED_HEADER)

$(OBJD)\test.obj : test.cpp

OBJS = \
    $(OBJD)\comspy.obj \
    $(OBJD)\iiddb.obj \
    $(OBJD)\interfaceinfo.obj \
    $(OBJD)\multiplepatcher.obj \
    $(OBJD)\retaddrlist.obj \
    $(OBJD)\tostring.obj \
    $(OBJD)\trclnk.obj

$(OBJD)\trclnk.res : trclnk.rc

$(BIND)\trclnk$(DETOURS_BITS).dll : $(OBJS) $(OBJD)\trclnk.res $(DEPS)
    cl /LD $(CFLAGS) /Fe$@ /Fd$(@R).pdb \
        $(OBJS) $(PRECOMPILED_OBJ) $(OBJD)\trclnk.res \
        /link $(LINKFLAGS) /subsystem:console \
        /export:DetourFinishHelperProcess,@1,NONAME \
        $(LIBS)

$(OBJD)\trclnk$(DETOURS_BITS).bsc : $(OBJD)\trclnk.obj
    bscmake /v /n /o $@ $(OBJD)\trclnk.sbr

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\trclnk$(DETOURS_OPTION_BITS).dll:
$(OPTD)\trclnk$(DETOURS_OPTION_BITS).pdb:

$(BIND)\trclnk$(DETOURS_OPTION_BITS).dll : $(OPTD)\trclnk$(DETOURS_OPTION_BITS).dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\trclnk$(DETOURS_OPTION_BITS).pdb : $(OPTD)\trclnk$(DETOURS_OPTION_BITS).pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\trclnk$(DETOURS_OPTION_BITS).dll \
    $(BIND)\trclnk$(DETOURS_OPTION_BITS).pdb \

!ELSE

option:

!ENDIF

##############################################################################

notepad: all
    @echo -------- Logging output to test.txt ------------
    start $(BIND)\syelogd.exe /o test.txt
    $(BIND)\sleep5.exe 1
    @echo -------- Should load trclnk$(DETOURS_BITS).dll dynamically using withdll.exe ------------
    @echo .
    @echo ** NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE **
    @echo **
    @echo ** Close the NotePad window to continue test.
    @echo **
    @echo ** NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE **
    @echo .
    $(BIND)\withdll -d:$(BIND)\trclnk$(DETOURS_BITS).dll $(SYSTEMROOT)\system32\notepad.exe
    @echo -------- Log from syelog -------------
    type test.txt

test: all
    @echo -------- Logging output to test.txt ------------
    start $(BIND)\syelogd.exe /o test.txt
    $(BIND)\sleep5.exe 1
    @echo -------- Should load trclnk$(DETOURS_BITS).dll dynamically using withdll.exe ------------
    @echo .
    $(BIND)\withdll -d:$(BIND)\trclnk$(DETOURS_BITS).dll $(SYSTEMROOT)\system32\cmd.exe /c dir
    @echo -------- Log from syelog -------------
    type test.txt

test2: all
    @echo -------- Logging output to a.txt ------------
    start $(BIND)\syelogd.exe /o $(BIND)\a.txt
    $(BIND)\withdll -d:$(BIND)\trclnk$(DETOURS_BITS).dll "C:\Program Files (x86)\Microsoft Money\System\msmoney.exe"

test3: test.exe
    .\test.exe
test.exe: $(OBJD)/test.obj
################################################################# End of File.
