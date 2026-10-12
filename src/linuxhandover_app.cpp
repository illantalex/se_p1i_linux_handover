// linuxhandover_app.cpp
// Test program for bare-metal handover LDD.
// Loads the payload (bare-metal stub + appended Linux zImage) from D:\other\p1i_linux.bin
// and hands over to it.

#include "linuxhandover.h"

#include <e32base.h>
#include <f32file.h>

_LIT(KPayloadFile, "D:\\other\\p1i_linux.bin");
_LIT(KLogFile, "C:\\linuxhandover.log");

const TInt KMaxPayload = 4 * 1024 * 1024;

static void MainL() {
    RFs fs;
    User::LeaveIfError(fs.Connect());
    CleanupClosePushL(fs);

    RFile logFile;
    User::LeaveIfError(logFile.Replace(fs, KLogFile, EFileWrite | EFileShareAny));
    CleanupClosePushL(logFile);

    TBuf8<256> logBuf;

    logBuf.Copy(_L8("linuxhandover_app starting\r\n"));
    logFile.Write(logBuf);
    logFile.Flush();

    // Load the LDD.
    TInt r = User::LoadLogicalDevice(KLinuxHandoverLddFile);
    logBuf.Format(_L8("LoadLogicalDevice: %d\r\n"), r);
    logFile.Write(logBuf);
    logFile.Flush();
    if (r != KErrNone && r != KErrAlreadyExists)
        User::Leave(r);

    // Open the channel.
    RLinuxHandover handover;
    r = handover.Open();
    logBuf.Format(_L8("Open: %d\r\n"), r);
    logFile.Write(logBuf);
    logFile.Flush();
    User::LeaveIfError(r);
    CleanupClosePushL(handover);

    // Snapshot the MMU state and log it BEFORE attempting the handover, so the data
    // survives even if the handover aborts the thread (KERN-EXEC 3).
    TMmuInfo mmu;
    r = handover.MmuInfo(mmu);
    logBuf.Format(_L8("MmuInfo: %d\r\n"), r);
    logFile.Write(logBuf);
    if (r == KErrNone) {
        logBuf.Format(_L8("  Control  %08x\r\n  TTBR     %08x\r\n  DACR     %08x\r\n"),
                      mmu.iControl, mmu.iTtbr, mmu.iDacr);
        logFile.Write(logBuf);
        logBuf.Format(_L8("  FCSE PID %08x\r\n  payload  phys %08x sectionVA %08x\r\n"),
                      mmu.iFcsePid, mmu.iPayloadPhys, mmu.iSectionVA);
        logFile.Write(logBuf);
        logBuf.Format(_L8("  target L1 @%08x = %08x\r\n"), mmu.iDescPhys, mmu.iDescCurrent);
        logFile.Write(logBuf);
        logBuf.Format(_L8("  self VA  %08x  L1 @%08x = %08x\r\n"), mmu.iSelfVA,
                      mmu.iSelfDescPhys, mmu.iSelfDesc);
        logFile.Write(logBuf);
    }
    logFile.Flush();

    // Read the bare-metal binary.
    RFile payloadFile;
    r = payloadFile.Open(fs, KPayloadFile, EFileRead);
    logBuf.Format(_L8("Open payload: %d\r\n"), r);
    logFile.Write(logBuf);
    logFile.Flush();
    User::LeaveIfError(r);
    CleanupClosePushL(payloadFile);

    TInt payloadSize = 0;
    User::LeaveIfError(payloadFile.Size(payloadSize));
    if (payloadSize <= 0 || payloadSize > KMaxPayload)
        User::Leave(KErrTooBig);

    logBuf.Format(_L8("Payload size: %d bytes\r\n"), payloadSize);
    logFile.Write(logBuf);
    logFile.Flush();

    HBufC8* payloadBuf = HBufC8::NewLC(payloadSize);
    TPtr8 payloadPtr = payloadBuf->Des();
    User::LeaveIfError(payloadFile.Read(payloadPtr, payloadSize));

    logBuf.Copy(_L8("Read complete. Initiating handover...\r\n"));
    logFile.Write(logBuf);
    logFile.Flush();

    // Handover to the bare-metal payload at physical 0x80600000.
    // This call does not return.
    r = handover.Handover(*payloadBuf, 0x80600000);

    // If we get here, handover failed.
    logBuf.Format(_L8("Handover returned (error): %d\r\n"), r);
    logFile.Write(logBuf);
    logFile.Flush();

    CleanupStack::PopAndDestroy(5, &fs);  // payloadBuf, payloadFile, handover, logFile, fs
}

GLDEF_C TInt E32Main() {
    __UHEAP_MARK;
    CTrapCleanup* cleanup = CTrapCleanup::New();
    TRAPD(err, MainL());
    delete cleanup;
    __UHEAP_MARKEND;
    return err;
}
