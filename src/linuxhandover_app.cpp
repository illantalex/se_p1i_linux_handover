// linuxhandover_app.cpp
// Test program for bare-metal handover LDD.
// Loads the payload (bare-metal stub + appended Linux zImage) from D:\other\p1i_linux.bin
// and hands over to it.

#include "linuxhandover.h"

#include <e32base.h>
#include <f32file.h>
#include <mdaaudiooutputstream.h>
#include <mda/common/audio.h>

_LIT(KPayloadFile, "D:\\other\\p1i_linux.bin");
_LIT(KLogFile, "C:\\linuxhandover.log");

const TInt KMaxPayload = 4 * 1024 * 1024;

// RFs::FinaliseDrives() is exported by efsrv.dll (efsrv.dso has _ZN3RFs14FinaliseDrivesEv),
// but the UIQ 3.1 SDK's f32file.h does not declare it. A member function gets `this` as its
// first argument, so a free function bound to the same symbol is call-compatible. Needs
// DiskAdmin.
TInt RFsFinaliseDrives(RFs* aFs) __asm__("_ZN3RFs14FinaliseDrivesEv");

// Linux cannot start a PCM stream on the audio DSP yet: it accepts every message but never
// creates the stream. A stream Symbian started keeps running after the handover, though, and
// Linux can feed it (DSP area 0, 44.1 kHz 16-bit stereo, 2016-byte halves). So before the
// handover, play silence through Symbian's audio stream API until it runs, and hand over with
// the stream still open. Any failure here only means no sound under Linux.
class CSilentStream : public CBase, public MMdaAudioOutputStreamCallback {
public:
    static CSilentStream* NewL() {
        CSilentStream* self = new (ELeave) CSilentStream;
        CleanupStack::PushL(self);
        self->iStream = CMdaAudioOutputStream::NewL(*self);
        self->iSilence.SetLength(self->iSilence.MaxLength());
        self->iSilence.FillZ();
        CleanupStack::Pop(self);
        return self;
    }
    // Opens the stream and keeps silence queued; returns once it has played for KRunUs, or
    // after KTimeoutUs. The stream stays open (deleting it would stop the DSP stream).
    TInt Start() {
        CPeriodic* timer = CPeriodic::New(CActive::EPriorityStandard);
        if (!timer)
            return KErrNoMemory;
        iSettings.iSampleRate = TMdaAudioDataSettings::ESampleRate44100Hz;
        iSettings.iChannels = TMdaAudioDataSettings::EChannelsStereo;
        iSettings.iFlags = TMdaAudioDataSettings::ENoNetworkRouting;
        iSettings.iVolume = 0;
        iStream->Open(&iSettings);
        timer->Start(KTimeoutUs, KTimeoutUs, TCallBack(Timeout, this));
        CActiveScheduler::Start();
        delete timer;
        // Nothing refills the queue from here on (no scheduler running): queue ~2 s more,
        // so the stream does not run dry (and stop) before the handover.
        if (iError == KErrNone)
            for (TInt i = 0; i < KTail; ++i)
                Write();
        return iError;
    }
    TInt Copied() const { return iCopied; }
private:
    enum { KQueued = 10, KTail = 90, KRunUs = 1500000, KTimeoutUs = 4000000 };
    static TInt Timeout(TAny* aSelf) {
        CSilentStream* self = static_cast<CSilentStream*>(aSelf);
        if (self->iError == KErrNone && self->iCopied == 0)
            self->iError = KErrTimedOut;
        CActiveScheduler::Stop();
        return EFalse;
    }
    void Write() {
        TRAPD(r, iStream->WriteL(iSilence));
        if (r != KErrNone)
            iError = r;
    }
    void MaoscOpenComplete(TInt aError) {
        if (aError != KErrNone) {
            iError = aError;
            CActiveScheduler::Stop();
            return;
        }
        TRAPD(r, iStream->SetAudioPropertiesL(TMdaAudioDataSettings::ESampleRate44100Hz,
                                              TMdaAudioDataSettings::EChannelsStereo));
        if (r != KErrNone) {
            iError = r;
            CActiveScheduler::Stop();
            return;
        }
        iStream->SetVolume(iStream->MaxVolume());
        for (TInt i = 0; i < KQueued; ++i)
            Write();
        iStarted.UniversalTime();
    }
    void MaoscBufferCopied(TInt aError, const TDesC8& /*aBuffer*/) {
        if (aError != KErrNone)
            return;   // KErrAbort when the stream stops
        ++iCopied;
        Write();      // keep KQueued buffers queued
        TTime now;
        now.UniversalTime();
        if (now.MicroSecondsFrom(iStarted).Int64() >= KRunUs && !iStopping) {
            iStopping = ETrue;
            CActiveScheduler::Stop();
        }
    }
    void MaoscPlayComplete(TInt aError) {
        if (!iStopping) {
            iError = aError ? aError : KErrEof;
            CActiveScheduler::Stop();
        }
    }
    CMdaAudioOutputStream* iStream;
    TMdaAudioDataSettings iSettings;
    TBuf8<4096> iSilence;   // 23 ms at 44.1 kHz stereo
    TTime iStarted;
    TInt iCopied;
    TInt iError;
    TBool iStopping;
};

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

    logBuf.Copy(_L8("Read complete. Starting the audio stream...\r\n"));
    logFile.Write(logBuf);
    logFile.Flush();

    // Never deleted: the stream has to be running at the handover.
    CActiveScheduler* scheduler = new (ELeave) CActiveScheduler;
    CActiveScheduler::Install(scheduler);
    CSilentStream* stream = NULL;
    TRAP(r, stream = CSilentStream::NewL());
    if (r == KErrNone)
        r = stream->Start();
    logBuf.Format(_L8("Audio stream: %d, %d buffers played. Finalising drives...\r\n"), r,
                  stream ? stream->Copied() : 0);
    logFile.Write(logBuf);
    logFile.Flush();

    // Linux takes over without Symbian shutting down, which for the file systems is like
    // pulling the battery. Close our files and finalise every drive (D:, which the payload
    // came from, included) so no FAT is left dirty. Finalise, log the result, then finalise
    // again, because writing the log dirties C: once more.
    payloadFile.Close();
    r = RFsFinaliseDrives(&fs);
    logBuf.Format(_L8("FinaliseDrives: %d\r\nInitiating handover...\r\n"), r);
    logFile.Write(logBuf);
    logFile.Flush();
    logFile.Close();
    RFsFinaliseDrives(&fs);

    // Handover to the bare-metal payload at physical 0x80600000.
    // This call does not return.
    r = handover.Handover(*payloadBuf, 0x80600000);

    // If we get here, handover failed.
    if (logFile.Open(fs, KLogFile, EFileWrite | EFileShareAny) == KErrNone) {
        TInt pos = 0;
        logFile.Seek(ESeekEnd, pos);
        logBuf.Format(_L8("Handover returned (error): %d\r\n"), r);
        logFile.Write(logBuf);
        logFile.Flush();
    }

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
