; Generated into the pinned full template by prepare-windows-nsis.ps1.
; Current-user/unelevated only. UNRUN private candidate; native review required.
!if "${INSTALLMODE}" != "currentUser"
  !error "csq S2a requires NSIS currentUser"
!endif
Var CsqHelper
Var CsqStage
Var CsqResult
Var CsqFailureMessage
Var CsqExpectedAlt
Var CsqLeaseResponseMode
Var CsqInstallerLease
Var CsqLeaseDigits
Var CsqLeaseCandidate
Var CsqParentPid
Var CsqLaunchArgs
Var CsqLaunched
Var CsqCommitted
Var CsqFile
Var CsqProvider
Var CsqHash
Var CsqBuffer
Var CsqDirectoryHandles
Var CsqDirectoryCount
Var CsqPinnedStage
Var CsqPinnedStageParent
Var CsqPinnedHelper
Var CsqBootstrapDirectory
Var CsqOwnerHandle
Var CsqPinResult
Var CsqPinnedForStage
Var CsqStageChild
Var CsqExpectedLeaseName
Var CsqLeaseObjectValid
Var CsqObjectInfoClass
Var CsqObjectExpected
Var CsqScanDirectory
Var CsqProfileRoot
Var CsqPinnedProfile
Var CsqProfileDirectory
Var CsqOutcomeFile
Var CsqCleanupLogName
Var CsqOwnedFrom
Var CsqStageRetry
Var CsqControllerStillLive

Var CsqRoot
Var CsqImages
Var CsqCommand
Var CsqExpected
Var CsqTimeout
Var CsqReadPipe
Var CsqWritePipe
Var CsqStartup
Var CsqProcessInfo
Var CsqCapture
Var CsqProcess
Var CsqThread
Var CsqBytesRead
Var CsqAttributeList
Var CsqAttributeInitialized
Var CsqHandleList
Var CsqInputRead

; Functions are emitted for installer and newly generated uninstaller.
!macro CsqAuthenticationFunctions Prefix
Function ${Prefix}CsqRefuse
  ${If} $CsqControllerStillLive != 1
    Call ${Prefix}CsqReleaseVerifiedNamespace
  ${EndIf}
  SetErrorLevel 73
  ${If} $CsqFailureMessage == ""
    StrCpy $CsqFailureMessage "csq could not verify safe installer admission. Close csq and rerun the installer."
  ${EndIf}
  ; Silent refusals deliberately suppress dialogs; exit 73 and stderr carry the result.
  Call ${Prefix}CsqWriteOutcome
  MessageBox MB_ICONSTOP|MB_OK "$CsqFailureMessage" /SD IDOK
  Quit
FunctionEnd

Function ${Prefix}CsqWriteOutcome
  Push $0
  Push $1
  Push $2
  DetailPrint "$CsqFailureMessage"
  ; A silent caller can capture stderr. GUI callers also receive a message box.
  System::Call 'kernel32::GetStdHandle(i -12) p .r0'
  ${If} $0 != 0
  ${AndIf} $0 != -1
    StrCpy $1 '$CsqFailureMessage$\r$\n'
    StrLen $2 $1
    System::Call 'kernel32::WriteFile(p r0, m r1, i r2, *i .r2, p 0)'
  ${EndIf}
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; The profile comes from the process token, not HKCU shell-folder strings.
Function ${Prefix}CsqLoadProfileRoot
  Push $0
  Push $1
  Push $2
  System::Call 'kernel32::GetCurrentProcess() p .r0'
  System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p .r1) i .r2'
  ${If} $2 == 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrCpy $2 ${NSIS_MAX_STRLEN}
  System::Call 'userenv::GetUserProfileDirectoryW(p r1, w .r0, *i r2) i .r2'
  Push $2
  System::Call 'kernel32::CloseHandle(p r1)'
  Pop $2
  ${If} $2 == 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrCpy $CsqProfileRoot $0
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function ${Prefix}CsqVerifyUnelevated
  Push $0
  Push $1
  Push $2
  System::Call 'kernel32::GetCurrentProcess() p .r0'
  ; The packaged helper target is Windows x64. Refuse unless this NSIS host is
  ; a 32-bit WOW64 process before using 32-bit SDK structures/handle arrays.
  StrCpy $1 0
  System::Call 'kernel32::IsWow64Process(p r0, *i .r1) i .r2'
  ${If} $2 == 0
  ${OrIf} $1 == 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p .r1) i .r2'
  ${If} $2 == 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  System::Call 'advapi32::GetTokenInformation(p r1, i 20, *i .r0, i 4, *i .r2) i .r2'
  Push $2
  System::Call 'kernel32::CloseHandle(p r1)'
  Pop $2
  ${If} $2 == 0
  ${OrIf} $0 != 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function ${Prefix}CsqReleaseVerifiedNamespace
  Push $0
  Push $1
  ${If} $CsqFile != ""
  ${AndIf} $CsqFile != -1
  ${AndIf} $CsqFile != 0
    System::Call 'kernel32::CloseHandle(p $CsqFile)'
  ${EndIf}
  StrCpy $CsqFile -1
  ${If} $CsqBootstrapDirectory != ""
  ${AndIf} $CsqBootstrapDirectory != -1
  ${AndIf} $CsqBootstrapDirectory != 0
    System::Call 'kernel32::CloseHandle(p $CsqBootstrapDirectory)'
  ${EndIf}
  StrCpy $CsqBootstrapDirectory 0
  ${If} $CsqProfileDirectory != ""
  ${AndIf} $CsqProfileDirectory != 0
  ${AndIf} $CsqProfileDirectory != -1
    System::Call 'kernel32::CloseHandle(p $CsqProfileDirectory)'
  ${EndIf}
  StrCpy $CsqProfileDirectory 0
  ${If} $CsqDirectoryHandles != ""
  ${AndIf} $CsqDirectoryHandles != 0
    csq_release_next:
      ${If} $CsqDirectoryCount == 0
        Goto csq_release_done
      ${EndIf}
      IntOp $CsqDirectoryCount $CsqDirectoryCount - 1
      IntOp $0 $CsqDirectoryCount * 4
      IntOp $0 $0 + $CsqDirectoryHandles
      System::Call '*$0(p .r1)'
      System::Call 'kernel32::CloseHandle(p r1)'
      Goto csq_release_next
    csq_release_done:
    System::Free $CsqDirectoryHandles
  ${EndIf}
  StrCpy $CsqDirectoryHandles 0
  StrCpy $CsqDirectoryCount 0
  StrCpy $CsqPinnedForStage ""
  Pop $1
  Pop $0
FunctionEnd

; Check owner of an already retained directory handle against the actual token
; user SID, never against a username/path/HKCU string. All allocations are local.
Function ${Prefix}CsqCheckStageOwner
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  StrCpy $CsqPinResult 1
  StrCpy $3 0
  StrCpy $4 0
  StrCpy $5 0
  System::Call 'kernel32::GetCurrentProcess() p .r0'
  System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p .r3) i .r1'
  ${If} $1 == 0
    Goto csq_owner_cleanup
  ${EndIf}
  StrCpy $2 0
  System::Call 'advapi32::GetTokenInformation(p r3, i 1, p 0, i 0, *i .r2)'
  ${If} $2 == 0
  ${OrIf} $2 > 65536
    Goto csq_owner_cleanup
  ${EndIf}
  System::Alloc $2
  Pop $4
  ${If} $4 == 0
    Goto csq_owner_cleanup
  ${EndIf}
  System::Call 'advapi32::GetTokenInformation(p r3, i 1, p r4, i r2, *i .r2) i .r1'
  ${If} $1 == 0
    Goto csq_owner_cleanup
  ${EndIf}
  System::Call '*$4(p .r0)'
  Push $0
  System::Call 'advapi32::GetSecurityInfo(p $CsqOwnerHandle, i 1, i 1, *p .r2, p 0, p 0, p 0, *p .r5) i .r1'
  Pop $0
  ${If} $1 != 0
  ${OrIf} $2 == 0
    Goto csq_owner_cleanup
  ${EndIf}
  System::Call 'advapi32::EqualSid(p r0, p r2) i .r1'
  ${If} $1 != 0
    StrCpy $CsqPinResult 0
  ${EndIf}
  csq_owner_cleanup:
  ${If} $5 != 0
    System::Call 'kernel32::LocalFree(p r5)'
  ${EndIf}
  ${If} $4 != 0
    System::Free $4
  ${EndIf}
  ${If} $3 != 0
    System::Call 'kernel32::CloseHandle(p r3)'
  ${EndIf}
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Pin the resolved volume-GUID namespace, from the token profile through every directory
; component, before opening/hash-reading the executable. Original DOS spelling
; must equal the final DOS path; redirected known-folder spellings refuse.
; Directory pins deny rename/removal, not sibling creation: TRAVERSE|SYNCHRONIZE
; participates in sharing; READ|WRITE sharing permits safe leaf creation.
; Every component from the token profile root onward must be token-user owned.
; Unsupported namespace, reparse, owner or sharing states fail closed.
Function ${Prefix}CsqPinStageNamespace
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6
  Push $7
  Push $8
  Push $9
  StrCpy $CsqPinResult 1
  StrCpy $CsqDirectoryCount 0
  StrCpy $CsqDirectoryHandles 0
  StrCpy $CsqBootstrapDirectory 0
  ; READ_CONTROL|READ_ATTRIBUTES|TRAVERSE|SYNCHRONIZE, share READ|WRITE,
  ; no DELETE; BACKUP_SEMANTICS|OPEN_REPARSE_POINT.
  Call ${Prefix}CsqLoadProfileRoot
  StrLen $0 $CsqProfileRoot
  IntOp $0 $0 + 1
  StrCpy $1 $CsqStage $0
  ${If} $1 != "$CsqProfileRoot\"
    Goto csq_pin_done
  ${EndIf}
  ; Mounted-folder profiles are outside this supported namespace shape.
  System::Call 'kernel32::GetVolumePathNameW(w "$CsqProfileRoot", w .r1, i ${NSIS_MAX_STRLEN}) i .r2'
  ${If} $2 == 0
    Goto csq_pin_done
  ${EndIf}
  StrLen $0 $1
  ${If} $0 != 3
    Goto csq_pin_done
  ${EndIf}
  ; Retain/resolve the actual profile itself before resolving the stage.
  ; C:\ and C:\Users are neither opened nor pinned by this transaction.
  System::Call 'kernel32::CreateFileW(w "$CsqProfileRoot", i 0x1200A0, i 3, p 0, i 3, i 0x02200000, p 0) p .r0 ?e'
  Pop $1
  ${If} $0 == -1
    ${If} $1 == 32
      StrCpy $CsqFailureMessage "CSQ_INSTALL_V1 REFUSED staging_sharing_violation"
    ${EndIf}
    Goto csq_pin_done
  ${EndIf}
  StrCpy $CsqProfileDirectory $0
  System::Call 'kernel32::GetFinalPathNameByHandleW(p $CsqProfileDirectory, w .r1, i ${NSIS_MAX_STRLEN}, i 0) i .r2'
  ${If} $2 == 0
  ${OrIf} $2 >= ${NSIS_MAX_STRLEN}
    Goto csq_pin_done
  ${EndIf}
  StrCpy $0 $1 4
  ${If} $0 != "\\?\"
    Goto csq_pin_done
  ${EndIf}
  StrCpy $0 $1 "" 4
  ${If} $0 != $CsqProfileRoot
    Goto csq_pin_done
  ${EndIf}
  System::Call 'kernel32::GetFinalPathNameByHandleW(p $CsqProfileDirectory, w .r1, i ${NSIS_MAX_STRLEN}, i 1) i .r2'
  ${If} $2 == 0
  ${OrIf} $2 >= ${NSIS_MAX_STRLEN}
    Goto csq_pin_done
  ${EndIf}
  StrCpy $CsqPinnedProfile $1
  StrLen $CsqOwnedFrom $CsqPinnedProfile
  System::Call 'kernel32::CreateFileW(w "$CsqStage", i 0x1200A0, i 3, p 0, i 3, i 0x02200000, p 0) p .r0 ?e'
  Pop $1
  ${If} $0 == -1
    ${If} $1 == 32
      StrCpy $CsqFailureMessage "CSQ_INSTALL_V1 REFUSED staging_sharing_violation"
    ${EndIf}
    Goto csq_pin_done
  ${EndIf}
  StrCpy $CsqBootstrapDirectory $0
  System::Call 'kernel32::GetFinalPathNameByHandleW(p $CsqBootstrapDirectory, w .r1, i ${NSIS_MAX_STRLEN}, i 0) i .r2'
  ${If} $2 == 0
  ${OrIf} $2 >= ${NSIS_MAX_STRLEN}
    Goto csq_pin_done
  ${EndIf}
  StrCpy $0 $1 4
  ${If} $0 != "\\?\"
    Goto csq_pin_done
  ${EndIf}
  StrCpy $0 $1 "" 4
  ${If} $0 != $CsqStage
    Goto csq_pin_done
  ${EndIf}
  System::Call 'kernel32::GetFinalPathNameByHandleW(p $CsqBootstrapDirectory, w .r1, i ${NSIS_MAX_STRLEN}, i 1) i .r2'
  ${If} $2 == 0
  ${OrIf} $2 >= ${NSIS_MAX_STRLEN}
    Goto csq_pin_done
  ${EndIf}
  StrCpy $0 $1 11
  ${If} $0 != "\\?\Volume{"
    Goto csq_pin_done
  ${EndIf}
  StrCpy $0 $1 2 47
  ${If} $0 != "}\"
    Goto csq_pin_done
  ${EndIf}
  ; The resolved stage must descend from the resolved, retained profile.
  IntOp $0 $CsqOwnedFrom + 1
  StrCpy $0 $1 $0
  ${If} $0 != "$CsqPinnedProfile\"
    Goto csq_pin_done
  ${EndIf}
  StrCpy $CsqPinnedStage $1
  ${GetParent} "$CsqPinnedStage" $CsqPinnedStageParent
  StrCpy $CsqPinnedHelper "$CsqPinnedStage\csq-upgrade-helper.exe"
  ; At most 128 retained directory handles; excessive depth refuses.
  System::Alloc 512
  Pop $CsqDirectoryHandles
  ${If} $CsqDirectoryHandles == 0
    Goto csq_pin_done
  ${EndIf}
  StrCpy $3 $CsqPinnedStage 49
  System::Call 'kernel32::GetDriveTypeW(w r3) i .r0'
  ${If} $0 != 3
    Goto csq_pin_done
  ${EndIf}
  StrCpy $3 $CsqPinnedProfile
  IntOp $4 $CsqOwnedFrom + 1
  StrLen $5 $CsqPinnedStage
  csq_pin_open:
    ${If} $CsqDirectoryCount >= 128
      Goto csq_pin_done
    ${EndIf}
    System::Call 'kernel32::CreateFileW(w r3, i 0x1200A0, i 3, p 0, i 3, i 0x02200000, p 0) p .r6 ?e'
    Pop $0
    ${If} $6 == -1
      ${If} $0 == 32
        StrCpy $CsqFailureMessage "CSQ_INSTALL_V1 REFUSED staging_sharing_violation"
      ${EndIf}
      Goto csq_pin_done
    ${EndIf}
    IntOp $0 $CsqDirectoryCount * 4
    IntOp $0 $0 + $CsqDirectoryHandles
    System::Call '*$0(p r6)'
    IntOp $CsqDirectoryCount $CsqDirectoryCount + 1
    System::Call 'kernel32::SetHandleInformation(p r6, i 1, i 0) i .r0'
    ${If} $0 == 0
      Goto csq_pin_done
    ${EndIf}
    System::Alloc 52
    Pop $7
    ${If} $7 == 0
      Goto csq_pin_done
    ${EndIf}
    System::Call 'kernel32::GetFileInformationByHandle(p r6, p r7) i .r0'
    System::Call '*$7(i .r8)'
    System::Free $7
    ${If} $0 == 0
      Goto csq_pin_done
    ${EndIf}
    IntOp $0 $8 & 0x410
    ${If} $0 != 0x10
      Goto csq_pin_done
    ${EndIf}
    StrCpy $CsqOwnerHandle $6
    Call ${Prefix}CsqCheckStageOwner
    ${If} $CsqPinResult != 0
      Goto csq_pin_done
    ${EndIf}
    StrCpy $CsqPinResult 1
    ${If} $4 >= $5
      StrCpy $CsqPinResult 0
      StrCpy $CsqPinnedForStage $CsqStage
      Goto csq_pin_done
    ${EndIf}
    ; The first loop handle is the profile root, without a trailing slash.
    ; Descendant scanning starts after its separator, never above the profile.
    StrCpy $9 $4
    csq_pin_component:
      StrCpy $0 $CsqPinnedStage 1 $4
      ${If} $0 == "\"
      ${OrIf} $0 == ""
        ${If} $4 == $9
          Goto csq_pin_done
        ${EndIf}
        StrCpy $3 $CsqPinnedStage $4
        IntOp $4 $4 + 1
        Goto csq_pin_open
      ${EndIf}
      IntOp $4 $4 + 1
      Goto csq_pin_component
  csq_pin_done:
  ; Bootstrap handle remains retained through process creation as well.
  Pop $9
  Pop $8
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Query the SHA-pinned embedded helper before READY, independently of the
; returned handle. This fixed pure verb reads the protected profile secret and
; derives the session-local HMAC name; it does not acquire a lease or use IPC.
Function ${Prefix}CsqExpectedLeaseIdentity
  StrCpy $CsqExpectedLeaseName ""
  StrCpy $CsqCommand '$\"$CsqHelper$\" lease-object-name'
  StrCpy $CsqExpectedAlt ""
  StrCpy $CsqLeaseResponseMode 2
  StrCpy $CsqExpected "CSQ_INSTALL_V1 LEASE_OBJECT_NAME"
  StrCpy $CsqTimeout 10000
  Call ${Prefix}CsqRunController
  ${If} $CsqExpectedLeaseName == ""
    Call ${Prefix}CsqRefuse
  ${EndIf}
FunctionEnd

; NSIS host is 32-bit: UNICODE_STRING is Length:u16, MaximumLength:u16,
; Buffer:u32. Check the returned pointer/length before comparing exact UTF-16.
Function ${Prefix}CsqCheckLeaseObject
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  StrCpy $CsqLeaseObjectValid 0
  System::Alloc 4096
  Pop $1
  ${If} $1 == 0
    Goto csq_object_done
  ${EndIf}
  System::Call 'ntdll::NtQueryObject(p $CsqLeaseCandidate, i $CsqObjectInfoClass, p r1, i 4096, *i .r0) i .r2'
  ${If} $2 != 0
  ${OrIf} $0 < 8
  ${OrIf} $0 > 4096
    Goto csq_object_free
  ${EndIf}
  System::Call '*$1(&i2 .r2, &i2 .r3, p .r4)'
  StrLen $5 $CsqObjectExpected
  IntOp $5 $5 * 2
  ${If} $2 != $5
  ${OrIf} $3 < $2
    Goto csq_object_free
  ${EndIf}
  IntOp $5 $1 + 8
  ${If} $4 < $5
    Goto csq_object_free
  ${EndIf}
  IntOp $5 $4 + $2
  IntOp $0 $1 + 4094
  ${If} $5 > $0
  ${OrIf} $5 < $4
    Goto csq_object_free
  ${EndIf}
  System::Call '*$5(&i2 0)'
  System::Call '*$4(&w${NSIS_MAX_STRLEN} .r0)'
  StrCmpS $0 $CsqObjectExpected 0 csq_object_free
  StrCpy $CsqLeaseObjectValid 1
  csq_object_free:
  System::Free $1
  csq_object_done:
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Every enumeration uses the retained volume-GUID parent. Errors refuse, rather
; than treating an unreadable directory as empty. The DLL load flag is separate
; protection: directory pins do not prevent a same-user sibling-create race.
Function ${Prefix}CsqCheckStageContents
  Push $0
  Push $1
  Push $2
  Push $3
  StrCpy $CsqResult 1
  System::Alloc 592
  Pop $1
  ${If} $1 == 0
    Goto csq_contents_done
  ${EndIf}
  System::Call 'kernel32::FindFirstFileW(w "$CsqScanDirectory\*", p r1) p .r0 ?e'
  Pop $2
  ${If} $0 == -1
    ; Every initial failure refuses, including FILE_NOT_FOUND.
    Goto csq_contents_free
  ${EndIf}
  csq_contents_next:
    IntOp $2 $1 + 44
    System::Call '*$2(&w260 .r3)'
    ${If} $3 != "."
    ${AndIf} $3 != ".."
      ${If} $3 != "csq-upgrade-helper.exe"
        Goto csq_contents_close
      ${EndIf}
      System::Call '*$1(i .r2)'
      IntOp $2 $2 & 0x410
      ${If} $2 != 0
        Goto csq_contents_close
      ${EndIf}
    ${EndIf}
    System::Call 'kernel32::FindNextFileW(p r0, p r1) i .r2 ?e'
    Pop $3
    ${If} $2 != 0
      Goto csq_contents_next
    ${EndIf}
    ${If} $3 == 18
      StrCpy $CsqResult 0
    ${EndIf}
  csq_contents_close:
    System::Call 'kernel32::FindClose(p r0)'
  csq_contents_free:
    System::Free $1
  csq_contents_done:
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Only this version's random-name logs with exact fixed content qualify. The
; writer retains its no-delete-sharing handle until exit, so active logs cannot
; be opened exclusively for disposition. Unknown/legacy log shapes are kept.
Function ${Prefix}CsqPruneOutcomeLog
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6
  Push $7
  Push $8
  Push $9
  StrCpy $4 0
  StrCpy $5 -1
  StrLen $0 $CsqCleanupLogName
  ${If} $0 != 52
    Goto csq_log_done
  ${EndIf}
  StrCpy $0 $CsqCleanupLogName 16
  StrCmpS $0 "install-outcome-" 0 csq_log_done
  StrCpy $0 $CsqCleanupLogName 4 -4
  StrCmpS $0 ".txt" 0 csq_log_done
  StrCpy $1 16
  csq_log_hex:
    StrCpy $0 $CsqCleanupLogName 1 $1
    StrCmp $0 "0" csq_log_hex_valid
    StrCmp $0 "1" csq_log_hex_valid
    StrCmp $0 "2" csq_log_hex_valid
    StrCmp $0 "3" csq_log_hex_valid
    StrCmp $0 "4" csq_log_hex_valid
    StrCmp $0 "5" csq_log_hex_valid
    StrCmp $0 "6" csq_log_hex_valid
    StrCmp $0 "7" csq_log_hex_valid
    StrCmp $0 "8" csq_log_hex_valid
    StrCmp $0 "9" csq_log_hex_valid
    StrCmp $0 "a" csq_log_hex_valid
    StrCmp $0 "b" csq_log_hex_valid
    StrCmp $0 "c" csq_log_hex_valid
    StrCmp $0 "d" csq_log_hex_valid
    StrCmp $0 "e" csq_log_hex_valid
    StrCmp $0 "f" csq_log_hex_valid
    Goto csq_log_done
    csq_log_hex_valid:
    IntOp $1 $1 + 1
    ${If} $1 < 48
      Goto csq_log_hex
    ${EndIf}
  ; GENERIC_READ|DELETE|READ_CONTROL|READ_ATTRIBUTES, exclusive sharing.
  System::Call 'kernel32::CreateFileW(w "$CsqPinnedStageParent\$CsqCleanupLogName", i 0x80030080, i 0, p 0, i 3, i 0x00200000, p 0) p .r5'
  ${If} $5 == -1
    Goto csq_log_done
  ${EndIf}
  System::Alloc 52
  Pop $4
  ${If} $4 == 0
    Goto csq_log_done
  ${EndIf}
  System::Call 'kernel32::GetFileInformationByHandle(p r5, p r4) i .r0'
  ${If} $0 == 0
    Goto csq_log_done
  ${EndIf}
  System::Call '*$4(i .r0)'
  IntOp $0 $0 & 0x410
  ${If} $0 != 0
    Goto csq_log_done
  ${EndIf}
  IntOp $0 $4 + 32
  System::Call '*$0(i .r7, i .r8, i .r9)'
  StrCpy $3 "csq installed, not launched. Start csq from the Start menu when ready.$\r$\n"
  StrLen $2 $3
  ${If} $7 != 0
  ${OrIf} $8 != $2
  ${OrIf} $9 != 1
    Goto csq_log_done
  ${EndIf}
  IntOp $0 $4 + 20
  System::Call '*$0(l .r6)'
  System::Call 'kernel32::GetSystemTimeAsFileTime(*l .r7)'
  System::Int64Op $7 - $6
  Pop $6
  ; Keep at least seven days; future timestamps also remain untouched.
  System::Int64Op $6 < 6048000000000
  Pop $7
  ${If} $7 != 0
    Goto csq_log_done
  ${EndIf}
  StrCpy $CsqOwnerHandle $5
  Call ${Prefix}CsqCheckStageOwner
  ${If} $CsqPinResult != 0
    Goto csq_log_done
  ${EndIf}
  System::Free $4
  StrCpy $4 0
  System::Alloc 256
  Pop $4
  ${If} $4 == 0
    Goto csq_log_done
  ${EndIf}
  System::Call 'kernel32::ReadFile(p r5, p r4, i 255, *i .r1, p 0) i .r0'
  ${If} $0 == 0
  ${OrIf} $1 != $2
    Goto csq_log_done
  ${EndIf}
  IntOp $0 $4 + $1
  System::Call '*$0(&i1 0)'
  System::Call '*$4(&m255 .r0)'
  StrCmpS $0 $3 0 csq_log_done
  ; Mark the authenticated open file, never reopen/delete a path after checks.
  System::Call 'kernel32::SetFileInformationByHandle(p r5, i 4, *i 1, i 1)'
  csq_log_done:
  ${If} $4 != 0
    System::Free $4
  ${EndIf}
  ${If} $5 != -1
    System::Call 'kernel32::CloseHandle(p r5)'
  ${EndIf}
  Pop $9
  Pop $8
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Best-effort, nonrecursive cleanup: keep current SHA, unknown content, foreign
; owners, reparses and active helpers. Only a checked old SHA directory's single
; helper leaf is deleted while that directory is pinned. RemoveDirectory never
; follows a substituted junction and cannot remove a nonempty directory.
Function ${Prefix}CsqCleanupStaleStages
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6
  Push $7
  Push $8
  Push $9
  Push $CsqScanDirectory
  StrCpy $9 128
  System::Alloc 592
  Pop $1
  ${If} $1 == 0
    Goto csq_stale_done
  ${EndIf}
  System::Call 'kernel32::FindFirstFileW(w "$CsqPinnedStageParent\*", p r1) p .r0'
  ${If} $0 == -1
    Goto csq_stale_free
  ${EndIf}
  csq_stale_next:
    ${If} $9 == 0
      Goto csq_stale_find_close
    ${EndIf}
    IntOp $9 $9 - 1
    IntOp $2 $1 + 44
    System::Call '*$2(&w260 .r3)'
    StrLen $2 $3
    ${If} $2 != 64
      StrCpy $CsqCleanupLogName $3
      Call ${Prefix}CsqPruneOutcomeLog
      Goto csq_stale_advance
    ${EndIf}
    StrCmpS $3 "@CSQ_HELPER_SHA256@" csq_stale_advance
    StrCpy $4 0
    csq_stale_hex:
      StrCpy $2 $3 1 $4
      StrCmpS $2 "0" csq_stale_hex_valid
      StrCmpS $2 "1" csq_stale_hex_valid
      StrCmpS $2 "2" csq_stale_hex_valid
      StrCmpS $2 "3" csq_stale_hex_valid
      StrCmpS $2 "4" csq_stale_hex_valid
      StrCmpS $2 "5" csq_stale_hex_valid
      StrCmpS $2 "6" csq_stale_hex_valid
      StrCmpS $2 "7" csq_stale_hex_valid
      StrCmpS $2 "8" csq_stale_hex_valid
      StrCmpS $2 "9" csq_stale_hex_valid
      StrCmpS $2 "a" csq_stale_hex_valid
      StrCmpS $2 "b" csq_stale_hex_valid
      StrCmpS $2 "c" csq_stale_hex_valid
      StrCmpS $2 "d" csq_stale_hex_valid
      StrCmpS $2 "e" csq_stale_hex_valid
      StrCmpS $2 "f" csq_stale_hex_valid
      Goto csq_stale_advance
      csq_stale_hex_valid:
      IntOp $4 $4 + 1
      ${If} $4 < 64
        Goto csq_stale_hex
      ${EndIf}
    StrCpy $CsqScanDirectory "$CsqPinnedStageParent\$3"
    System::Call 'kernel32::CreateFileW(w "$CsqScanDirectory", i 0x1200A0, i 3, p 0, i 3, i 0x02200000, p 0) p .r5'
    ${If} $5 == -1
      Goto csq_stale_advance
    ${EndIf}
    System::Alloc 52
    Pop $6
    ${If} $6 == 0
      Goto csq_stale_close
    ${EndIf}
    System::Call 'kernel32::GetFileInformationByHandle(p r5, p r6) i .r7'
    System::Call '*$6(i .r8)'
    System::Free $6
    IntOp $8 $8 & 0x410
    ${If} $7 == 0
    ${OrIf} $8 != 0x10
      Goto csq_stale_close
    ${EndIf}
    StrCpy $CsqOwnerHandle $5
    Call ${Prefix}CsqCheckStageOwner
    ${If} $CsqPinResult != 0
      Goto csq_stale_close
    ${EndIf}
    Call ${Prefix}CsqCheckStageContents
    ${If} $CsqResult != 0
      Goto csq_stale_close
    ${EndIf}
    System::Call 'kernel32::DeleteFileW(w "$CsqScanDirectory\csq-upgrade-helper.exe") i .r7'
    System::Call 'kernel32::CloseHandle(p r5)'
    ; Empty old directories can also be removed; absence is harmless.
    System::Call 'kernel32::RemoveDirectoryW(w "$CsqScanDirectory")'
    Goto csq_stale_advance
  csq_stale_close:
    System::Call 'kernel32::CloseHandle(p r5)'
  csq_stale_advance:
    System::Call 'kernel32::FindNextFileW(p r0, p r1) i .r2'
    ${If} $2 != 0
      Goto csq_stale_next
    ${EndIf}
  csq_stale_find_close:
    System::Call 'kernel32::FindClose(p r0)'
  csq_stale_free:
    System::Free $1
  csq_stale_done:
  Pop $CsqScanDirectory
  Pop $9
  Pop $8
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Hash before every helper execution. The digest is compiled into the installer
; as delivered; updater minisign covers the installer. No Authenticode is assumed.
Function ${Prefix}CsqVerifyHelper
  Push $0
  Push $1
  Push $2
  Push $3
  StrCpy $CsqResult 1
  ; Existing verified directory pins survive extraction -> hash -> exec.
  ${If} $CsqPinnedForStage != $CsqStage
  ${OrIf} $CsqDirectoryCount == 0
    Call ${Prefix}CsqReleaseVerifiedNamespace
    Call ${Prefix}CsqPinStageNamespace
    ${If} $CsqPinResult != 0
      Call ${Prefix}CsqRefuse
    ${EndIf}
  ${EndIf}
  StrCpy $CsqScanDirectory $CsqPinnedStage
  Call ${Prefix}CsqCheckStageContents
  ${If} $CsqResult != 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrCpy $CsqResult 1
  ; Rehashing may reopen the leaf while keeping every parent directory pinned.
  ${If} $CsqFile != ""
  ${AndIf} $CsqFile != -1
  ${AndIf} $CsqFile != 0
    System::Call 'kernel32::CloseHandle(p $CsqFile)'
  ${EndIf}
  StrCpy $CsqFile -1
  StrCpy $CsqProvider 0
  StrCpy $CsqHash 0
  StrCpy $CsqBuffer 0
  System::Call 'kernel32::CreateFileW(w "$CsqPinnedHelper", i 0x80000000, i 1, p 0, i 3, i 0x00200000, p 0) p .r0'
  StrCpy $CsqFile $0
  ${If} $CsqFile == -1
    Goto csq_hash_cleanup
  ${EndIf}
  ; NULL SECURITY_ATTRIBUTES already creates a noninheritable handle. Check
  ; the explicit clearing too, independently of the process handle allowlist.
  System::Call 'kernel32::SetHandleInformation(p $CsqFile, i 1, i 0) i .r1'
  ${If} $1 == 0
    Goto csq_hash_cleanup
  ${EndIf}
  System::Alloc 52
  Pop $3
  ${If} $3 == 0
    Goto csq_hash_cleanup
  ${EndIf}
  System::Call 'kernel32::GetFileInformationByHandle(p $CsqFile, p r3) i .r1'
  System::Call '*$3(i .r2)'
  System::Free $3
  ${If} $1 == 0
    Goto csq_hash_cleanup
  ${EndIf}
  IntOp $2 $2 & 0x410
  ${If} $2 != 0
    Goto csq_hash_cleanup
  ${EndIf}
  StrCpy $0 0
  System::Call 'advapi32::CryptAcquireContextW(*p .r0, p 0, p 0, i 24, i 0xF0000000) i .r1'
  StrCpy $CsqProvider $0
  ${If} $1 == 0
    Goto csq_hash_cleanup
  ${EndIf}
  System::Call 'advapi32::CryptCreateHash(p $CsqProvider, i 0x800C, p 0, i 0, *p .r0) i .r1'
  StrCpy $CsqHash $0
  ${If} $1 == 0
    Goto csq_hash_cleanup
  ${EndIf}
  System::Alloc 65536
  Pop $CsqBuffer
  ${If} $CsqBuffer == 0
    Goto csq_hash_cleanup
  ${EndIf}
  csq_hash_read:
    System::Call 'kernel32::ReadFile(p $CsqFile, p $CsqBuffer, i 65536, *i .r2, p 0) i .r1'
    ${If} $1 == 0
      Goto csq_hash_cleanup
    ${EndIf}
    ${If} $2 == 0
      Goto csq_hash_finish
    ${EndIf}
    System::Call 'advapi32::CryptHashData(p $CsqHash, p $CsqBuffer, i r2, i 0) i .r1'
    ${If} $1 == 0
      Goto csq_hash_cleanup
    ${EndIf}
    Goto csq_hash_read
  csq_hash_finish:
    StrCpy $3 32
    System::Call 'advapi32::CryptGetHashParam(p $CsqHash, i 2, p $CsqBuffer, *i r3, i 0) i .r1'
    ${If} $1 == 0
      Goto csq_hash_cleanup
    ${EndIf}
    StrCpy $3 65
    System::Call 'crypt32::CryptBinaryToStringW(p $CsqBuffer, i 32, i 0x4000000C, w .r2, *i r3) i .r1'
    ${If} $1 != 0
    ${AndIf} $2 == "@CSQ_HELPER_SHA256@"
      StrCpy $CsqResult 0
    ${EndIf}
  csq_hash_cleanup:
    ${If} $CsqHash != 0
      System::Call 'advapi32::CryptDestroyHash(p $CsqHash)'
    ${EndIf}
    ${If} $CsqProvider != 0
      System::Call 'advapi32::CryptReleaseContext(p $CsqProvider, i 0)'
    ${EndIf}
    ${If} $CsqBuffer != 0
      System::Free $CsqBuffer
    ${EndIf}
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd
!macroend
!insertmacro CsqAuthenticationFunctions ""
!insertmacro CsqAuthenticationFunctions "un."

; Called only for the two compile-time stage components below. Existing
; parent ancestry is already pinned; creation uses that exact GUID parent.
!macro CsqStagingFunctions Prefix
Function ${Prefix}CsqCreateAndPinStageChild
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  ${If} $CsqDirectoryCount == 0
  ${OrIf} $CsqDirectoryCount >= 128
  ${OrIf} $CsqPinnedForStage != $CsqStage
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrLen $0 $CsqPinnedStage
  StrLen $1 $CsqStageChild
  IntOp $0 $0 + $1
  ; Separator + later helper basename and terminator must fit the NSIS string.
  IntOp $0 $0 + 25
  ${If} $0 >= ${NSIS_MAX_STRLEN}
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrCpy $3 "$CsqPinnedStage\$CsqStageChild"
  System::Call 'kernel32::CreateDirectoryW(w r3, p 0) i .r0'
  ; Creation may report already-existing or another error; neither authorizes
  ; the next write. Only a successful retained OPEN_EXISTING + checks below do.
  ; Open the final child itself, never a reparse target. Retain before checking
  ; its attributes/owner and before any next-component write is possible.
  System::Call 'kernel32::CreateFileW(w r3, i 0x1200A0, i 3, p 0, i 3, i 0x02200000, p 0) p .r4 ?e'
  Pop $0
  ${If} $4 == -1
    ${If} $0 == 32
      StrCpy $CsqFailureMessage "CSQ_INSTALL_V1 REFUSED staging_sharing_violation"
    ${EndIf}
    Call ${Prefix}CsqRefuse
  ${EndIf}
  IntOp $0 $CsqDirectoryCount * 4
  IntOp $0 $0 + $CsqDirectoryHandles
  System::Call '*$0(p r4)'
  IntOp $CsqDirectoryCount $CsqDirectoryCount + 1
  System::Call 'kernel32::SetHandleInformation(p r4, i 1, i 0) i .r0'
  ${If} $0 == 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  System::Alloc 52
  Pop $2
  ${If} $2 == 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  System::Call 'kernel32::GetFileInformationByHandle(p r4, p r2) i .r0'
  System::Call '*$2(i .r1)'
  System::Free $2
  ${If} $0 == 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  IntOp $1 $1 & 0x410
  ${If} $1 != 0x10
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrCpy $CsqOwnerHandle $4
  Call ${Prefix}CsqCheckStageOwner
  ${If} $CsqPinResult != 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrCpy $CsqPinnedStageParent $CsqPinnedStage
  StrCpy $CsqPinnedStage $3
  StrCpy $CsqStage "$CsqStage\$CsqStageChild"
  StrCpy $CsqPinnedForStage $CsqStage
  StrCpy $CsqPinnedHelper "$CsqPinnedStage\csq-upgrade-helper.exe"
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function ${Prefix}CsqStageHelper
  Call ${Prefix}CsqVerifyUnelevated
  ; LOCALAPPDATA is only a discovery hint: the token profile root and every
  ; directory below it must be nonreparse, owned and pinned before creation.
  StrCpy $CsqStage "$LOCALAPPDATA"
  Call ${Prefix}CsqReleaseVerifiedNamespace
  Call ${Prefix}CsqPinStageNamespace
  ${If} $CsqPinResult != 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  ; Exactly two descendants, each created/opened via the retained GUID parent
  ; and checked nonreparse/current-user-owned before the next descendant.
  StrCpy $CsqStageChild "Code Squad Q.upgrade-gate"
  Call ${Prefix}CsqCreateAndPinStageChild
  StrCpy $CsqStageChild "@CSQ_HELPER_SHA256@"
  Call ${Prefix}CsqCreateAndPinStageChild
  StrCpy $CsqHelper "$CsqStage\csq-upgrade-helper.exe"
  ; Use exactly the retained namespace, after owner/nonreparse checks.
  ClearErrors
  SetOutPath "$CsqPinnedStage"
  ${If} ${Errors}
    Call ${Prefix}CsqRefuse
  ${EndIf}
  ; NSIS3.11 EW_EXTRACTFILE uses kernel CREATE_NEW for overwriteflag1.
  ; An existing file/link is skipped without truncation or read-only mutation.
  ; No IfFileExists check is relied upon for atomicity.
  StrCpy $CsqStageRetry 0
  csq_stage_extract:
  ClearErrors
  SetOverwrite off
  File /oname=csq-upgrade-helper.exe "@CSQ_HELPER_PAYLOAD@"
  SetOverwrite lastused
  ; A failed write may have left a truncated file; verification determines
  ; recovery. Parent namespace pins remain held throughout both attempts.
  Call ${Prefix}CsqVerifyHelper
  ${If} $CsqResult != 0
    ${If} $CsqStageRetry != 0
      Call ${Prefix}CsqRefuse
    ${EndIf}
    StrCpy $CsqStageRetry 1
    ${If} $CsqFile != -1
    ${AndIf} $CsqFile != 0
      System::Call 'kernel32::CloseHandle(p $CsqFile)'
    ${EndIf}
    StrCpy $CsqFile -1
    System::Call 'kernel32::DeleteFileW(w "$CsqPinnedHelper") i .r0'
    ${If} $0 == 0
      Call ${Prefix}CsqRefuse
    ${EndIf}
    ; Retry uses CREATE_NEW again, never truncate/overwrite a replacement.
    Goto csq_stage_extract
  ${EndIf}
  Call ${Prefix}CsqCleanupStaleStages
  System::Call 'kernel32::GetCurrentProcessId() i .r0'
  StrCpy $CsqParentPid $0
FunctionEnd

!macroend
!insertmacro CsqStagingFunctions ""
!insertmacro CsqStagingFunctions "un."

; Successful silent/passive no-launch remains exit 0. Random CREATE_NEW names
; retry collisions, never truncate. Keep the writer handle until process exit
; so cleanup cannot remove a live transaction's record.
Function CsqRecordNoLaunch
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Call CsqReleaseVerifiedNamespace
  Call CsqPinStageNamespace
  ${If} $CsqPinResult != 0
    StrCpy $CsqFailureMessage "csq installed, not launched; outcome log could not be created safely. Start csq manually."
    Call CsqRefuse
  ${EndIf}
  System::Alloc 16
  Pop $4
  ${If} $4 == 0
    Call CsqRefuse
  ${EndIf}
  StrCpy $5 0
  csq_outcome_create:
    System::Call 'bcrypt::BCryptGenRandom(p 0, p r4, i 16, i 2) i .r0'
    ${If} $0 != 0
      System::Free $4
      StrCpy $CsqFailureMessage "csq installed, not launched; outcome log random name could not be generated. Start csq manually."
      Call CsqRefuse
    ${EndIf}
    StrCpy $1 33
    System::Call 'crypt32::CryptBinaryToStringW(p r4, i 16, i 0x4000000C, w .r0, *i r1) i .r2'
    ${If} $2 == 0
      System::Free $4
      StrCpy $CsqFailureMessage "csq installed, not launched; outcome log random name could not be encoded. Start csq manually."
      Call CsqRefuse
    ${EndIf}
    StrCpy $2 "$CsqPinnedStageParent\install-outcome-$0.txt"
    System::Call 'kernel32::CreateFileW(w r2, i 0x40020080, i 1, p 0, i 1, i 0x80200000, p 0) p .r3 ?e'
    Pop $2
    ${If} $3 == -1
      IntOp $5 $5 + 1
      ${If} $5 < 8
        ${If} $2 == 80
        ${OrIf} $2 == 183
          Goto csq_outcome_create
        ${EndIf}
      ${EndIf}
      System::Free $4
      StrCpy $CsqFailureMessage "csq installed, not launched; outcome log could not be created. Start csq manually."
      Call CsqRefuse
    ${EndIf}
  System::Free $4
  StrCpy $CsqOwnerHandle $3
  Call CsqCheckStageOwner
  ${If} $CsqPinResult != 0
    System::Call 'kernel32::CloseHandle(p r3)'
    StrCpy $CsqFailureMessage "csq installed, not launched; outcome log owner could not be verified. Start csq manually."
    Call CsqRefuse
  ${EndIf}
  StrCpy $1 "csq installed, not launched. Start csq from the Start menu when ready.$\r$\n"
  StrLen $0 $1
  System::Call 'kernel32::WriteFile(p r3, m r1, i r0, *i .r2, p 0) i .r1'
  ${If} $1 == 0
  ${OrIf} $2 != $0
    System::Call 'kernel32::CloseHandle(p r3)'
    StrCpy $CsqFailureMessage "csq installed, not launched; outcome log could not be written. Start csq manually."
    Call CsqRefuse
  ${EndIf}
  System::Call 'kernel32::FlushFileBuffers(p r3) i .r0'
  ${If} $0 == 0
    System::Call 'kernel32::CloseHandle(p r3)'
    StrCpy $CsqFailureMessage "csq installed, not launched; outcome log could not be saved. Start csq manually."
    Call CsqRefuse
  ${EndIf}
  StrCpy $CsqOutcomeFile $3
  Call CsqReleaseVerifiedNamespace
  SetErrorLevel 0
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; ROOTab48589b: after stock installation completes, release then launch normally.
; Controller implementation must check that this transaction owns the live lease.
Function CsqGateLaunch
  ${If} $CsqCommitted != 1
    Call CsqRefuse
  ${EndIf}
  Call CsqGateCommitRelease
  nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" "$CsqLaunchArgs"
  StrCpy $CsqLaunched 1
  DetailPrint "csq installed; launch requested"
FunctionEnd

; Reject command-line delimiters in discovery hints before quoting them. The
; helper separately validates canonical path, ownership, identity, and basenames.
!macro CsqControllerFunctions Prefix
Function ${Prefix}CsqValidateHint
  Push $0
  Push $1
  StrCpy $0 0
  csq_hint_next:
    StrCpy $1 $CsqResult 1 $0
    ${If} $1 == ""
      Goto csq_hint_done
    ${EndIf}
    ${If} $1 == '$\"'
    ${OrIf} $1 == '$\r'
    ${OrIf} $1 == '$\n'
      Call ${Prefix}CsqRefuse
    ${EndIf}
    IntOp $0 $0 + 1
    Goto csq_hint_next
  csq_hint_done:
  StrCpy $1 $CsqResult 1 -1
  ${If} $1 == "\"
    Call ${Prefix}CsqRefuse
  ${EndIf}
  Pop $1
  Pop $0
FunctionEnd

Function ${Prefix}CsqBuildImages
  Push $0
  StrCpy $CsqResult $INSTDIR
  Call ${Prefix}CsqValidateHint
  StrCpy $CsqImages '--image "$INSTDIR\${MAINBINARYNAME}.exe"'
  ReadRegStr $0 SHCTX "${UNINSTKEY}" "MainBinaryName"
  ${If} $0 != ""
    StrCpy $CsqResult $0
    Call ${Prefix}CsqValidateHint
    StrCpy $CsqImages '$CsqImages --image "$INSTDIR\$0"'
  ${EndIf}
  Pop $0
FunctionEnd

; This source requires a 32-bit NSIS host: STARTUPINFOEXW=72 and
; PROCESS_INFORMATION=16. Native compilation must confirm that layout. Direct CreateProcess makes installer the controller's
; parent; nsExec would interpose another process and fail the helper binding.
Function ${Prefix}CsqRunController
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  StrCpy $CsqControllerStillLive 0
  Call ${Prefix}CsqVerifyUnelevated
  Call ${Prefix}CsqVerifyHelper
  ${If} $CsqResult != 0
    Call ${Prefix}CsqRefuse
  ${EndIf}
  StrCpy $CsqResult 1
  StrCpy $CsqReadPipe 0
  StrCpy $CsqWritePipe 0
  StrCpy $CsqStartup 0
  StrCpy $CsqProcessInfo 0
  StrCpy $CsqCapture 0
  StrCpy $CsqProcess 0
  StrCpy $CsqThread 0
  StrCpy $CsqAttributeList 0
  StrCpy $CsqAttributeInitialized 0
  StrCpy $CsqHandleList 0
  StrCpy $CsqInputRead 0
  System::Call '*(i 12, p 0, i 1) p .r0'
  ${If} $0 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $1 0
  StrCpy $2 0
  System::Call 'kernel32::CreatePipe(*p .r1, *p .r2, p r0, i 4096) i .r3'
  System::Free $0
  StrCpy $CsqReadPipe $1
  StrCpy $CsqWritePipe $2
  ${If} $3 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  System::Call 'kernel32::SetHandleInformation(p $CsqReadPipe, i 1, i 0) i .r3'
  ${If} $3 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  ; Valid stdin is an inherited read pipe whose writer is closed (EOF).
  ; Only this read handle and stdout/stderr write handle enter HANDLE_LIST.
  System::Call '*(i 12, p 0, i 1) p .r0'
  ${If} $0 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $1 0
  StrCpy $2 0
  System::Call 'kernel32::CreatePipe(*p .r1, *p .r2, p r0, i 4096) i .r3'
  System::Free $0
  StrCpy $CsqInputRead $1
  ${If} $2 != 0
    System::Call 'kernel32::CloseHandle(p r2)'
  ${EndIf}
  ${If} $3 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $1 0
  System::Call 'kernel32::InitializeProcThreadAttributeList(p 0, i 1, i 0, *i .r1)'
  ${If} $1 == 0
  ${OrIf} $1 > 1048576
    Goto csq_controller_cleanup
  ${EndIf}
  System::Alloc $1
  Pop $CsqAttributeList
  ${If} $CsqAttributeList == 0
    Goto csq_controller_cleanup
  ${EndIf}
  System::Call 'kernel32::InitializeProcThreadAttributeList(p $CsqAttributeList, i 1, i 0, *i r1) i .r3'
  ${If} $3 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $CsqAttributeInitialized 1
  System::Call '*(p $CsqWritePipe, p $CsqInputRead) p .r0'
  StrCpy $CsqHandleList $0
  ${If} $CsqHandleList == 0
    Goto csq_controller_cleanup
  ${EndIf}
  System::Call 'kernel32::UpdateProcThreadAttribute(p $CsqAttributeList, i 0, i 0x20002, p $CsqHandleList, i 8, p 0, p 0) i .r3'
  ${If} $3 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  System::Call '*(i 72, p 0, p 0, p 0, i 0, i 0, i 0, i 0, i 0, i 0, i 0, i 0x100, &i2 0, &i2 0, p 0, p $CsqInputRead, p $CsqWritePipe, p $CsqWritePipe, p $CsqAttributeList) p .r0'
  StrCpy $CsqStartup $0
  System::Call '*(p 0, p 0, i 0, i 0) p .r0'
  StrCpy $CsqProcessInfo $0
  ${If} $CsqStartup == 0
  ${OrIf} $CsqProcessInfo == 0
    Goto csq_controller_cleanup
  ${EndIf}
  ; Executable path is fixed separately from the parsed command line.
  System::Call 'kernel32::CreateProcessW(w "$CsqPinnedHelper", w "$CsqCommand", p 0, p 0, i 1, i 0x08080000, p 0, p 0, p $CsqStartup, p $CsqProcessInfo) i .r3'
  System::Call 'kernel32::CloseHandle(p $CsqWritePipe)'
  StrCpy $CsqWritePipe 0
  ${If} $3 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $CsqControllerStillLive 1
  System::Call '*$CsqProcessInfo(p .r0, p .r1, i .r2, i .r4)'
  StrCpy $CsqProcess $0
  StrCpy $CsqThread $1
  System::Call 'kernel32::WaitForSingleObject(p $CsqProcess, i $CsqTimeout) i .r3'
  ${If} $3 != 0
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $CsqControllerStillLive 0
  System::Call 'kernel32::GetExitCodeProcess(p $CsqProcess, *i .r2) i .r3'
  ${If} $3 == 0
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $5 $2
  System::Call 'kernel32::PeekNamedPipe(p $CsqReadPipe, p 0, i 0, p 0, *i .r2, p 0) i .r3'
  ${If} $3 == 0
  ${OrIf} $2 == 0
  ${OrIf} $2 > 512
    Goto csq_controller_cleanup
  ${EndIf}
  System::Alloc 513
  Pop $CsqCapture
  ${If} $CsqCapture == 0
    Goto csq_controller_cleanup
  ${EndIf}
  System::Call 'kernel32::ReadFile(p $CsqReadPipe, p $CsqCapture, i r2, *i .r1, p 0) i .r3'
  ${If} $3 == 0
  ${OrIf} $1 != $2
    Goto csq_controller_cleanup
  ${EndIf}
  StrCpy $CsqBytesRead $1
  IntOp $0 $CsqCapture + $1
  System::Call '*$0(&i1 0)'
  System::Call '*$CsqCapture(&m512 .r0)'
  ${If} $5 != 0
    ${If} $0 == 'CSQ_INSTALL_V1 REFUSED namespace_directory_reparsed$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED namespace_directory_reparsed$\r$\n'
      StrCpy $CsqFailureMessage "Installation stopped because a csq safety folder is a link or has changed. Check the folder before retrying."
    ${ElseIf} $0 == 'CSQ_INSTALL_V1 REFUSED namespace_filesystem_unsupported$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED namespace_filesystem_unsupported$\r$\n'
      StrCpy $CsqFailureMessage "Installation stopped because your Windows profile is not on a supported NTFS drive."
    ${ElseIf} $0 == 'CSQ_INSTALL_V1 REFUSED foreign_user$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED foreign_user$\r$\n'
      StrCpy $CsqFailureMessage "close csq (or sign in as its user) and rerun"
    ${ElseIf} $0 == 'CSQ_INSTALL_V1 REFUSED legacy_running$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED legacy_running$\r$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED identity_unavailable$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED identity_unavailable$\r$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED drain_refused$\n'
    ${OrIf} $0 == 'CSQ_INSTALL_V1 REFUSED drain_refused$\r$\n'
      StrCpy $CsqFailureMessage "An older csq is running; close it and rerun the installer."
    ${EndIf}
    Goto csq_controller_cleanup
  ${EndIf}
  ${If} $CsqLeaseResponseMode == 2
    ; Pure-query output is ASCII and one exact LF/CRLF-terminated frame.
    ; Read count equality rejects embedded NUL/trailing bytes hidden by strings.
    StrLen $1 '$CsqExpected '
    StrCpy $2 $0 $1
    StrCmpS $2 '$CsqExpected ' 0 csq_controller_cleanup
    StrLen $2 $0
    ${If} $CsqBytesRead != $2
      Goto csq_controller_cleanup
    ${EndIf}
    StrCpy $3 $0 1 -1
    StrCmpS $3 '$\n' 0 csq_controller_cleanup
    IntOp $2 $2 - 1
    StrCpy $3 $0 1 -2
    ${If} $3 == '$\r'
      IntOp $2 $2 - 1
    ${EndIf}
    IntOp $2 $2 - $1
    ${If} $2 <= 10
      Goto csq_controller_cleanup
    ${EndIf}
    StrCpy $CsqExpectedLeaseName $0 $2 $1
    StrCpy $3 $CsqExpectedLeaseName 10
    StrCmpS $3 '\Sessions\' 0 csq_query_name_invalid
    StrCpy $1 0
    csq_query_name_next:
      StrCpy $3 $CsqExpectedLeaseName 1 $1
      ${If} $3 == ""
        StrCpy $CsqResult 0
        Goto csq_controller_cleanup
      ${EndIf}
      ; Reject all control/space characters, including embedded CR/LF/tab.
      System::Call 'kernel32::GetStringTypeW(i 1, w r3, i 1, *i .r4) i .r5'
      ${If} $5 == 0
        Goto csq_query_name_invalid
      ${EndIf}
      IntOp $4 $4 & 0x28
      ${If} $4 != 0
        Goto csq_query_name_invalid
      ${EndIf}
      IntOp $1 $1 + 1
      Goto csq_query_name_next
    csq_query_name_invalid:
      StrCpy $CsqExpectedLeaseName ""
      Goto csq_controller_cleanup
  ${ElseIf} $CsqLeaseResponseMode == 1
    ; The value is an installer-local DuplicateHandle result returned only by
    ; the authenticated direct controller. It is never read from argv/registry.
    StrLen $1 '$CsqExpected 0x'
    StrCpy $2 $0 $1
    StrCmpS $2 '$CsqExpected 0x' 0 csq_lease_not_primary
    StrCpy $CsqLeaseDigits $0 8 $1
    StrLen $2 $CsqLeaseDigits
    ${If} $2 != 8
      Goto csq_controller_cleanup
    ${EndIf}
    ; Exact byte framing rejects NUL suffixes, whitespace and trailing tokens.
    IntOp $2 $1 + 9
    IntOp $3 $1 + 10
    ${If} $CsqBytesRead == $2
      StrCmpS $0 '$CsqExpected 0x$CsqLeaseDigits$\n' csq_lease_framed csq_controller_cleanup
    ${ElseIf} $CsqBytesRead == $3
      StrCmpS $0 '$CsqExpected 0x$CsqLeaseDigits$\r$\n' csq_lease_framed csq_controller_cleanup
    ${Else}
      Goto csq_controller_cleanup
    ${EndIf}
    csq_lease_framed:
    StrCpy $1 0
    csq_lease_hex_next:
      StrCpy $2 $CsqLeaseDigits 1 $1
      ; Plain character comparisons compile in installer AND uninstaller.
      StrCmpS $2 "0" csq_lease_hex_valid
      StrCmpS $2 "1" csq_lease_hex_valid
      StrCmpS $2 "2" csq_lease_hex_valid
      StrCmpS $2 "3" csq_lease_hex_valid
      StrCmpS $2 "4" csq_lease_hex_valid
      StrCmpS $2 "5" csq_lease_hex_valid
      StrCmpS $2 "6" csq_lease_hex_valid
      StrCmpS $2 "7" csq_lease_hex_valid
      StrCmpS $2 "8" csq_lease_hex_valid
      StrCmpS $2 "9" csq_lease_hex_valid
      StrCmpS $2 "A" csq_lease_hex_valid
      StrCmpS $2 "B" csq_lease_hex_valid
      StrCmpS $2 "C" csq_lease_hex_valid
      StrCmpS $2 "D" csq_lease_hex_valid
      StrCmpS $2 "E" csq_lease_hex_valid
      StrCmpS $2 "F" csq_lease_hex_valid
      Goto csq_controller_cleanup
      csq_lease_hex_valid:
      IntOp $1 $1 + 1
      ${If} $1 < 8
        Goto csq_lease_hex_next
      ${EndIf}
    ${If} $CsqLeaseDigits == "00000000"
    ${OrIf} $CsqLeaseDigits == "FFFFFFFF"
      Goto csq_controller_cleanup
    ${EndIf}
    ${If} $CsqInstallerLease != ""
    ${AndIf} $CsqInstallerLease != 0
      Goto csq_controller_cleanup
    ${EndIf}
    StrCpy $CsqLeaseCandidate "0x$CsqLeaseDigits"
    IntFmt $2 "%08X" $CsqLeaseCandidate
    StrCmpS $2 $CsqLeaseDigits 0 csq_controller_cleanup
    System::Call 'kernel32::GetHandleInformation(p $CsqLeaseCandidate, *i .r2) i .r3'
    ${If} $3 == 0
      Goto csq_controller_cleanup
    ${EndIf}
    ; Both inheritance and PROTECT_FROM_CLOSE must be clear for this ref.
    IntOp $2 $2 & 3
    ${If} $2 != 0
      Goto csq_controller_cleanup
    ${EndIf}
    ; Expected name was obtained by the separate pure query before admission.
    ${If} $CsqExpectedLeaseName == ""
      Goto csq_controller_cleanup
    ${EndIf}
    StrCpy $CsqObjectInfoClass 2
    StrCpy $CsqObjectExpected "Mutant"
    Call ${Prefix}CsqCheckLeaseObject
    ${If} $CsqLeaseObjectValid != 1
      Goto csq_controller_cleanup
    ${EndIf}
    StrCpy $CsqObjectInfoClass 1
    StrCpy $CsqObjectExpected $CsqExpectedLeaseName
    Call ${Prefix}CsqCheckLeaseObject
    ${If} $CsqLeaseObjectValid != 1
      Goto csq_controller_cleanup
    ${EndIf}
    StrCpy $CsqInstallerLease $CsqLeaseCandidate
    StrCpy $CsqResult 0
    Goto csq_controller_cleanup
    csq_lease_not_primary:
  ${Else}
    StrLen $1 $CsqExpected
    IntOp $2 $1 + 1
    IntOp $3 $1 + 2
    ${If} $CsqBytesRead == $2
    ${AndIf} $0 == '$CsqExpected$\n'
      StrCpy $CsqResult 0
    ${ElseIf} $CsqBytesRead == $3
    ${AndIf} $0 == '$CsqExpected$\r$\n'
      StrCpy $CsqResult 0
    ${EndIf}
  ${EndIf}
  ${If} $CsqExpectedAlt != ""
    StrLen $1 $CsqExpectedAlt
    IntOp $2 $1 + 1
    IntOp $3 $1 + 2
    ${If} $CsqBytesRead == $2
    ${AndIf} $0 == '$CsqExpectedAlt$\n'
      StrCpy $CsqResult 0
    ${ElseIf} $CsqBytesRead == $3
    ${AndIf} $0 == '$CsqExpectedAlt$\r$\n'
      StrCpy $CsqResult 0
    ${EndIf}
  ${EndIf}
  csq_controller_cleanup:
  ${If} $CsqControllerStillLive != 1
    Call ${Prefix}CsqReleaseVerifiedNamespace
  ${EndIf}
  ${If} $CsqAttributeInitialized == 1
    System::Call 'kernel32::DeleteProcThreadAttributeList(p $CsqAttributeList)'
  ${EndIf}
  ${If} $CsqAttributeList != 0
    System::Free $CsqAttributeList
  ${EndIf}
  ${If} $CsqHandleList != 0
    System::Free $CsqHandleList
  ${EndIf}
  ${If} $CsqInputRead != 0
    System::Call 'kernel32::CloseHandle(p $CsqInputRead)'
  ${EndIf}
  ${If} $CsqReadPipe != 0
    System::Call 'kernel32::CloseHandle(p $CsqReadPipe)'
  ${EndIf}
  ${If} $CsqWritePipe != 0
    System::Call 'kernel32::CloseHandle(p $CsqWritePipe)'
  ${EndIf}
  ${If} $CsqProcess != 0
    System::Call 'kernel32::CloseHandle(p $CsqProcess)'
  ${EndIf}
  ${If} $CsqThread != 0
    System::Call 'kernel32::CloseHandle(p $CsqThread)'
  ${EndIf}
  ${If} $CsqStartup != 0
    System::Free $CsqStartup
  ${EndIf}
  ${If} $CsqProcessInfo != 0
    System::Free $CsqProcessInfo
  ${EndIf}
  ${If} $CsqCapture != 0
    System::Free $CsqCapture
  ${EndIf}
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  ${If} $CsqResult != 0
    ; If the controller is still live, namespace pins survive this dialog until
    ; installer exit. The helper contract requires self-pins before actual
    ; parent validation and through internal broker CreateProcess; otherwise
    ; delayed broker spawn after parent exit remains a BLOCKED custody edge.
    ; Installer exit also closes the broker's retained installer handle lease.
    ; A timed-out controller is not killed to manufacture a successful result.
    Call ${Prefix}CsqRefuse
  ${EndIf}
FunctionEnd

!macroend
!insertmacro CsqControllerFunctions ""
!insertmacro CsqControllerFunctions "un."

Function CsqGateEnsure
  ${If} $CsqRoot != ""
    ${If} $INSTDIR != $CsqRoot
      StrCpy $CsqFailureMessage "The installation directory changed after admission. Rerun the installer with the final directory selected."
      Call CsqRefuse
    ${EndIf}
    Return
  ${EndIf}
  ; S2a gate is synchronous: the wizard may stop repainting while draining.
  ; Moving this onto a worker requires a separate NSIS callback/handle protocol.
  Call CsqStageHelper
  Call CsqExpectedLeaseIdentity
  Call CsqBuildImages
  StrCpy $CsqRoot $INSTDIR
  StrCpy $CsqCommand '$\"$CsqHelper$\" begin --installer-pid $CsqParentPid --install-root $\"$CsqRoot$\" $CsqImages'
  StrCpy $CsqExpectedAlt ""
  StrCpy $CsqLeaseResponseMode 1
  StrCpy $CsqExpected "CSQ_INSTALL_V1 READY"
  ; Observer ceiling only: discovery + three role windows, then refusal.
  StrCpy $CsqTimeout 1217000
  Call CsqRunController
FunctionEnd

!macro CsqGateBoundary Phase
  Call CsqGateEnsure
  Call CsqBuildImages
  StrCpy $CsqCommand '$\"$CsqHelper$\" recheck --installer-pid $CsqParentPid --phase ${Phase} $CsqImages'
  StrCpy $CsqExpectedAlt ""
  StrCpy $CsqLeaseResponseMode 0
  StrCpy $CsqExpected "CSQ_INSTALL_V1 RECHECK_OK ${Phase}"
  StrCpy $CsqTimeout 15000
  Call CsqRunController
!macroend

Function CsqGateCommitRelease
  Push $0
  ${If} $CsqCommitted != 1
  ${OrIf} $INSTDIR != $CsqRoot
  ${OrIf} $CsqInstallerLease == ""
  ${OrIf} $CsqInstallerLease == 0
    Call CsqRefuse
  ${EndIf}
  StrCpy $CsqCommand '$\"$CsqHelper$\" commit-release --installer-pid $CsqParentPid --transaction-committed --rollback-closed'
  StrCpy $CsqExpectedAlt ""
  StrCpy $CsqLeaseResponseMode 0
  StrCpy $CsqExpected "CSQ_INSTALL_V1 RELEASED"
  StrCpy $CsqTimeout 10000
  Call CsqRunController
  ; Only exact RELEASED confirms that the coordinator dropped its own ref.
  ; Our noninherited kernel ref has covered helper death during copy/rollback.
  System::Call 'kernel32::CloseHandle(p $CsqInstallerLease) i .r0'
  ${If} $0 == 0
    Call CsqRefuse
  ${EndIf}
  StrCpy $CsqInstallerLease 0
  Pop $0
FunctionEnd

Function un.CsqGateRefuseIfRunning
  Push $0
  Call un.CsqVerifyUnelevated
  ; Standalone uninstall carries and repairs its own helper payload.
  Call un.CsqStageHelper
  Call un.CsqExpectedLeaseIdentity
  ; The controller authenticates and retains the exact helper before exec.
  System::Call 'kernel32::GetCurrentProcessId() i .r0'
  StrCpy $CsqParentPid $0
  Call un.CsqBuildImages
  StrCpy $CsqCommand '$\"$CsqHelper$\" uninstall-admit --installer-pid $CsqParentPid --install-root $\"$INSTDIR$\" $CsqImages'
  StrCpy $CsqLeaseResponseMode 1
  StrCpy $CsqExpected "CSQ_INSTALL_V1 UNINSTALL_READY"
  StrCpy $CsqExpectedAlt "CSQ_INSTALL_V1 UNINSTALL_REUSE_OK"
  ; Observer ceiling only: discovery + three role windows, then refusal.
  StrCpy $CsqTimeout 1217000
  Call un.CsqRunController
  Pop $0
FunctionEnd
