use super::*;

impl VirtualExecutionEngine {
    /// Rtl*/Nt*/Zw* dispatch — middle batch of match arms (lines 841-1203 of original).
    pub(in crate::runtime::engine) fn dispatch_ntdll_rtl(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        // Validation guard: list all function names from this group
        match function {
            "RtlEraseUnicodeString" | "RtlUpcaseUnicodeString"
            | "RtlDowncaseUnicodeString" | "RtlAppendAnsiStringToString"
            | "RtlUnicodeStringToInteger" | "RtlCharToInteger"
            | "RtlDoesNameContainWildCards"
            | "RtlIsNameInExpression" | "RtlIsNameInUnUpcasedExpression"
            | "RtlIsTextUnicode"
            | "RtlDosPathNameToNtPathName_U"
            | "RtlDosPathNameToNtPathName_U_WithStatus"
            | "RtlDosLongPathNameToNtPathName_U_WithStatus"
            | "RtlDosPathNameToRelativeNtPathName_U"
            | "RtlDosPathNameToRelativeNtPathName_U_WithStatus"
            | "RtlDosLongPathNameToRelativeNtPathName_U_WithStatus"
            | "RtlNtPathNameToDosPathName"
            | "RtlGetCurrentDirectory_U" | "RtlSetCurrentDirectory_U"
            | "RtlGetFullPathName_U" | "RtlGetFullPathName_UEx"
            | "RtlGetFullPathName_UstrEx"
            | "RtlMultiByteToUnicodeN" | "RtlUnicodeToMultiByteN"
            | "RtlUTF8ToUnicodeN" | "RtlUnicodeToUTF8N"
            | "RtlOemStringToUnicodeString" | "RtlUnicodeStringToOemString"
            | "RtlMultiByteToUnicodeSize" | "RtlUnicodeToMultiByteSize"
            | "RtlOemToUnicodeN" | "RtlUnicodeToOemN"
            | "RtlUpcaseUnicodeToMultiByteN" | "RtlUpcaseUnicodeToOemN"
            | "RtlConsoleMultiByteToUnicodeN"
            | "RtlCreateProcessParametersEx" | "RtlCreateProcessParameters"
            | "RtlCreateProcessParametersWithTemplate" | "RtlDestroyProcessParameters"
            | "RtlNormalizeProcessParams" | "RtlDeNormalizeProcessParams"
            | "RtlCreateEnvironment" | "RtlCreateEnvironmentEx"
            | "RtlDestroyEnvironment" | "RtlSetEnvironmentVariable"
            | "RtlQueryEnvironmentVariable" | "RtlExpandEnvironmentStrings"
            | "RtlExpandEnvironmentStrings_U"
            | "RtlAddVectoredContinueHandler" | "RtlRemoveVectoredContinueHandler"
            | "RtlSetUnhandledExceptionFilter" | "RtlUnhandledExceptionFilter2"
            | "RtlUnhandledExceptionFilter" | "RtlRaiseException" | "RtlRaiseStatus"
            | "RtlCaptureStackBackTrace"
            | "RtlSubAuthorityCountSid" | "RtlSubAuthoritySid"
            | "NtAccessCheck" | "ZwAccessCheck"
            | "NtAccessCheckAndAuditAlarm" | "ZwAccessCheckAndAuditAlarm"
            | "NtQuerySecurityObject" | "ZwQuerySecurityObject"
            | "NtSetSecurityObject" | "ZwSetSecurityObject"
            | "NtPrivilegeCheck" | "ZwPrivilegeCheck"
            | "NtImpersonateClientOfPort" | "ZwImpersonateClientOfPort"
            | "RtlImpersonateSelf" | "RtlImpersonateSelfEx" | "RtlRevertToSelf"
            | "NtQuerySystemTime" | "ZwQuerySystemTime"
            | "NtQueryInstallTimeStamp"
            | "NtGetCurrentProcessorNumber" | "ZwGetCurrentProcessorNumber"
            | "NtSetTimerResolution" | "ZwSetTimerResolution"
            | "NtQueryDefaultLocale" | "ZwQueryDefaultLocale"
            | "NtQueryDefaultUILanguage" | "ZwQueryDefaultUILanguage"
            | "NtQueryInstallUILanguage" | "ZwQueryInstallUILanguage"
            | "NtPowerInformation" | "ZwPowerInformation"
            | "NtDisplayString" | "ZwDisplayString"
            | "NtCreatePort" | "ZwCreatePort"
            | "NtCreateWaitablePort" | "ZwCreateWaitablePort"
            | "NtListenPort" | "ZwListenPort"
            | "NtAcceptConnectPort" | "ZwAcceptConnectPort"
            | "NtCompleteConnectPort" | "ZwCompleteConnectPort"
            | "NtRequestPort" | "ZwRequestPort"
            | "NtRequestWaitReplyPort" | "ZwRequestWaitReplyPort"
            | "NtReplyPort" | "ZwReplyPort"
            | "NtReplyWaitReplyPort" | "ZwReplyWaitReplyPort"
            | "NtReplyWaitReceivePort" | "ZwReplyWaitReceivePort"
            | "NtReplyWaitReceivePortEx" | "ZwReplyWaitReceivePortEx"
            | "NtConnectPort" | "ZwConnectPort"
            | "NtSecureConnectPort" | "ZwSecureConnectPort"
            | "NtCreateTransaction" | "ZwCreateTransaction"
            | "NtOpenTransaction" | "ZwOpenTransaction"
            | "NtCommitTransaction" | "ZwCommitTransaction"
            | "NtRollbackTransaction" | "ZwRollbackTransaction"
            | "NtCreateTransactionManager" | "ZwCreateTransactionManager"
            | "NtOpenTransactionManager" | "ZwOpenTransactionManager"
            | "NtCreateResourceManager" | "ZwCreateResourceManager"
            | "NtOpenResourceManager" | "ZwOpenResourceManager"
            | "NtCreateEnlistment" | "ZwCreateEnlistment"
            | "NtOpenEnlistment" | "ZwOpenEnlistment"
            | "NtQueryWnfStateData" | "ZwQueryWnfStateData"
            | "NtUpdateWnfStateData" | "ZwUpdateWnfStateData"
            | "NtLoadDriver" | "ZwLoadDriver"
            | "NtUnloadDriver" | "ZwUnloadDriver"
            | "NtApphelpCacheControl" | "ZwApphelpCacheControl"
            | "NtAssociateWaitCompletionPacket" | "ZwAssociateWaitCompletionPacket"
            | "NtCancelWaitCompletionPacket" | "ZwCancelWaitCompletionPacket"
            // ── Remaining Nt/Zw stubs (iteration 3 batch) ──────────
            | "NtAccessCheckByType" | "NtAccessCheckByTypeAndAuditAlarm"
            | "NtAccessCheckByTypeResultList" | "NtAcquireCrossVmMutant"
            | "NtAcquireProcessActivityReference" | "NtAddAtom"
            | "NtAddAtomEx" | "NtAddBootEntry"
            | "NtAddDriverEntry" | "NtAdjustGroupsToken"
            | "NtAdjustTokenClaimsAndDeviceGroups" | "NtAlertThreadByThreadId"
            | "NtAllocateReserveObject" | "NtAllocateUserPhysicalPages"
            | "NtAllocateUserPhysicalPagesEx" | "NtCallbackReturn"
            | "NtCallEnclave" | "NtCancelSynchronousIo"
            | "NtCancelSynchronousIoFile" | "NtCancelTimer2"
            | "NtChangeWnfStateData" | "NtCloseObjectAuditAlarm"
            | "NtCommitComplete" | "NtCommitEnlistment"
            | "NtCommitRegistryTransaction" | "NtCompareObjects"
            | "NtCompareSigningLevels" | "NtCompareTokens"
            | "NtConnectNamedPipe" | "NtContinueEx"
            | "NtCopyFileChunk" | "NtCreateCrossVmEvent"
            | "NtCreateCrossVmMutant" | "NtCreateEnclave"
            | "NtCreateIRTimer" | "NtCreateJobSet"
            | "NtCreateKeyedEvent" | "NtCreateLowBoxToken"
            | "NtCreatePartition" | "NtCreatePrivateNamespace"
            | "NtCreateProfile" | "NtCreateProfileEx"
            | "NtCreateRegistryTransaction" | "NtCreateSectionEx"
            | "NtCreateTimer2" | "NtCreateToken"
            | "NtCreateTokenEx" | "NtCreateWaitCompletionPacket"
            | "NtCreateWnfStateName" | "NtCreateWorkerFactory"
            | "NtDeleteAtom" | "NtDeleteBootEntry"
            | "NtDeleteDriverEntry" | "NtDeleteObjectAuditAlarm"
            | "NtDeletePrivateNamespace" | "NtDeleteWnfStateData"
            | "NtDeleteWnfStateName" | "NtDirectGraphicsCall"
            | "NtDisableLastKnownGood" | "NtdllDefWindowProc_A"
            | "NtdllDefWindowProc_W" | "NtdllDialogWndProc_A"
            | "NtdllDialogWndProc_W" | "NtDrawText"
            | "NtEnableLastKnownGood" | "NtEnumerateBootEntries"
            | "NtEnumerateDriverEntries" | "NtEnumerateSystemEnvironmentValuesEx"
            | "NtEnumerateTransactionObject" | "NtFilterBootOption"
            | "NtFilterToken" | "NtFilterTokenEx"
            | "NtFindAtom" | "NtFlushInstallUILanguage"
            | "NtFlushInstructionCache" | "NtFlushProcessWriteBuffers"
            | "NtFlushWriteBuffer" | "NtFreeUserPhysicalPages"
            | "NtFreezeRegistry" | "NtFreezeTransactions"
            | "NtGetCachedSigningLevel" | "NtGetCompleteWnfStateSubscription"
            | "NtGetCurrentProcessorNumberEx" | "NtGetDevicePowerState"
            | "NtGetMUIRegistryInfo" | "NtGetNlsSectionPtr"
            | "NtGetNotificationResourceManager" | "NtInitializeEnclave"
            | "NtInitializeNlsFiles" | "NtInitializeRegistry"
            | "NtInitiatePowerAction" | "NtIsSystemResumeAutomatic"
            | "NtIsUILanguageComitted" | "NtLoadEnclaveData"
            | "NtLockProductActivationKeys" | "NtManageHotPatch"
            | "NtManagePartition" | "NtMapCMFModule"
            | "NtMapUserPhysicalPages" | "NtMapUserPhysicalPagesScatter"
            | "NtModifyBootEntry" | "NtModifyDriverEntry"
            | "NtNotifyChangeDirectoryFileEx" | "NtNotifyChangeSession"
            | "NtOpenObjectAuditAlarm" | "NtOpenPartition"
            | "NtOpenPrivateNamespace" | "NtOpenRegistryTransaction"
            | "NtOpenSession" | "NtPlugPlayControl"
            | "NtPrepareComplete" | "NtPrepareEnlistment"
            | "NtPrePrepareComplete" | "NtPrePrepareEnlistment"
            | "NtPrivilegedServiceAuditAlarm" | "NtPrivilegeObjectAuditAlarm"
            | "NtPropagationComplete" | "NtPropagationFailed"
            | "NtPssCaptureVaSpaceBulk" | "NtQueryAuxiliaryCounterFrequency"
            | "NtQueryBootEntryOrder" | "NtQueryBootOptions"
            | "NtQueryDebugFilterState" | "NtQueryDriverEntryOrder"
            | "NtQueryInformationAtom" | "NtQueryInformationEnlistment"
            | "NtQueryInformationPort" | "NtQueryInformationResourceManager"
            | "NtQueryInformationTransaction" | "NtQueryInformationTransactionManager"
            | "NtQueryInformationWorkerFactory" | "NtQueryIntervalProfile"
            | "NtQueryIoCompletion" | "NtQueryPortInformationProcess"
            | "NtQuerySecurityAttributesToken" | "NtQuerySecurityPolicy"
            | "NtQuerySystemEnvironmentValue" | "NtQuerySystemEnvironmentValueEx"
            | "NtQueryWnfStateNameInformation" | "NtQueueApcThreadEx"
            | "NtQueueApcThreadEx2" | "NtRaiseException"
            | "NtRaiseHardError" | "NtReadOnlyEnlistment"
            | "NtReadRequestData" | "NtRecoverEnlistment"
            | "NtRecoverResourceManager" | "NtRecoverTransactionManager"
            | "NtRegisterProtocolAddressInformation" | "NtRegisterThreadTerminatePort"
            | "NtReleaseWorkerFactoryWorker" | "NtRemoveIoCompletionEx"
            | "NtRenameTransactionManager" | "NtReplacePartitionUnit"
            | "NtResumeProcess" | "NtRevertContainerImpersonation"
            | "NtRollbackComplete" | "NtRollbackEnlistment"
            | "NtRollbackRegistryTransaction" | "NtRollforwardTransactionManager"
            | "NtSerializeBoot" | "NtSetBootEntryOrder"
            | "NtSetBootOptions" | "NtSetCachedSigningLevel"
            | "NtSetCachedSigningLevel2" | "NtSetDebugFilterState"
            | "NtSetDefaultHardErrorPort" | "NtSetDefaultLocale"
            | "NtSetDefaultUILanguage" | "NtSetDriverEntryOrder"
            | "NtSetEventBoostPriority" | "NtSetHighEventPair"
            | "NtSetHighWaitLowEventPair" | "NtSetInformationEnlistment"
            | "NtSetInformationKey" | "NtSetInformationObject"
            | "NtSetInformationResourceManager" | "NtSetInformationSymbolicLink"
            | "NtSetInformationToken" | "NtSetInformationTransaction"
            | "NtSetInformationTransactionManager" | "NtSetInformationVirtualMemory"
            | "NtSetInformationWorkerFactory" | "NtSetIntervalProfile"
            | "NtSetIoCompletionEx" | "NtSetIRTimer"
            | "NtSetLdtEntries" | "NtSetLowEventPair"
            | "NtSetLowWaitHighEventPair" | "NtSetSystemEnvironmentValue"
            | "NtSetSystemEnvironmentValueEx" | "NtSetSystemPowerState"
            | "NtSetSystemTime" | "NtSetThreadExecutionState"
            | "NtSetTimer2" | "NtSetUuidSeed"
            | "NtSetWnfProcessNotificationEvent" | "NtShutdownSystem"
            | "NtShutdownWorkerFactory" | "NtSinglePhaseReject"
            | "NtStartProfile" | "NtStopProfile"
            | "NtSubscribeWnfStateChange" | "NtSuspendProcess"
            | "NtSystemDebugControl" | "NtTerminateEnclave"
            | "NtThawRegistry" | "NtThawTransactions"
            | "NtTranslateFilePath" | "NtUmsThreadYield"
            | "NtUnsubscribeWnfStateChange" | "NtVdmControl"
            | "NtWaitForAlertByThreadId" | "NtWaitForMultipleObjects32"
            | "NtWaitForWorkViaWorkerFactory" | "NtWaitHighEventPair"
            | "NtWaitLowEventPair" | "NtWorkerFactoryCreate"
            | "NtWorkerFactoryReady" | "NtWorkerFactoryRelease"
            | "NtWorkerFactoryShutdown" | "NtWorkerFactoryWait"
            | "NtWorkerFactoryWorkerReady" | "NtWriteRequestData"
            | "NtYieldExecution"
            // ALPC Nt* stubs
            | "NtAlpcAcceptConnectPort" | "NtAlpcCancelMessage"
            | "NtAlpcConnectPort" | "NtAlpcConnectPortEx"
            | "NtAlpcCreatePort" | "NtAlpcCreatePortSection"
            | "NtAlpcCreateResourceReserve" | "NtAlpcCreateSectionView"
            | "NtAlpcCreateSecurityContext" | "NtAlpcDeletePortSection"
            | "NtAlpcDeleteResourceReserve" | "NtAlpcDeleteSectionView"
            | "NtAlpcDeleteSecurityContext" | "NtAlpcDisconnectPort"
            | "NtAlpcImpersonateClientContainerOfPort" | "NtAlpcImpersonateClientOfPort"
            | "NtAlpcOpenSenderProcess" | "NtAlpcOpenSenderThread"
            | "NtAlpcQueryInformation" | "NtAlpcQueryInformationMessage"
            | "NtAlpcRevokeSecurityContext" | "NtAlpcSendWaitReceivePort"
            | "NtAlpcSetInformation"
            // Remaining Zw* stubs
            | "ZwAlertThreadByThreadId" | "ZwCancelTimer2"
            | "ZwClose" | "ZwDuplicateObject"
            | "ZwGetTickCount" | "ZwRemoveProcessDebug"
            | "ZwSetTimer2" | "ZwWaitForAlertByThreadId"
            // ── Remaining Rtl stubs (iteration 3 batch) ────────────
            | "RtlAbsoluteToSelfRelativeSD" | "RtlAddAccessAllowedAce"
            | "RtlAddAccessAllowedAceEx" | "RtlAddAccessAllowedObjectAce"
            | "RtlAddAccessDeniedAce" | "RtlAddAccessDeniedAceEx"
            | "RtlAddAccessDeniedObjectAce" | "RtlAddAce"
            | "RtlAddAuditAccessAce" | "RtlAddAuditAccessAceEx"
            | "RtlAddAuditAccessObjectAce" | "RtlAddCompoundAce"
            | "RtlAddIntegrityLabelToBoundaryDescriptor" | "RtlAddMandatoryAce"
            | "RtlAddRefMemoryStream" | "RtlAddSIDToBoundaryDescriptor"
            | "RtlAllocateAndInitializeSID" | "RtlAllocateMemoryBlockLookaside"
            | "RtlAllocateMemoryZone" | "RtlAnsiCharToUnicodeChar"
            | "RtlAppendAsciizToString" | "RtlApplyLengthToAcl"
            | "RtlAreAllAccessesGranted" | "RtlAreAnyAccessesGranted"
            | "RtlAreBitsClear" | "RtlAreBitsSet"
            | "RtlAssert" | "RtlBackupEventLog"
            | "RtlBindImageUntrusted" | "RtlBitTestAndComplement"
            | "RtlBitTestAndReset" | "RtlBitTestAndSet"
            | "RtlCrc64" | "RtlCreateAcl"
            | "RtlCreateAndSetSD" | "RtlCreateAtomTable"
            | "RtlCreateRegistryKey" | "RtlCreateSecurityDescriptor"
            | "RtlCreateServiceSid" | "RtlCreateSystemVolumeInformationFolder"
            | "RtlCreateTagHeap" | "RtlCreateTimer"
            | "RtlCreateUserProcess" | "RtlCreateUserSecurityObject"
            | "RtlCreateVirtualAccountSid" | "RtlCustomCPToUnicodeN"
            | "RtlDecompressBufferEx" | "RtlDecompressFragment"
            | "RtlDefaultNpAcl" | "RtlDelete"
            | "RtlDeleteAce" | "RtlDeleteAtomFromAtomTable"
            | "RtlDeleteAtomTable" | "RtlDeleteBoundaryDescriptor"
            | "RtlDeleteElementGenericTableAvl" | "RtlDeleteRegistryValue"
            | "RtlDeleteResource" | "RtlDeleteSecurityObject"
            | "RtlDeleteTimer" | "RtlDeleteTimerQueue"
            | "RtlDeleteTimerQueueEx" | "RtlDeregisterWait"
            | "RtlDestroyMemoryBlockLookaside"
            | "RtlDetermineDosPathNameType" | "RtlDetermineDosPathNameType_U"
            | "RtlDisableThreadProfiling" | "RtlDosLongPathToNtPathPath_U_WithStatus"
            | "RtlDosSearchPath_U" | "RtlDosSearchPath_Ustr"
            | "RtlDowncaseUnicodeChar" | "RtlDumpResource"
            | "RtlEnableThreadProfiling" | "RtlEnlargedIntegerMultiply"
            | "RtlEnlargedUnsignedDivide" | "RtlEnlargedUnsignedMultiply"
            | "RtlEnumerateEntryHashTable" | "RtlEqualComputerName"
            | "RtlEqualDomainName"

            | "RtlExtendedIntegerMultiply" | "RtlExtendedLargeIntegerDivide"
            | "RtlFillMemoryUlong" | "RtlFillMemoryUlonglong"
            | "RtlFindClearBits" | "RtlFindClearBitsAndSet"
            | "RtlFindClearRuns" | "RtlFindFirstRunClear"
            | "RtlFindLastBackwardRunClear" | "RtlFindLongestRunClear"
            | "RtlFindMessage" | "RtlFindNextForwardRunClear"
            | "RtlFindSetBits" | "RtlFindSetBitsAndClear"
            | "RtlFormatCurrentUserKeyPath" | "RtlFormatMessage"
            | "RtlFormatMessageEx" | "RtlFreeMemoryBlockLookaside"
            | "RtlFreeThreadExecutionEnvironment" | "RtlFreeUserThreadStack"
            | "RtlGenerate8dot3Name" | "RtlGetAce"
            | "RtlGetAclInformation" | "RtlGetControlSecurityDescriptor"
            | "RtlGetDaclSecurityDescriptor" | "RtlGetElementGenericTable"
            | "RtlGetElementGenericTableAvl" | "RtlGetFirstEntryHashTable"
            | "RtlGetFrame" | "RtlGetGroupSecurityDescriptor"
            | "RtlGetIntegerAtom" | "RtlGetLengthWithoutLastFullOrBackSlash"
            | "RtlGetLengthWithoutTrailingPathSeperators" | "RtlGetLongestNtPathLength"
            | "RtlGetNativeSystemInformation" | "RtlGetNextEntryHashTable"
            | "RtlGetNtGlobalFlags" | "RtlGetNtProductType"
            | "RtlGetNtVersionNumbers" | "RtlGetOwnerSecurityDescriptor"
            | "RtlGetProcessHeaps" | "RtlGetSaclSecurityDescriptor"
            | "RtlGetSecurityDescriptorRMControl" | "RtlGetSetBootStatusData"
            | "RtlGetSuiteMask" | "RtlGetThreadErrorMode"
            | "RtlIdentifierAuthoritySid" | "RtlImageDirectoryEntryToData"
            | "RtlImageNtHeader" | "RtlImageRvaToSection"
            | "RtlImageRvaToVa" | "RtlInitAnsiStringEx"
            | "RtlInitializeBitMap" | "RtlInitializeContext"
            | "RtlInitializeGenericTable" | "RtlInitializeGenericTableAvl"
            | "RtlInitializeHandleTable" | "RtlInitializeResource"
            | "RtlInitializeSID" | "RtlInitializeSListHead"
                // Bool32 stubs — moved from ntdll_stubs
                | "RtlValidSecurityDescriptor" | "RtlValidRelativeSecurityDescriptor"
                | "RtlValidSid" | "RtlValidAcl" | "RtlValidateHeap"
                | "RtlPrefixString" | "RtlPrefixUnicodeString"
                | "RtlCancelTimer" | "RtlLockHeap" | "RtlUnlockHeap"
                | "TpIsTimerSet"
                // CRT functions forwarded from ntdll (pointer returns)
                | "memcpy" | "memmove" | "memset"
                | "wmemcpy" | "wmemmove" | "wmemset"
                | "strcpy" | "strncpy" | "wcscpy" | "wcsncpy"
                | "strcat" | "strncat" | "wcscat" | "wcsncat"
                | "strchr" | "strrchr" | "wcschr" | "wcsrchr"
                | "strstr" | "wcsstr" | "strpbrk" | "wcspbrk"
                | "memchr" | "wmemchr" | "strrev" | "strset"
                | "itoa" | "ltoa" | "ultoa" | "bsearch"
                // SList / Heap / misc pointer returns
                | "RtlFirstEntrySList" | "RtlInterlockedPopEntrySList"
                | "RtlInterlockedPushEntrySList" | "RtlReAllocateHeap"
                | "RtlCreateQueryDebugBuffer" | "RtlIpv6AddressToStringA"
                | "RtlLocateExtendedFeature" | "RtlLocateLegacyContext"
            => {}
            _ => return None,
        }
        Some((|| -> Result<u64, VmError> {
            match function {
                "RtlEraseUnicodeString" => {
                    // Zero the UNICODE_STRING
                    if ctx.raw(0) != 0 {
                        self.write_unicode_string_descriptor(ctx.raw(0), 0, 0, 0)?;
                    }
                    Ok(0)
                }
                "RtlUpcaseUnicodeString" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlDowncaseUnicodeString" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlAppendAnsiStringToString" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlUnicodeStringToInteger" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlCharToInteger" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlDoesNameContainWildCards" => {
                    Ok(0)
                }
                "RtlIsNameInExpression" | "RtlIsNameInUnUpcasedExpression" => {
                    Ok(1) // always match for emulation
                }
                "RtlIsTextUnicode" => {
                    Ok(1) // assume unicode
                }
                "RtlDosPathNameToNtPathName_U"
                | "RtlDosPathNameToNtPathName_U_WithStatus"
                | "RtlDosLongPathNameToNtPathName_U_WithStatus"
                | "RtlDosPathNameToRelativeNtPathName_U"
                | "RtlDosPathNameToRelativeNtPathName_U_WithStatus"
                | "RtlDosLongPathNameToRelativeNtPathName_U_WithStatus" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlNtPathNameToDosPathName" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlGetCurrentDirectory_U"
                | "RtlSetCurrentDirectory_U"
                | "RtlGetFullPathName_U"
                | "RtlGetFullPathName_UEx"
                | "RtlGetFullPathName_UstrEx" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlMultiByteToUnicodeN" | "RtlUnicodeToMultiByteN"
                | "RtlUTF8ToUnicodeN" | "RtlUnicodeToUTF8N"
                | "RtlOemStringToUnicodeString"
                | "RtlUnicodeStringToOemString"
                | "RtlMultiByteToUnicodeSize"
                | "RtlUnicodeToMultiByteSize"
                | "RtlOemToUnicodeN"
                | "RtlUnicodeToOemN"
                | "RtlUpcaseUnicodeToMultiByteN"
                | "RtlUpcaseUnicodeToOemN"
                | "RtlConsoleMultiByteToUnicodeN" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Process parameters / environment ─────────────────────
                "RtlCreateProcessParametersEx"
                | "RtlCreateProcessParameters"
                | "RtlCreateProcessParametersWithTemplate"
                | "RtlDestroyProcessParameters"
                | "RtlNormalizeProcessParams"
                | "RtlDeNormalizeProcessParams"
                | "RtlCreateEnvironment"
                | "RtlCreateEnvironmentEx"
                | "RtlDestroyEnvironment"
                | "RtlSetEnvironmentVariable"
                | "RtlQueryEnvironmentVariable"
                | "RtlExpandEnvironmentStrings"
                | "RtlExpandEnvironmentStrings_U" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Vectored exception / security ─────────────────────────
                "RtlAddVectoredContinueHandler" => {
                    Ok(self.register_vectored_exception_handler(ctx.raw(0) != 0, ctx.raw(1)))
                }
                "RtlRemoveVectoredContinueHandler" => {
                    Ok(self.remove_vectored_exception_handler(ctx.raw(0) as u32) as u64)
                }
                "RtlSetUnhandledExceptionFilter"
                | "RtlUnhandledExceptionFilter2"
                | "RtlUnhandledExceptionFilter"
                | "RtlRaiseException"
                | "RtlRaiseStatus" => {
                    Ok(0)
                }
                "RtlCaptureStackBackTrace" => {
                    Ok(0)
                }
                // SID field accessors — return pointers into the SID structure
                "RtlSubAuthorityCountSid" => {
                    Ok(ctx.raw(0).saturating_add(1))
                }
                "RtlSubAuthoritySid" => {
                    let sid = ctx.raw(0);
                    let index = ctx.raw(1);
                    Ok(sid.wrapping_add(8).wrapping_add(index.wrapping_mul(4)))
                }
                "NtAccessCheck" | "ZwAccessCheck"
                | "NtAccessCheckAndAuditAlarm" | "ZwAccessCheckAndAuditAlarm"
                | "NtQuerySecurityObject" | "ZwQuerySecurityObject"
                | "NtSetSecurityObject" | "ZwSetSecurityObject"
                | "NtPrivilegeCheck" | "ZwPrivilegeCheck"
                | "NtImpersonateClientOfPort" | "ZwImpersonateClientOfPort"
                | "RtlImpersonateSelf" | "RtlImpersonateSelfEx"
                | "RtlRevertToSelf" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── System time/info ──────────────────────────────────────
                "NtQuerySystemTime" | "ZwQuerySystemTime"
                | "NtQueryInstallTimeStamp"
                | "NtGetCurrentProcessorNumber" | "ZwGetCurrentProcessorNumber"
                | "NtSetTimerResolution" | "ZwSetTimerResolution"
                | "NtQueryDefaultLocale" | "ZwQueryDefaultLocale"
                | "NtQueryDefaultUILanguage" | "ZwQueryDefaultUILanguage"
                | "NtQueryInstallUILanguage" | "ZwQueryInstallUILanguage"
                | "NtPowerInformation" | "ZwPowerInformation"
                | "NtDisplayString" | "ZwDisplayString" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── ALPC / Port / LPC stubs ──────────────────────────────
                "NtCreatePort" | "ZwCreatePort"
                | "NtCreateWaitablePort" | "ZwCreateWaitablePort"
                | "NtListenPort" | "ZwListenPort"
                | "NtAcceptConnectPort" | "ZwAcceptConnectPort"
                | "NtCompleteConnectPort" | "ZwCompleteConnectPort"
                | "NtRequestPort" | "ZwRequestPort"
                | "NtRequestWaitReplyPort" | "ZwRequestWaitReplyPort"
                | "NtReplyPort" | "ZwReplyPort"
                | "NtReplyWaitReplyPort" | "ZwReplyWaitReplyPort"
                | "NtReplyWaitReceivePort" | "ZwReplyWaitReceivePort"
                | "NtReplyWaitReceivePortEx" | "ZwReplyWaitReceivePortEx"
                | "NtConnectPort" | "ZwConnectPort"
                | "NtSecureConnectPort" | "ZwSecureConnectPort" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Transaction / WNF / misc ─────────────────────────────
                "NtCreateTransaction" | "ZwCreateTransaction"
                | "NtOpenTransaction" | "ZwOpenTransaction"
                | "NtCommitTransaction" | "ZwCommitTransaction"
                | "NtRollbackTransaction" | "ZwRollbackTransaction"
                | "NtCreateTransactionManager" | "ZwCreateTransactionManager"
                | "NtOpenTransactionManager" | "ZwOpenTransactionManager"
                | "NtCreateResourceManager" | "ZwCreateResourceManager"
                | "NtOpenResourceManager" | "ZwOpenResourceManager"
                | "NtCreateEnlistment" | "ZwCreateEnlistment"
                | "NtOpenEnlistment" | "ZwOpenEnlistment"
                | "NtQueryWnfStateData" | "ZwQueryWnfStateData"
                | "NtUpdateWnfStateData" | "ZwUpdateWnfStateData"
                | "NtLoadDriver" | "ZwLoadDriver"
                | "NtUnloadDriver" | "ZwUnloadDriver"
                | "NtApphelpCacheControl" | "ZwApphelpCacheControl"
                | "NtAssociateWaitCompletionPacket" | "ZwAssociateWaitCompletionPacket"
                | "NtCancelWaitCompletionPacket" | "ZwCancelWaitCompletionPacket" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Bool32 stubs: return TRUE (1) ─────────────────────
                "RtlEqualPrefixSid"
                | "RtlPrefixString" | "RtlPrefixUnicodeString"
                | "RtlCancelTimer" | "RtlLockHeap" | "RtlUnlockHeap"
                | "RtlValidSecurityDescriptor" | "RtlValidRelativeSecurityDescriptor"
                | "RtlValidSid" | "RtlValidAcl" | "RtlValidateHeap" => {
                    Ok(1) // TRUE
                }
                "TpIsTimerSet" => {
                    Ok(0) // FALSE: timer is not set, safe default
                }
                // ── Pointer-copy stubs: return destination pointer ───
                "memcpy" | "memmove" | "memset"
                | "wmemcpy" | "wmemmove" | "wmemset"
                | "strcpy" | "strncpy" | "wcscpy" | "wcsncpy"
                | "strcat" | "strncat" | "wcscat" | "wcsncat"
                | "itoa" | "ltoa" | "ultoa"
                | "RtlReAllocateHeap" | "RtlIpv6AddressToStringA" => {
                    Ok(ctx.raw(0)) // return destination/buffer pointer
                }
                "RtlDestroyHeap" => {
                    Ok(ctx.raw(0)) // return HeapHandle (arg0)
                }
                // ── SList stubs: return 0 = empty list ───────────────
                "RtlFirstEntrySList" | "RtlInterlockedPopEntrySList"
                | "RtlInterlockedPushEntrySList" => {
                    Ok(0) // NULL = empty list, safe default
                }
                // ── Search stubs: return NULL = not found ────────────
                "strchr" | "strrchr" | "wcschr" | "wcsrchr"
                | "strstr" | "wcsstr" | "strpbrk" | "wcspbrk"
                | "memchr" | "wmemchr" | "strrev" | "strset"
                | "bsearch" | "RtlCreateQueryDebugBuffer"
                | "RtlLocateExtendedFeature" | "RtlLocateLegacyContext" => {
                    Ok(0) // NULL = not found / safe default
                }

                // ── Remaining Nt/Zw stubs (iteration 3 batch) ──────────────
                "NtAccessCheckByType" | "NtAccessCheckByTypeAndAuditAlarm"
                | "NtAccessCheckByTypeResultList" | "NtAcquireCrossVmMutant"
                | "NtAcquireProcessActivityReference" | "NtAddAtom"
                | "NtAddAtomEx" | "NtAddBootEntry"
                | "NtAddDriverEntry" | "NtAdjustGroupsToken"
                | "NtAdjustTokenClaimsAndDeviceGroups" | "NtAlertThreadByThreadId"
                | "NtAllocateReserveObject" | "NtAllocateUserPhysicalPages"
                | "NtAllocateUserPhysicalPagesEx" | "NtCallbackReturn"
                | "NtCallEnclave" | "NtCancelSynchronousIo"
                | "NtCancelSynchronousIoFile" | "NtCancelTimer2"
                | "NtChangeWnfStateData" | "NtCloseObjectAuditAlarm"
                | "NtCommitComplete" | "NtCommitEnlistment"
                | "NtCommitRegistryTransaction" | "NtCompareObjects"
                | "NtCompareSigningLevels" | "NtCompareTokens"
                | "NtConnectNamedPipe" | "NtContinueEx"
                | "NtCopyFileChunk" | "NtCreateCrossVmEvent"
                | "NtCreateCrossVmMutant" | "NtCreateEnclave"
                | "NtCreateIRTimer" | "NtCreateJobSet"
                | "NtCreateKeyedEvent" | "NtCreateLowBoxToken"
                | "NtCreatePartition" | "NtCreatePrivateNamespace"
                | "NtCreateProfile" | "NtCreateProfileEx"
                | "NtCreateRegistryTransaction" | "NtCreateSectionEx"
                | "NtCreateTimer2" | "NtCreateToken"
                | "NtCreateTokenEx" | "NtCreateWaitCompletionPacket"
                | "NtCreateWnfStateName" | "NtCreateWorkerFactory"
                | "NtDeleteAtom" | "NtDeleteBootEntry"
                | "NtDeleteDriverEntry" | "NtDeleteObjectAuditAlarm"
                | "NtDeletePrivateNamespace" | "NtDeleteWnfStateData"
                | "NtDeleteWnfStateName" | "NtDirectGraphicsCall"
                | "NtDisableLastKnownGood" | "NtdllDefWindowProc_A"
                | "NtdllDefWindowProc_W" | "NtdllDialogWndProc_A"
                | "NtdllDialogWndProc_W" | "NtDrawText"
                | "NtEnableLastKnownGood" | "NtEnumerateBootEntries"
                | "NtEnumerateDriverEntries" | "NtEnumerateSystemEnvironmentValuesEx"
                | "NtEnumerateTransactionObject" | "NtFilterBootOption"
                | "NtFilterToken" | "NtFilterTokenEx"
                | "NtFindAtom" | "NtFlushInstallUILanguage"
                | "NtFlushInstructionCache" | "NtFlushProcessWriteBuffers"
                | "NtFlushWriteBuffer" | "NtFreeUserPhysicalPages"
                | "NtFreezeRegistry" | "NtFreezeTransactions"
                | "NtGetCachedSigningLevel" | "NtGetCompleteWnfStateSubscription"
                | "NtGetCurrentProcessorNumberEx" | "NtGetDevicePowerState"
                | "NtGetMUIRegistryInfo" | "NtGetNlsSectionPtr"
                | "NtGetNotificationResourceManager" | "NtInitializeEnclave"
                | "NtInitializeNlsFiles" | "NtInitializeRegistry"
                | "NtInitiatePowerAction" | "NtIsSystemResumeAutomatic"
                | "NtIsUILanguageComitted" | "NtLoadEnclaveData"
                | "NtLockProductActivationKeys" | "NtManageHotPatch"
                | "NtManagePartition" | "NtMapCMFModule"
                | "NtMapUserPhysicalPages" | "NtMapUserPhysicalPagesScatter"
                | "NtModifyBootEntry" | "NtModifyDriverEntry"
                | "NtNotifyChangeDirectoryFileEx" | "NtNotifyChangeSession"
                | "NtOpenObjectAuditAlarm" | "NtOpenPartition"
                | "NtOpenPrivateNamespace" | "NtOpenRegistryTransaction"
                | "NtOpenSession" | "NtPlugPlayControl"
                | "NtPrepareComplete" | "NtPrepareEnlistment"
                | "NtPrePrepareComplete" | "NtPrePrepareEnlistment"
                | "NtPrivilegedServiceAuditAlarm" | "NtPrivilegeObjectAuditAlarm"
                | "NtPropagationComplete" | "NtPropagationFailed"
                | "NtPssCaptureVaSpaceBulk" | "NtQueryAuxiliaryCounterFrequency"
                | "NtQueryBootEntryOrder" | "NtQueryBootOptions"
                | "NtQueryDebugFilterState" | "NtQueryDriverEntryOrder"
                | "NtQueryInformationAtom" | "NtQueryInformationEnlistment"
                | "NtQueryInformationPort" | "NtQueryInformationResourceManager"
                | "NtQueryInformationTransaction" | "NtQueryInformationTransactionManager"
                | "NtQueryInformationWorkerFactory" | "NtQueryIntervalProfile"
                | "NtQueryIoCompletion" | "NtQueryPortInformationProcess"
                | "NtQuerySecurityAttributesToken" | "NtQuerySecurityPolicy"
                | "NtQuerySystemEnvironmentValue" | "NtQuerySystemEnvironmentValueEx"
                | "NtQueryWnfStateNameInformation" | "NtQueueApcThreadEx"
                | "NtQueueApcThreadEx2" | "NtRaiseException"
                | "NtRaiseHardError" | "NtReadOnlyEnlistment"
                | "NtReadRequestData" | "NtRecoverEnlistment"
                | "NtRecoverResourceManager" | "NtRecoverTransactionManager"
                | "NtRegisterProtocolAddressInformation" | "NtRegisterThreadTerminatePort"
                | "NtReleaseWorkerFactoryWorker" | "NtRemoveIoCompletionEx"
                | "NtRenameTransactionManager" | "NtReplacePartitionUnit"
                | "NtResumeProcess" | "NtRevertContainerImpersonation"
                | "NtRollbackComplete" | "NtRollbackEnlistment"
                | "NtRollbackRegistryTransaction" | "NtRollforwardTransactionManager"
                | "NtSerializeBoot" | "NtSetBootEntryOrder"
                | "NtSetBootOptions" | "NtSetCachedSigningLevel"
                | "NtSetCachedSigningLevel2" | "NtSetDebugFilterState"
                | "NtSetDefaultHardErrorPort" | "NtSetDefaultLocale"
                | "NtSetDefaultUILanguage" | "NtSetDriverEntryOrder"
                | "NtSetEventBoostPriority" | "NtSetHighEventPair"
                | "NtSetHighWaitLowEventPair" | "NtSetInformationEnlistment"
                | "NtSetInformationKey" | "NtSetInformationObject"
                | "NtSetInformationResourceManager" | "NtSetInformationSymbolicLink"
                | "NtSetInformationToken" | "NtSetInformationTransaction"
                | "NtSetInformationTransactionManager" | "NtSetInformationVirtualMemory"
                | "NtSetInformationWorkerFactory" | "NtSetIntervalProfile"
                | "NtSetIoCompletionEx" | "NtSetIRTimer"
                | "NtSetLdtEntries" | "NtSetLowEventPair"
                | "NtSetLowWaitHighEventPair" | "NtSetSystemEnvironmentValue"
                | "NtSetSystemEnvironmentValueEx" | "NtSetSystemPowerState"
                | "NtSetSystemTime" | "NtSetThreadExecutionState"
                | "NtSetTimer2" | "NtSetUuidSeed"
                | "NtSetWnfProcessNotificationEvent" | "NtShutdownSystem"
                | "NtShutdownWorkerFactory" | "NtSinglePhaseReject"
                | "NtStartProfile" | "NtStopProfile"
                | "NtSubscribeWnfStateChange" | "NtSuspendProcess"
                | "NtSystemDebugControl" | "NtTerminateEnclave"
                | "NtThawRegistry" | "NtThawTransactions"
                | "NtTranslateFilePath" | "NtUmsThreadYield"
                | "NtUnsubscribeWnfStateChange" | "NtVdmControl"
                | "NtWaitForAlertByThreadId" | "NtWaitForMultipleObjects32"
                | "NtWaitForWorkViaWorkerFactory" | "NtWaitHighEventPair"
                | "NtWaitLowEventPair" | "NtWorkerFactoryCreate"
                | "NtWorkerFactoryReady" | "NtWorkerFactoryRelease"
                | "NtWorkerFactoryShutdown" | "NtWorkerFactoryWait"
                | "NtWorkerFactoryWorkerReady" | "NtWriteRequestData"
                | "NtYieldExecution"
                // ALPC Nt* stubs
                | "NtAlpcAcceptConnectPort" | "NtAlpcCancelMessage"
                | "NtAlpcConnectPort" | "NtAlpcConnectPortEx"
                | "NtAlpcCreatePort" | "NtAlpcCreatePortSection"
                | "NtAlpcCreateResourceReserve" | "NtAlpcCreateSectionView"
                | "NtAlpcCreateSecurityContext" | "NtAlpcDeletePortSection"
                | "NtAlpcDeleteResourceReserve" | "NtAlpcDeleteSectionView"
                | "NtAlpcDeleteSecurityContext" | "NtAlpcDisconnectPort"
                | "NtAlpcImpersonateClientContainerOfPort" | "NtAlpcImpersonateClientOfPort"
                | "NtAlpcOpenSenderProcess" | "NtAlpcOpenSenderThread"
                | "NtAlpcQueryInformation" | "NtAlpcQueryInformationMessage"
                | "NtAlpcRevokeSecurityContext" | "NtAlpcSendWaitReceivePort"
                | "NtAlpcSetInformation"
                // Remaining Zw* stubs
                | "ZwAlertThreadByThreadId" | "ZwCancelTimer2"
                | "ZwClose" | "ZwDuplicateObject"
                | "ZwGetTickCount" | "ZwRemoveProcessDebug"
                | "ZwSetTimer2" | "ZwWaitForAlertByThreadId"
                // ── Remaining Rtl stubs (iteration 3 batch) ────────────
                | "RtlAbsoluteToSelfRelativeSD" | "RtlAddAccessAllowedAce"
                | "RtlAddAccessAllowedAceEx" | "RtlAddAccessAllowedObjectAce"
                | "RtlAddAccessDeniedAce" | "RtlAddAccessDeniedAceEx"
                | "RtlAddAccessDeniedObjectAce" | "RtlAddAce"
                | "RtlAddAuditAccessAce" | "RtlAddAuditAccessAceEx"
                | "RtlAddAuditAccessObjectAce" | "RtlAddCompoundAce"
                | "RtlAddIntegrityLabelToBoundaryDescriptor" | "RtlAddMandatoryAce"
                | "RtlAddRefMemoryStream" | "RtlAddSIDToBoundaryDescriptor"
                | "RtlAllocateAndInitializeSID" | "RtlAllocateMemoryBlockLookaside"
                | "RtlAllocateMemoryZone" | "RtlAnsiCharToUnicodeChar"
                | "RtlAppendAsciizToString" | "RtlApplyLengthToAcl"
                | "RtlAreAllAccessesGranted" | "RtlAreAnyAccessesGranted"
                | "RtlAreBitsClear" | "RtlAreBitsSet"
                | "RtlAssert" | "RtlBackupEventLog"
                | "RtlBindImageUntrusted" | "RtlBitTestAndComplement"
                | "RtlBitTestAndReset" | "RtlBitTestAndSet"
                | "RtlCrc64" | "RtlCreateAcl"
                | "RtlCreateAndSetSD" | "RtlCreateAtomTable"
                | "RtlCreateRegistryKey" | "RtlCreateSecurityDescriptor"
                | "RtlCreateServiceSid" | "RtlCreateSystemVolumeInformationFolder"
                | "RtlCreateTagHeap" | "RtlCreateTimer"
                | "RtlCreateUserProcess" | "RtlCreateUserSecurityObject"
                | "RtlCreateVirtualAccountSid" | "RtlCustomCPToUnicodeN"
                | "RtlDecompressBufferEx" | "RtlDecompressFragment"
                | "RtlDefaultNpAcl" | "RtlDelete"
                | "RtlDeleteAce" | "RtlDeleteAtomFromAtomTable"
                | "RtlDeleteAtomTable" | "RtlDeleteBoundaryDescriptor"
                | "RtlDeleteElementGenericTableAvl" | "RtlDeleteRegistryValue"
                | "RtlDeleteResource" | "RtlDeleteSecurityObject"
                | "RtlDeleteTimer" | "RtlDeleteTimerQueue"
                | "RtlDeleteTimerQueueEx" | "RtlDeregisterWait"
                | "RtlDestroyMemoryBlockLookaside"
                | "RtlDetermineDosPathNameType" | "RtlDetermineDosPathNameType_U"
                | "RtlDisableThreadProfiling" | "RtlDosLongPathToNtPathPath_U_WithStatus"
                | "RtlDosSearchPath_U" | "RtlDosSearchPath_Ustr"
                | "RtlDowncaseUnicodeChar" | "RtlDumpResource"
                | "RtlEnableThreadProfiling" | "RtlEnlargedIntegerMultiply"
                | "RtlEnlargedUnsignedDivide" | "RtlEnlargedUnsignedMultiply"
                | "RtlEnumerateEntryHashTable" | "RtlEqualComputerName"
                | "RtlEqualDomainName"

                | "RtlExtendedIntegerMultiply" | "RtlExtendedLargeIntegerDivide"
                | "RtlFillMemoryUlong" | "RtlFillMemoryUlonglong"
                | "RtlFindClearBits" | "RtlFindClearBitsAndSet"
                | "RtlFindClearRuns" | "RtlFindFirstRunClear"
                | "RtlFindLastBackwardRunClear" | "RtlFindLongestRunClear"
                | "RtlFindMessage" | "RtlFindNextForwardRunClear"
                | "RtlFindSetBits" | "RtlFindSetBitsAndClear"
                | "RtlFormatCurrentUserKeyPath" | "RtlFormatMessage"
                | "RtlFormatMessageEx" | "RtlFreeMemoryBlockLookaside"
                | "RtlFreeThreadExecutionEnvironment" | "RtlFreeUserThreadStack"
                | "RtlGenerate8dot3Name" | "RtlGetAce"
                | "RtlGetAclInformation" | "RtlGetControlSecurityDescriptor"
                | "RtlGetDaclSecurityDescriptor" | "RtlGetElementGenericTable"
                | "RtlGetElementGenericTableAvl" | "RtlGetFirstEntryHashTable"
                | "RtlGetFrame" | "RtlGetGroupSecurityDescriptor"
                | "RtlGetIntegerAtom" | "RtlGetLengthWithoutLastFullOrBackSlash"
                | "RtlGetLengthWithoutTrailingPathSeperators" | "RtlGetLongestNtPathLength"
                | "RtlGetNativeSystemInformation" | "RtlGetNextEntryHashTable"
                | "RtlGetNtGlobalFlags" | "RtlGetNtProductType"
                | "RtlGetNtVersionNumbers" | "RtlGetOwnerSecurityDescriptor"
                | "RtlGetProcessHeaps" | "RtlGetSaclSecurityDescriptor"
                | "RtlGetSecurityDescriptorRMControl" | "RtlGetSetBootStatusData"
                | "RtlGetSuiteMask" | "RtlGetThreadErrorMode"
                | "RtlIdentifierAuthoritySid" | "RtlImageDirectoryEntryToData"
                | "RtlImageNtHeader" | "RtlImageRvaToSection"
                | "RtlImageRvaToVa" | "RtlInitAnsiStringEx"
                | "RtlInitializeBitMap" | "RtlInitializeContext"
                | "RtlInitializeGenericTable" | "RtlInitializeGenericTableAvl"
                | "RtlInitializeHandleTable" | "RtlInitializeResource"
                | "RtlInitializeSID" | "RtlInitializeSListHead"
                => {
                    Ok(STATUS_SUCCESS as u64)
                }

                _ => unreachable!(),
            }
        })())
    }
}
