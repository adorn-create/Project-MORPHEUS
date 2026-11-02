!include "LogicLib.nsh"
!include "nsDialogs.nsh"

!ifndef BUILD_UNINSTALLER
  Var FirewallLoggingCheckbox
  Var FirewallLoggingDialog
  Var EnableFirewallLogging

  !macro customPageAfterChangeDir
    Page custom FirewallLoggingPage FirewallLoggingPageLeave
  !macroend

  Function FirewallLoggingPage
    StrCpy $EnableFirewallLogging "0"
    nsDialogs::Create 1018
    Pop $FirewallLoggingDialog
    ${NSD_CreateLabel} 0 0 100% 32u "Optional Windows Firewall setup"
    Pop $0
    ${NSD_CreateCheckbox} 0 44u 100% 32u "Enable dropped-packet logging for all Windows Firewall profiles"
    Pop $FirewallLoggingCheckbox
    ${NSD_SetState} $FirewallLoggingCheckbox ${BST_UNCHECKED}
    ${NSD_CreateLabel} 0 86u 100% 48u "This sets the standard Windows Firewall log path and enables dropped-packet logging for all profiles. It does not enable automatic IP blocking. You can enable blocking later in Morpheus after enrolling a passkey."
    Pop $0
    nsDialogs::Show
  FunctionEnd

  Function FirewallLoggingPageLeave
    ${NSD_GetState} $FirewallLoggingCheckbox $EnableFirewallLogging
  FunctionEnd
!endif

!macro customInstall
  ${If} $EnableFirewallLogging == ${BST_CHECKED}
    CreateDirectory "$WINDIR\System32\LogFiles\Firewall"
    nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall set allprofiles logging filename "$WINDIR\System32\LogFiles\Firewall\pfirewall.log"'
    Pop $0
    ${If} $0 == 0
      nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall set allprofiles logging droppedconnections enable'
      Pop $0
    ${EndIf}
    ${If} $0 != 0
      MessageBox MB_ICONEXCLAMATION "Morpheus installed, but Windows Firewall dropped-packet logging could not be enabled. You can enable it later in Windows Defender Firewall with Advanced Security."
    ${Else}
      MessageBox MB_ICONINFORMATION "Windows Firewall dropped-packet logging is enabled. Morpheus inbound monitoring and automatic IP blocking remain off until you enable them in the dashboard."
    ${EndIf}
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\resources\firewall-worker\morpheus-firewall-worker.exe" --wait=10 stop'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\resources\firewall-worker\morpheus-firewall-worker.exe" --startup auto install'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Morpheus Firewall Worker installation failed. The installer will stop."
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\resources\firewall-worker\morpheus-firewall-worker.exe" --wait=10 start'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Morpheus Firewall Worker could not start. The installer will stop."
    Abort
  ${EndIf}
  CreateDirectory "$SMPROGRAMS\Morpheus Defense"
  CreateShortCut "$SMPROGRAMS\Morpheus Defense\Uninstall Morpheus Defense.lnk" "$INSTDIR\resources\uninstall-helper\MorpheusUninstallHelper.exe"
!macroend

!macro customUnInstall
  Delete "$SMPROGRAMS\Morpheus Defense\Uninstall Morpheus Defense.lnk"
  nsExec::ExecToLog '"$INSTDIR\resources\firewall-worker\morpheus-firewall-worker.exe" --wait=10 stop'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\resources\firewall-worker\morpheus-firewall-worker.exe" remove'
  Pop $0
  ${If} $0 != 0
    nsExec::ExecToLog '"$SYSDIR\sc.exe" delete MorpheusFirewallWorker'
    Pop $0
  ${EndIf}
!macroend
