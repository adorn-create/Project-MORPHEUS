!include "LogicLib.nsh"
!macro customInstall
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop MorpheusFirewallWorker'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete MorpheusFirewallWorker'
  Pop $0
  CreateDirectory "$SMPROGRAMS\Morpheus Defense"
  CreateShortCut "$SMPROGRAMS\Morpheus Defense\Uninstall Morpheus Defense.lnk" "$INSTDIR\resources\uninstall-helper\MorpheusUninstallHelper.exe"
!macroend

!macro customUnInstall
  Delete "$SMPROGRAMS\Morpheus Defense\Uninstall Morpheus Defense.lnk"
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop MorpheusFirewallWorker'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete MorpheusFirewallWorker'
  Pop $0
!macroend
