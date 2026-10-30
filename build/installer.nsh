!include "LogicLib.nsh"

!macro customInstall
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
!macroend

!macro customUnInstall
  nsExec::ExecToLog '"$INSTDIR\resources\firewall-worker\morpheus-firewall-worker.exe" --wait=10 stop'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\resources\firewall-worker\morpheus-firewall-worker.exe" remove'
  Pop $0
  ${If} $0 != 0
    nsExec::ExecToLog '"$SYSDIR\sc.exe" delete MorpheusFirewallWorker'
    Pop $0
  ${EndIf}
!macroend
