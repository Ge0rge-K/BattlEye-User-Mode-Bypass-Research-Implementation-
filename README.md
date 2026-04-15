# BattlEye-User-Mode-Bypass-Research-Implementation-
BattlEye User-Mode Bypass – Research &amp; Proof of Concept This repository documents and implements user-mode techniques to bypass BattlEye anti-cheat without using kernel drivers. BattlEye loads a kernel driver (BEDaisy.sys) and hooks user-mode APIs in ntdll.dll. Most detections happen at the user-mode level, which makes them avoidable.
