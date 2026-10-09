# LegacyHive : Windows user profile service arbitrary hive load elevation of privileges vulnerability

The PoC requires another standard user credentials and a third username (which can be an administrator account), if the PoC is successful, it will end up mounting the target user hive in current user classes root.

The PoC was stripped down as an attempt to prevent public exploitation, the original PoC did not require additional user credential and was not limited to usrclass.dat hive, any hive could be loaded using this vulnerability but you would need some brain cells to make the PoC do it.

<img width="1228" height="627" alt="Screenshot 2026-07-14 102705" src="https://github.com/user-attachments/assets/49deeaef-aadf-4a13-9006-a7c95eb2531e" />

The PoC is fully functional in all currently supported desktop and server installation with July 2026 patch.

