# applet
Cryptonit is a multiplatform open source (GPL) signing and (de)crypting software with PKCS#11 support that generates PKCS#7 containers.

### Installation
Compile the .cap file or download the pre-compiled one. For cap file compilation, see Martin Paljak's awesome AppletPlayground project. Use any tool you prefer to load the .cap file onto the card (GlobalPlatformPro, PyAPDUTool, GPShell and many others).

### Use
The applet can be used through OpenSC pksc11-tool, or PKCS Admin GUI tool (https://sourceforge.net/projects/pkcs11admin/) or with Cryptonit GUI tool (https://sourceforge.net/projects/cryptonit/files/latest/download). More on using the applets can be found at OpenSC wiki (https://github.com/OpenSC/OpenSC/wiki/Using-smart-cards-with-applications). Both GUI tools need to have PKCS11 driver specified, so you have to download OpenSC (driver locations here https://github.com/OpenSC/OpenSC/wiki/Installing-OpenSC-PKCS%2311-Module-in-Firefox,-Step-by-Step). 
