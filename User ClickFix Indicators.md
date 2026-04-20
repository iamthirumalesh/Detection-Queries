# User ClickFix Indicators


Rule looking for explorer and the user activity Reg Key indicating interactive commands, along with several malicious indicators around "clickfix" campaigns

```sql
// converted KQL query from Microsoft

#event_simpleName=ProcessRollup2
| ActionType="RegistryValueSet"
| InitiatingProcessFileName="explorer.exe"
| RegistryKey=/.*\\CurrentVersion\\Explorer\\RunMRU.*/
AND (
    RegistryValueData=/.*✅.*/ OR
    RegistryValueData = "*curl*" OR
    RegistryValueData = "*mshta*" OR
    RegistryValueData = "*msiexec*" OR
    RegistryValueData = "*powershell*" OR
    RegistryValueData = "*^*" OR
    (
        RegistryValueData=/.*mshta.*/ AND
        RegistryValueName!="MRUList" AND
        RegistryValueData != "mshta.exe\1" AND
        RegistryValueData != "mshta\1"
    ) OR
    (
        (
            RegistryValueData=/.*bitsadmin.*/ OR
            RegistryValueData=/.*forfiles.*/ OR
            RegistryValueData=/.*ProxyCommand=.*/
        ) AND
        RegistryValueName!="MRUList"
    ) OR
    (
        (
            RegistryValueData=/^cmd.*/ OR
            RegistryValueData=/^powershell.*/
        ) AND
        (
            RegistryValueData = "*-W Hidden *" OR
            RegistryValueData = "* -eC *" OR
            RegistryValueData = "*curl*" OR
            RegistryValueData = "*E:jscript*" OR
            RegistryValueData = "*ssh*" OR
            RegistryValueData = "*Invoke-Expression*" OR
            RegistryValueData = "*UtcNow*" OR
            RegistryValueData = "*Floor*" OR
            RegistryValueData = "*DownloadString*" OR
            RegistryValueData = "*DownloadFile*" OR
            RegistryValueData = "*FromBase64String*" OR
            RegistryValueData = "*System.IO.Compression*" OR
            RegistryValueData = "*System.IO.MemoryStream*" OR
            RegistryValueData = "*iex*" OR
            RegistryValueData = "*Invoke-WebRequest*" OR
            RegistryValueData = "*iwr*" OR
            RegistryValueData = "*Get-ADDomainController*" OR
            RegistryValueData = "*InstallProduct*" OR
            RegistryValueData = "*-w h*" OR
            RegistryValueData = "*-X POST*" OR
            RegistryValueData = "*Invoke-RestMethod*" OR
            RegistryValueData = "*-NoP -W*" OR
            RegistryValueData = "*.InVOKe*" OR
            RegistryValueData = "*-useb*" OR
            RegistryValueData = "*irm *" OR
            RegistryValueData = "*^*" OR
            RegistryValueData = "*[char]*" OR
            RegistryValueData = "*[scriptblock]*" OR
            RegistryValueData = "*-UserAgent*" OR
            RegistryValueData = "*UseBasicParsing*" OR
            RegistryValueData = "*.Content*" OR
            RegistryValueData=/[-\/–][Ee\^]{1,2}[NnCcOoDdEeMmAa\^]*\s[A-Za-z0-9+\/=]{15,}/
        )
    )
)


```



