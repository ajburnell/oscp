# Active Directory Attacks

## Traditional Appraoch

Enumerate local accounts:  
`net user`  

Enumerate all users in entire domain:  
`net user /domain`  

Enumerate a specific user:  
`net user bob_admin /domain`  

Enumerate all domain groups:  
`net group /domain`  

Note that net.exe cannot list nested groups and only shows direct user members.

# Modern Approach

Use the LDAP provider path format:
`LDAP://HostName[:PortNumber][/DistinguishedName]`

See exercises section for more information.
