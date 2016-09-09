# eLDAPperDan or ldapper.pl
#
# ldapper is an Active Directory and LDAP interrogation tool
# I wrote this to aid in getting useful information formatted cleanly
# during penetration tests
#
# Necessary libraries:
apt-get install libnet-ldap-perl

# Example Usage:
```
user@linux:/# ./ldap.pl
 -= el Dapper Dan Usage =-
-s Server (Target LDAP Server)
-u User (user must be user@domain or old style DOMAIN\User)
-d domain (used to create Base DN for ldap, eg site.company.com)
-g group (List all members of target group, case sensitive)

 -= Target Information =-
-R (generate report of useful data)
   (currently: Domain Controllers, Sites)
-C (list all computers in domain)
-G (list all groups in domain)
-M <user> (list all groups <user> is a member of)
-S (list all Servers in domain)
-U (list all Users in domain)
-N (list all Subnets in domain)
-T (list all Trusts in domain)

user@linux:/# ./ldap.pl -s 10.0.0.10 -u evilco\\administrator -U -d evilco.loc
Enter your password: 
[+] Connecting to Server: 10.0.0.10
[+] User: evilco\administrator
[+] BaseDN: dc=evilco,dc=loc
USER: Administrator, Administrator, DESC: Built-in account for administering the computer/domain, HOME: , PWDRESET: 2016-09-09, LASTLOGON: 2016-09-09
USER: Guest, Guest, DESC: Built-in account for guest access to the computer/domain, HOME: , PWDRESET: 1600-12-31, LASTLOGON: Never
USER: krbtgt, krbtgt, DESC: Key Distribution Center Service Account, HOME: , PWDRESET: 2016-09-09, LASTLOGON: Never

user@linux:/# 
```