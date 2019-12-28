# eLDAPperDan or ldapper.pl

 ldapper is an Active Directory and LDAP interrogation tool
 I wrote this to aid in getting useful information formatted cleanly
 during penetration tests without having to switch to a windows box

# Necessary libraries:
apt-get install libnet-ldap-perl

# Example Usage:
```
 -= el Dapper Dan Usage =-
-s Server (Target LDAP Server)
-u User (user must be user@domain or old style DOMAIN\User)
-d domain (used to create Base DN for ldap, eg site.company.com)

 -= Target Information =-
-R (Run all Queries)
   (currently: Computers, Groups, Users, Trusts, Sites)
-C (list all computers in domain)
-E (list all Exchange Servers)
-G (list all groups in domain and members of those groups)
-I (get Domain Info, e.g. Domain SID, LAPS Config, etc.)
-K (list all Service Principal Names - for Kerberoasting)
-L (list all groups in domain (simple listing))
-N (list all Subnets in domain)
-O (list of all Organizational Units - detailed)
-S (list all Servers in domain)
-T (list all Trusts in domain)
-U (list all Users in domain)
-g <group> (list all members of target group, case sensitive)
-M <user> (list all groups <user> is a member of)
-A <user> (list all attributes for <user> *NOTE* that this strips binary data)
-W (list all LAPS passwords, you may want to run this with various user accounts)
-X (Enumerate DNS Zones and DNS Records)
-Y <baseDN Prefix> (Use New Prefix to BaseDN, use with -Z option)
-Z <Filter> (Query LDAP with <Filter>)




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
