#!/usr/bin/perl
#
$version = "0.92";
#
# apt-get install libnet-ldap-perl
# apt-get install libnet-ldap-sid-perl
#
#
#
# -u argument is either user@domain.com
# or 'domain\user' 
# note the backslash is not escaped in single quotes
#
#
# Example manual query that worked:
# -X 'DC=DomainDNSZones' -Z 'CN=Zone'
#
# To Do
# create 'report' format which runs all commands
# and outputs in more human readable format
#
# Enumerate Nested Groups
# Add recursive grab of group info eg; user is 
# member of GroupX, grab GroupX description
# 
# Disabled accounts userAccountControl = 514
# http://support.microsoft.com/kb/305144
#
# objectClass = trustedDomain
# trustType = 2, trustDirection = 1
#
# Define the Base DN format is DC=pwn,DC=me
# $baseDN = "dc=site,dc=mycompany,dc=com";


use Term::ReadKey;
use Getopt::Std;
use POSIX();
use Socket;

use Net::DNS;

use Net::LDAP;
use Net::LDAP::Control::Paged;
use Net::LDAP::SID;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );

$groupFilter = "(objectClass=group)";
$siteFilter = "(objectClass=site)";
$subnetFilter = "(objectClass=subnet)";
$serverFilter = "(objectClass=computer)";
$siteServerFilter = "(objectClass=server)";
$userFilter = "(&(objectClass=user)(objectcategory=person))";
$trustFilter = "(objectClass=trustedDomain)";
$containerFilter = "(objectClass=Container)";
$ouFilter = "(objectClass=OrganizationalUnit)";
$spnFilter = "(&(objectclass=user)(objectcategory=user)(servicePrincipalName=*))";
$exchangeFilter = "(objectCategory=msExchExchangeServer)";
$lapsFilter = "(objectClass=attributeSchema)";
$lapsPwdFilter = "(ms-mcs-AdmPwd=*)";
$lapsExpFilter = "(ms-mcs-AdmPwdExpirationTime=*)";

$objectSIDFilter = "(objectSid=*)";


my %args;	

if ( @ARGV < 1 )
{
print " -= el Dapper Dan Usage =-\n";
print "-s Server (Target LDAP Server)\n";
print "-u User (user must be user\@domain or old style DOMAIN\\User)\n";
print "-d domain (used to create Base DN for ldap, eg site.company.com)\n";
print "\n -= Target Information =-\n";
print "-R (Run all Queries)\n";
print "   (currently: Computers, Groups, Users, Trusts, Sites)\n";
print "-C (list all computers in domain)\n";
print "-E (list all Exchange Servers)\n";
print "-G (list all groups in domain and members of those groups)\n";
print "-I (get Domain Info, e.g. Domain SID, LAPS Config, etc.)\n";
print "-K (list all Service Principal Names - for Kerberoasting)\n";
print "-L (list all groups in domain (simple listing))\n";
print "-N (list all Subnets in domain)\n";
print "-O (list of all Organizational Units - detailed)\n";
print "-S (list all Servers in domain)\n";
print "-T (list all Trusts in domain)\n";
print "-U (list all Users in domain)\n";
print "-g <group> (list all members of target group, case sensitive)\n";
print "-M <user> (list all groups <user> is a member of)\n";
print "-A <user> (list all attributes for <user> *NOTE* that this strips binary data)\n";
print "-W (list all LAPS passwords, you may want to run this with various user accounts)\n";
print "-X (Enumerate DNS Zones and DNS Records)\n";
print "-Y <baseDN Prefix> (Use New Prefix to BaseDN, use with -Z option)\n";
print "-Z <Filter> (Query LDAP with <Filter>)\n";
exit;
}

# Pretty Obvious
sub procWindowsTime{
   $timeInteger = @_[0];
   $retTime = POSIX::strftime( "%Y-%m-%d", localtime(($timeInteger/10000000)-11644473600) );
   return $retTime;
}

sub printGenTime 
{ 
	# GeneralizedTime Format YYYYmmddHH[MM[SS]

    my $time = $_[0]; 

    my($year, $month, $day, $hour, $minute) = 
    $time =~ /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/;

    $printTime = "$month/$day/$year $hour:$minute";
    #print "printTime: $printTime\n";
     
    return ($printTime); 
} 


getopt('sugpdMAYZ', \%args);

$server = $args{s};
$username = $args{u};
$groupname = $args{g};
$argDomain = $args{d};

$exchangeServers = $args{E};
$listAllGroups = $args{G};
$listGroupsSimple = $args{L};

$listAllServers = $args{S};
$listAllUsers = $args{U};
$listAllSubnets = $args{N};
$listAllTrusts = $args{T};
$generateReport = $args{R};
$listAllComputers = $args{C};
$userGroupMembers = $args{M};
$userAllAtributes = $args{A};
$listAllSPNs = $args{K};
$getDomainInfo = $args{I};

$listLapsPwds = $args{W};
$listDNSRecords = $args{X};
$prefixBaseDN = $args{Y};
$manualFilter = $args{Z};


$listOrgUnits = $args{O};

if ($groupname) {
  $findGroup = "YES";
}

if ($generateReport)
{
 $listAllUsers = "YUP";
 $listAllGroups = "YUP";
 $listAllComputers = "YUP";
 $listAllSubnets = "YUP";
 $listOrgUnits = "YUP";
 $listAllTrusts = "YUP";
}

if ( $args{p} )
{
 $passwd = $args{p};
}
else
{
 print "Enter your password: ";
 ReadMode 'noecho';
 $passwd = ReadLine 0;
 chomp $passwd;
 ReadMode 'normal';
 print "\n";
}

if ( $argDomain )
{
  @domVals = split( '\.', $argDomain);
  $numElements=@domVals;
  $i = 1;

  foreach my $val (@domVals) {
    $baseDN .= "dc=".$val;
    if ($i < $numElements )
    {
	$baseDN .=",";
    }
    $i++;
   }

  $ldap = Net::LDAP->new ( "$server" ) or die "$@";
  $mesg = $ldap->bind ( "$username", password => $passwd, version => 3 );          
  $mesg->code( ) && die $mesg->error;

  my $page = Net::LDAP::Control::Paged->new(size => 999);
  my $cookie;
}

else {
    $obtainBaseDN = "YES";
}

printf("[+] Connecting to Server: $server\n");
printf("[+] User: $username\n");

if ( $baseDN ) 
{ 
 printf("[+] BaseDN: $baseDN\n");
}


if ( $obtainBaseDN)
{ 
	obtainBaseDN(); 
}

$page = Net::LDAP::Control::Paged->new(size => 999);



sub obtainBaseDN
{
 $ldap = Net::LDAP->new ( "$server" ) or die "$@";
 $mesg = $ldap->bind ( "$username", password => $passwd, version => 3 );          
 $mesg->code( ) && die $mesg->error;

 my $page = Net::LDAP::Control::Paged->new(size => 999);
 my $cookie;

 print "[+] BaseDN not specified, querying RootDSE\n";
 my $dse = $ldap->root_dse( attrs => ['defaultNamingContext'] );
 my @contexts = $dse->get_value('namingContexts');
 
 $baseDN = $dse->get_value('defaultNamingContext');
 print "[+] Obtained baseDN: $baseDN\n";
}



# This loop will list all users within a domain
if ( $listAllUsers)
{
  while(1){
  $mesg = $ldap->search( base    => $baseDN, filter  => $userFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

  foreach $entry (@entries) {
   $cName = $entry->get_value("cn");
   $sName = $entry->get_value("sAMAccountName");
   $desc = $entry->get_value("description");
   $hDir = $entry->get_value("homeDirectory");
   $pwdLastSet = $entry->get_value("pwdLastSet");
   $lastLogon = $entry->get_value("lastLogon");
   $uac = $entry->get_value("userAccountControl");

   if ( $uac eq 2){$uac = "(2) Account Disabled"}
   if ( $uac eq 16){$uac = "(16) Account Locked"}
   if ( $uac eq 32){$uac = "(32) Password Not Required"}
   if ( $uac eq 64){$uac = "(64) Password Cannot be Changed"}
   if ( $uac eq 512){$uac = "(2) Account Normal"}
   if ( $uac eq 514){$uac = "(514) Account Disabled"}
   if ( $uac eq 8388608){$uac = "(8388608) Password Expired"}

  $pwdLastSetTime = procWindowsTime($pwdLastSet);
  if( $lastLogon == 0 ) {
   $lastLogonTime = "Never"; }
  else {
   $lastLogonTime = procWindowsTime($lastLogon); }

   #Add whenCreated
   $lastTime = procWindowsTime($lastLogon);

    print "USER: $sName, $cName, $uac, DESC: $desc, HOME: $hDir, PWDRESET: $pwdLastSetTime, LASTLOGON: $lastLogonTime\n";
  }
 }
}

# this will list all computers in the domain
if ( $listAllComputers)
{
 while(1){
  $mesg = $ldap->search( base    => $baseDN, filter  => $serverFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

  foreach $entry (@entries) {
  $cName = $entry->get_value("cn");
  $dName = $entry->get_value("dnsHostName");
  $opSystem = $entry->get_value("operatingSystem");
  $osPack = $entry->get_value("operatingSystemServicePack");
  $lastLogon = $entry->get_value("lastLogonTimestamp");
  $lastTime = procWindowsTime($lastLogon);
  print "Computer: $cName, $dName, $opSystem $osPack, LastLogon: $lastTime\n";
  }
 }
}

# This loop will list all servers within domain
if ( $listAllServers)
{
 while(1){
  $mesg = $ldap->search( base => $baseDN, filter  => $serverFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;

   foreach $entry (@entries) {
   $cName = $entry->get_value("cn");
   $dName = $entry->get_value("dnsHostName");
   $opSystem = $entry->get_value("operatingSystem");
   $osPack = $entry->get_value("operatingSystemServicePack");
   $lastLogon = $entry->get_value("lastLogonTimestamp");
   $lastTime = procWindowsTime($lastLogon);
   
    if ( $opSystem =~ /erver/) 
    {
     print "Server: $cName, $dName, $opSystem $osPack, LastLogon: $lastTime\n";
    }
   }
 }
}



 # This loop will list all SUBNETS within domain
 if( $listAllSubnets )
 {
   $newBaseDN = "CN=Subnets,CN=Sites,CN=Configuration," . $baseDN;
   $mesg = $ldap->search( base    => $newBaseDN, filter => $subnetFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) {
   $cName = $entry->get_value("cn");
   $desc = $entry->get_value("description");
   $siteObject = $entry->get_value("siteObject");
   $location = $entry->get_value("location");
	 print "SUBNET: $cName, DESC: $desc, SITE: $siteObject, LOCATION: $location\n";
   }
 }


# This loop will list all Members of the group
# specified by the -g command line argument
 if ( $findGroup )
 {
   printf("[+] Looking for all users in group $groupname\n");
   #$userFilter = "(&(objectClass=user)(objectcategory=person))";

   $groupFilter = "(sAMAccountName=$groupname)";
   #printf("[D] Filter: $groupFilter\n");


   $mesg = $ldap->search( base    => $baseDN, filter  => $groupFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) 
   {
   	$gname = $entry->get_value("cn");
   	if ($groupname && $gname eq $groupname)
   	{
    	print "[I] Found group $gname on server\n";
    	$description = $entry->get_value("description");
    	print "[I] Group Description: $description\n";
    	@members = $entry->get_value( "member");
    	foreach $member (@members)
    	{
     		#print "Running with filter $member\n";
     		$userfilter = "(objectClass=user)";
     		$newmesg = $ldap->search( base => $member, filter=> $userfilter);
     		@nentries = $newmesg->entries;
     		foreach $nentry (@nentries) {
       			$sam = $nentry->get_value("sAMAccountName");
       			print "$groupname: User: $sam\n";
     		}
    	}
    	foreach $member (@members)
    	{
     		#print "Running with filter $member\n";
     		$userfilter = "(objectClass=group)";
     		$newmesg = $ldap->search( base => $member, filter=> $userfilter);
     		@nentries = $newmesg->entries;
     		foreach $nentry (@nentries) {
       			$sam = $nentry->get_value("sAMAccountName");
       			print "$groupname: Group: $sam\n";
     		}
    	}
    }
   }
 }








 # This loop will list all Trusts within domain
 if( $listAllTrusts )
 {
   print "[+] Listing all Trusts\n";

   #$newBaseDN = "CN=Trusted-Domain,CN=SCHEMA,CN=Configuration," . $baseDN;
   $newBaseDN = $baseDN;

   $mesg = $ldap->search( base    => $newBaseDN, filter => $trustFilter,  control => [$page] );
   $mesg->code && die "[-]Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) 
   {
 	#trustType, trustDirection, trustPartner
   $flatName = $entry->get_value("flatName");
   $Name = $entry->get_value("name");
   $cName = $entry->get_value("cn");
   $trustPartner = $entry->get_value("trustPartner");
   $trustType = $entry->get_value("trustType");
   $trustDirection = $entry->get_value("trustDirection");

   #trustType (1=WindowsNT, 2=ActiveDirectory 2003 or newer, 3=Kerberos Realm, 4=DCE);
   #trustDirection (1=Inbound, 2=Outbound, 3=BiDirectional);
   #define arrays based on previous definitions

   @tType = ( "NA", "WindowsNT" ,"ActiveDirectory 2K3+" ,"KerberosRealm","DCE");
   @tDirection = ( "NA","Inbound","Outbound","Bidirectional");

   $trustType .= " @tType[$trustType]";
   $trustDirection .= " @tDirection[$trustDirection]";

   print "Trust: $flatName: $cName, Partner: $trustPartner, Type: $trustType, Direction: $trustDirection\n";

   #Now perform dns lookup of domain controllers for
   #target domain specified as trustedDomain
   #Note the second DNS query to obtain the IP address of the SRV record
    my $res   = Net::DNS::Resolver->new(nameservers => [$server, $server]);
    my $query=$res->search("_ldap._tcp.$trustPartner", SRV);

    if ($query) {
        @answers=$query->answer;
		foreach my $rr ($query->answer) 
		{
	  		$hostRes = Net::DNS::Resolver->new;
	  		$domainController = $rr->target;
	  		$hostReply = $hostRes->search( $domainController );
	  		if ($hostReply)
	  		{
	  			foreach my $rr ($hostReply->answer) 
	  			{
            	 next unless $rr->type eq "A";
	    		 $hostAddy = $rr->address;
	  			}
	  		}
	  	print "\t$flatName Domain Controller: " . $rr->target . " ($hostAddy)\n";
		}
	} 
   }
}

# This loop will list all Organizational Units
if ( $listOrgUnits)
{
 while (1){
  $mesg = $ldap->search( base => $baseDN, filter => $ouFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

 	foreach $entry (@entries) 
 	{
  	 $name = $entry->get_value("name");
  	 $cName = $entry->get_value("cn");
  	 $desc = $entry->get_value("description");
   	 $managedBy = $entry->get_value("managedBy");
     $dn = $entry->get_value("distinguishedName");
     print "OU: $name, DESC: $desc, Manager: $managedBy, DN: $dn \n";
 	}
}
 if (defined($cookie) && length($cookie)) {
    print "abnormal exit\n";
    # Abnormal exit, so let the server know we do not want any more
    $page->cookie($cookie);
    $page->size(0);
    $ldap->search(control => [$page]);
 }
}



# This loop will list all groups within domain
if ( $listGroupsSimple )
{
 while(1){
  $mesg = $ldap->search( base    => $baseDN, filter  => $groupFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

  foreach $entry (@entries) {
    $gname = $entry->get_value("cn");
    $desc = $entry->get_value("description");
    print "Group: $gname: $desc\n";
  }
 }
}


 # This loop will list all groups within domain AND print out all members
if ( $listAllGroups )
{
 while(1)
 {
   $mesg = $ldap->search( base    => $baseDN, filter  => $groupFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);

   foreach $entry (@entries) 
   {
      $gname = $entry->get_value("cn");
      $description = $entry->get_value("description");
      print "Group: $gname, Desc: $description\n";
      print "\tMembers: ";
      @members = $entry->get_value( "member");
      foreach $member (@members)
      {
         #print "Running with filter $member\n";
         $userfilter = "(objectClass=user)";
         $newmesg = $ldap->search( base => $member, filter=> $userfilter);
         @nentries = $newmesg->entries;
         foreach $nentry (@nentries) {
               $sam = $nentry->get_value("sAMAccountName");
               print "$sam,";
         }  
      }
     print "\n";
   }
  }
}

 # This loop will list all groups that user is a member of
 if ( $userGroupMembers )
 {
   print "[I] Checking $userGroupMembers group membership\n";
   $userMemberFilter = "(sAMAccountName=$userGroupMembers)";

   $mesg = $ldap->search( base    => $baseDN, filter  => $userMemberFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) {
    @member = $entry->get_value("memberOf");
    foreach $member (@member)
    {
     print "Group: $member\n";
    }
   }
 }



 # This loop will list all attributes for the user
 if ( $userAllAtributes )
 {
   print "[I] Grabbing All Attributes for $userAllAtributes\n";
   $userMemberFilter = "(sAMAccountName=$userAllAtributes)";

   $mesg = $ldap->search( base    => $baseDN, filter  => $userMemberFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

	my $entr;
 	foreach $entr ( @entries ) {
   		print "DN: ", $entr->dn, "\n";

   	 my $attr;
     foreach $attr ( sort $entr->attributes ) {
     # skip binary we can't handle
     $theEntry = $entr->get_value ( $attr );
     $theEntry =~ s/[^[:print:]]+//g;
     $attr =~ s/[^[:print:]]+//g;
        print "  $attr : ", $theEntry ,"\n";
   	 }
    }
 }

# List All Exchange Servers
if ( $exchangeServers )
{
   print "[I] Enumerating Exchange Servers\n";
   $configDN = "CN=Configuration," . $baseDN;

   $mesg = $ldap->search( base => $configDN, filter => $exchangeFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

  my $entr;
  foreach $entr ( @entries ) {
      print "DN: ", $entr->dn, "\n";
  }
   
}

# Grab Domain Info
if ( $getDomainInfo)
{
   print "[I] Enumerating Domain Information\n";


   $domainFilter = "(distinguishedName=$baseDN)";

   $mesg = $ldap->search( base => $baseDN, filter => $domainFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

	my $entr;
 	foreach $entr ( @entries ) {
   		print "DN: ", $entr->dn, "\n";

   	 my $attr;
   	 $theSid = $entr->get_value("objectSid");
   	 $sid = Net::LDAP::SID->new( $theSid );

   	 $lockoutDuration = $entr->get_value("lockoutDuration");
   	 $lockoutThresh = $entr->get_value("lockoutThreshold");
   	 $MinPwdLength = $entr->get_value("MinPwdLength");
   	 $maxPwdAge = $entr->get_value ("maxPwdAge");
   	 $forestVer = $entr->get_value("msDS-Behavior-Version");
   	 $passHistoryCount = $entr->get_value("pwdHistoryLength");
   	 $domainNative= $entr->get_value("nTMixedDomain");
   	 $domainCreated = $entr->get_value("whenCreated");
   	 $nextRid = $entr->get_value ("nextRid");

   	 # maPwdAge is represented in negative nanoseconds
   	 # that's why we have to multiply by -1
   	 $maxPwdAge = (($maxPwdAge / 10000000) / 86400) * -1;
   	 $lockoutDuration = (($lockoutDuration / 10000000) / 3600) * -1;


   	 if ($domainNative eq 1){ $domainNative = "(1) Mixed Mode"}
   	 if ($domainNative eq 0){ $domainNative = "(0) Native Mode"}

   	 if ($forestVer eq 0){ $forestVer = "(0) DS_BEHAVIOR_WIN2000"}
   	 if ($forestVer eq 1){ $forestVer = "(1) DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS"}
   	 if ($forestVer eq 2){ $forestVer = "(2) DS_BEHAVIOR_WIN2003"}
   	 if ($forestVer eq 3){ $forestVer = "(3) DS_BEHAVIOR_WIN2008 - Windows Server 2008 and later"}

   	 if ($forestVer eq 4){ $forestVer = "(4) DS_BEHAVIOR_WIN2008R2 - Windows Server 2008 R2 operating system and later"}
   	 if ($forestVer eq 5){ $forestVer = "(5) DS_BEHAVIOR_WIN2012 - Windows Server 2012 operating system and later"}
   	 if ($forestVer eq 6){ $forestVer = "(6) DS_BEHAVIOR_WIN2012R2 - Windows Server 2012 R2 operating system and later"}
   	 if ($forestVer eq 7){ $forestVer = "(7) DS_BEHAVIOR_WIN2016 - Windows Server 2016 and later"}

   	 # add pwdProperties to check for complexity requirement

 	 print "DomainSID:\t\t" . $sid->as_string . "\n";
 	 print "Pwd History Cnt:\t" . $passHistoryCount . "\n";
 	 print "Max Pwd Age:\t\t" . $maxPwdAge . " days\n";
 	 print "MinPwdLength:\t\t" . $MinPwdLength . "\n";
 	 print "lockoutThreshold:\t" . $lockoutThresh . "\n";
 	 print "lockoutDuration:\t" . $lockoutDuration . " hours\n";
 	 print "DomainVer:\t\t" . $domainNative . "\n";
 	 print "Forest Func Level:\t" . $forestVer . "\n";
 	 print "Domain Created:\t\t" . $domainCreated . "\n";
 	 print "NextRid:\t\t" . $nextRid . "\n";


     #foreach $attr ( sort $entr->attributes ) {
     # skip binary we can't handle
     #$theEntry = $entr->get_value ( $attr );
     #$theEntry =~ s/[^[:print:]]+//g;
     #$attr =~ s/[^[:print:]]+//g;
     #   print "  $attr : ", $theEntry ,"\n";
   	 #}
    }

   $lapsFilter = "(cn=ms-Mcs-AdmPwd)";
   $schemaDN = "CN=Schema,CN=Configuration," . $baseDN;

   $mesg = $ldap->search( base => $schemaDN, filter => $lapsFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   	my $entr;
 	foreach $entr ( @entries ) {
   		print "LAPS:\t\t\tLAPS Appears to be enabled\n";
   	}
}

 # This loop will list all Service Principal Names in the domain
if ( $listAllSPNs )
{
   $mesg = $ldap->search( base    => $baseDN, filter  => $spnFilter, control => [$page] );
   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) 
   {
      $cn = $entry->get_value("cn");
      $description = $entry->get_value("description");
      $spn = $entry->get_value("servicePrincipalName");
      
      $pwdLastSet = $entry->get_value("pwdLastSet");
      $pwdLastSetTime = procWindowsTime($pwdLastSet);
      
      print "SPN: $spn, $cn, $description, $pwdLastSetTime\n";
   }
}

 # This loop will list all Service Principal Names in the domain
if ( $listLapsPwds)
{
   print "[I] Querying for LAPS Passwords (note you need special privileges to actually enumerate)\n";

   # From ADSecurity.org
   # any authenticated user can view the value of the ms-mcs-AdmPwdExpirationTime attribute
   # Thus you can tell a few things as any user
   # If a computer is managed by LAPS (no value vs value present)
   # When the computer’s local Administrator password was last changed (read value in LAPS GPO and subtract this value from the date/time value in the attribute).
   # If a computer’s local Administrator password is no longer managed by LAPS (value is equal to a date/time in the past).


  $mesg = $ldap->search( base    => $baseDN, filter  => $lapsPwdFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

   foreach $entry (@entries) 
   {
      $cn = $entry->get_value("cn");
      $description = $entry->get_value("description");
      $password = $entry->get_value("ms-mcs-AdmPwd");
      $expTime = $entry->get_value("ms-mcs-AdmPwdExpirationTime");
      $expTimeVal = procWindowsTime($expTime);
      
      $pwdLastSet = $entry->get_value("pwdLastSet");
      $pwdLastSetTime = procWindowsTime($pwdLastSet);
      
      print "LAPS: $cn, $password, $description, $expTime\n";
   }
}


 if ( $manualFilter)
 {
  while (1)
  {
   print "[I] Running Manual query for: $manualFilter\n";
   #$userMemberFilter = "(sAMAccountName=$userAllAtributes)";
   if ($prefixBaseDN){
   	$baseDN = $prefixBaseDN . "," . $baseDN;
   }
   print "[I] Using new BaseDN: $baseDN\n";

   $mesg = $ldap->search( base => $baseDN, filter => $manualFilter, control => [$page] );
   #$mesg = $ldap->search( base    => $baseDN, filter  => $userMemberFilter, control => [$page] );
   my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
   $cookie    = $resp->cookie or last;
   $page->cookie($cookie);

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

  my $entr;
  foreach $entr ( @entries ) {
      print "DN: ", $entr->dn, "\n";
   }
  }
 }

if ( $listDNSRecords)
{
   print "[I] Listing DNS Records\n";

   $dnsFilter = "(instanceType=4)";
   $zoneFilter = "(cn=Zone)";
   $forestDN = "DC=forestDNSZones," . $baseDN;

   # DNS Zone: cn=Zone
  while(1) {
  $mesg = $ldap->search( base    => $forestDN, filter  => $zoneFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;


  foreach $entry (@entries) {
  $dc= $entry->get_value("dc");
  print "DNS-Zone: $dc\n";
  }
   my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);
  }

 while(1){
  $mesg = $ldap->search( base    => $forestDN, filter  => $dnsFilter, control => [$page] );
  $mesg->code && die "Error on search: $@ : " . $mesg->error;
  @entries = $mesg->entries;

  foreach $entry (@entries) {
  $dc= $entry->get_value("dc");
  $theDNSRec = $entry->get_value("dnsRecord");
  $distinguishedName = $entry->get_value("distinguishedName");
  $cn= $entry->get_value("cn");

  my @spl = split(',', $distinguishedName); 
  $dnsDomain = $spl[1];
  @splTwo = split('=', $dnsDomain);
  $recDomain = $splTwo[1];

  $whenCreated = $entry->get_value("whenCreated");
  $whenChanged = $entry->get_value("whenChanged");

  $whenCreated = printGenTime($whenCreated);
  $whenChanged = printGenTime($whenChanged);


  print "DNS-Record: $dc.$recDomain, $whenCreated, $whenChanged\n";

  }
   my($resp)  = $mesg->control( LDAP_CONTROL_PAGED ) or last;
  $cookie    = $resp->cookie or last;
  $page->cookie($cookie);
 }
}

# $testAttributes = "Yup";
# using this loop for testing of new queries
# it will list all attributes for the specified thing
 if ( $testAttributes )
 {
   print "[I] Grabbing All Attributes for $testAttribute\n";
   #$userMemberFilter = "(sAMAccountName=$userAllAtributes)";
   $mesg = $ldap->search( base => $baseDN, filter => $ouFilter, control => [$page] );
   #$mesg = $ldap->search( base    => $baseDN, filter  => $userMemberFilter, control => [$page] );

   $mesg->code && die "Error on search: $@ : " . $mesg->error;
   @entries = $mesg->entries;

  my $entr;
  foreach $entr ( @entries ) {
      print "DN: ", $entr->dn, "\n";

     my $attr;
     foreach $attr ( sort $entr->attributes ) {
     # skip binary we can't handle
     $theEntry = $entr->get_value ( $attr );
     $theEntry =~ s/[^[:print:]]+//g;
     $attr =~ s/[^[:print:]]+//g;
        print "  $attr : ", $theEntry ,"\n";
     }
    print"#####################################################################\n\n\n";
   }
 }



